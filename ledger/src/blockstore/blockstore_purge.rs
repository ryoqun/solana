use {
    super::*,
    crate::blockstore_db::ColumnIndexDeprecation,
    solana_sdk::message::AccountKeys,
    std::{cmp::max, time::Instant},
};

#[derive(Default)]
pub struct PurgeStats {
    delete_range: u64,
    write_batch: u64,
    delete_files_in_range: u64,
}

#[derive(Clone, Copy)]
/// Controls how `blockstore::purge_slots` purges the data.
pub enum PurgeType {
    /// A slower but more accurate way to purge slots by also ensuring higher
    /// level of consistency between data during the clean up process.
    Exact,
    /// The fastest purge mode that relies on the slot-id based TTL
    /// compaction filter to do the cleanup.
    CompactionFilter,
}

impl Blockstore {
    /// Performs cleanup based on the specified deletion range.  After this
    /// function call, entries within \[`from_slot`, `to_slot`\] will become
    /// unavailable to the reader immediately, while its disk space occupied
    /// by the deletion entries are reclaimed later via RocksDB's background
    /// compaction.
    ///
    /// Note that this function modifies multiple column families at the same
    /// time and might break the consistency between different column families
    /// as it does not update the associated slot-meta entries that refer to
    /// the deleted entries.
    ///
    /// For slot-id based column families, the purge is done by range deletion,
    /// while the non-slot-id based column families, `cf::TransactionStatus`,
    /// `AddressSignature`, and `cf::TransactionStatusIndex`, are cleaned-up
    /// based on the `purge_type` setting.
    pub fn purge_slots(&self, from_slot: Slot, to_slot: Slot, purge_type: PurgeType) {
        let mut purge_stats = PurgeStats::default();
        let purge_result =
            self.run_purge_with_stats(from_slot, to_slot, purge_type, &mut purge_stats);

        datapoint_info!(
            "blockstore-purge",
            ("from_slot", from_slot as i64, i64),
            ("to_slot", to_slot as i64, i64),
            ("delete_range_us", purge_stats.delete_range as i64, i64),
            ("write_batch_us", purge_stats.write_batch as i64, i64),
            (
                "delete_files_in_range_us",
                purge_stats.delete_files_in_range as i64,
                i64
            )
        );
        if let Err(e) = purge_result {
            error!(
                "Error: {:?}; Purge failed in range {:?} to {:?}",
                e, from_slot, to_slot
            );
        }
    }

    /// Usually this is paired with .purge_slots() but we can't internally call this in
    /// that function unconditionally. That's because set_max_expired_slot()
    /// expects to purge older slots by the successive chronological order, while .purge_slots()
    /// can also be used to purge *future* slots for --hard-fork thing, preserving older
    /// slots. It'd be quite dangerous to purge older slots in that case.
    /// So, current legal user of this function is LedgerCleanupService.
    pub fn set_max_expired_slot(&self, to_slot: Slot) {
        // convert here from inclusive purged range end to inclusive alive range start to align
        // with Slot::default() for initial compaction filter behavior consistency
        let to_slot = to_slot.checked_add(1).unwrap();
        self.db.set_oldest_slot(to_slot);

        if let Err(err) = self.maybe_cleanup_highest_primary_index_slot(to_slot) {
            warn!("Could not clean up TransactionStatusIndex: {err:?}");
        }
    }

    pub fn purge_and_compact_slots(&self, from_slot: Slot, to_slot: Slot) {
        self.purge_slots(from_slot, to_slot, PurgeType::Exact);
    }

    /// Ensures that the SlotMeta::next_slots vector for all slots contain no references in the
    /// \[from_slot,to_slot\] range
    ///
    /// Dangerous; Use with care
    pub fn purge_from_next_slots(&self, from_slot: Slot, to_slot: Slot) {
        let mut count = 0;
        let mut rewritten = 0;
        let mut last_print = Instant::now();
        let mut total_retain_us = 0;
        for (slot, mut meta) in self
            .slot_meta_iterator(0)
            .expect("unable to iterate over meta")
        {
            if slot > to_slot {
                break;
            }

            count += 1;
            if last_print.elapsed().as_millis() > 2000 {
                info!(
                    "purged: {} slots rewritten: {} retain_time: {}us",
                    count, rewritten, total_retain_us
                );
                count = 0;
                rewritten = 0;
                total_retain_us = 0;
                last_print = Instant::now();
            }
            let mut time = Measure::start("retain");
            let original_len = meta.next_slots.len();
            meta.next_slots
                .retain(|slot| *slot < from_slot || *slot > to_slot);
            if meta.next_slots.len() != original_len {
                rewritten += 1;
                info!(
                    "purge_from_next_slots: meta for slot {} no longer refers to slots {:?}",
                    slot,
                    from_slot..=to_slot
                );
                self.put_meta_bytes(
                    slot,
                    &bincode::serialize(&meta).expect("couldn't update meta"),
                )
                .expect("couldn't update meta");
            }
            time.stop();
            total_retain_us += time.as_us();
        }
    }

    /// Purges all columns relating to `slot`.
    ///
    /// Additionally, we cleanup the parent of `slot` by clearing `slot` from
    /// the parent's `next_slots`. We reinsert an orphaned `slot_meta` for `slot`
    /// that preserves `slot`'s `next_slots`. This ensures that `slot`'s fork is
    /// replayable upon repair of `slot`.
    pub(crate) fn purge_slot_cleanup_chaining(&self, slot: Slot) -> Result<bool> {
        let Some(mut slot_meta) = self.meta(slot)? else {
            return Err(BlockstoreError::SlotUnavailable);
        };
        let mut write_batch = self.db.batch()?;

        let columns_purged = self.purge_range(&mut write_batch, slot, slot, PurgeType::Exact)?;

        if let Some(parent_slot) = slot_meta.parent_slot {
            let parent_slot_meta = self.meta(parent_slot)?;
            if let Some(mut parent_slot_meta) = parent_slot_meta {
                // .retain() is a linear scan; however, next_slots should
                // only contain several elements so this isn't so bad
                parent_slot_meta
                    .next_slots
                    .retain(|&next_slot| next_slot != slot);
                write_batch.put::<cf::SlotMeta>(parent_slot, &parent_slot_meta)?;
            } else {
                error!(
                    "Parent slot meta {} for child {} is missing  or cleaned up.
                       Falling back to orphan repair to remedy the situation",
                    parent_slot, slot
                );
            }
        }

        // Retain a SlotMeta for `slot` with the `next_slots` field retained
        slot_meta.clear_unconfirmed_slot();
        write_batch.put::<cf::SlotMeta>(slot, &slot_meta)?;

        self.db.write(write_batch).inspect_err(|e| {
            error!(
                "Error: {:?} while submitting write batch for slot {:?}",
                e, slot
            )
        })?;
        Ok(columns_purged)
    }

    /// A helper function to `purge_slots` that executes the ledger clean up.
    /// The cleanup applies to \[`from_slot`, `to_slot`\].
    ///
    /// When `from_slot` is 0, any sst-file with a key-range completely older
    /// than `to_slot` will also be deleted.
    ///
    /// Note: slots > `to_slot` that chained to a purged slot are not properly
    /// cleaned up. This function is not intended to be used if such slots need
    /// to be replayed.
    pub(crate) fn run_purge_with_stats(
        &self,
        from_slot: Slot,
        to_slot: Slot,
        purge_type: PurgeType,
        purge_stats: &mut PurgeStats,
    ) -> Result<bool> {
        let mut write_batch = self.db.batch()?;

        let mut delete_range_timer = Measure::start("delete_range");
        let columns_purged = self.purge_range(&mut write_batch, from_slot, to_slot, purge_type)?;
        delete_range_timer.stop();

        let mut write_timer = Measure::start("write_batch");
        self.db.write(write_batch).inspect_err(|e| {
            error!(
                "Error: {:?} while submitting write batch for purge from_slot {} to_slot {}",
                e, from_slot, to_slot
            )
        })?;
        write_timer.stop();

        let mut purge_files_in_range_timer = Measure::start("delete_file_in_range");
        // purge_files_in_range delete any files whose slot range is within
        // [from_slot, to_slot].  When from_slot is 0, it is safe to run
        // purge_files_in_range because if purge_files_in_range deletes any
        // sst file that contains any range-deletion tombstone, the deletion
        // range of that tombstone will be completely covered by the new
        // range-delete tombstone (0, to_slot) issued above.
        //
        // On the other hand, purge_files_in_range is more effective and
        // efficient than the compaction filter (which runs key-by-key)
        // because all the sst files that have key range below to_slot
        // can be deleted immediately.
        if columns_purged && from_slot == 0 {
            self.purge_files_in_range(from_slot, to_slot);
        }
        purge_files_in_range_timer.stop();

        purge_stats.delete_range += delete_range_timer.as_us();
        purge_stats.write_batch += write_timer.as_us();
        purge_stats.delete_files_in_range += purge_files_in_range_timer.as_us();

        Ok(columns_purged)
    }

    fn purge_range(
        &self,
        write_batch: &mut WriteBatch,
        from_slot: Slot,
        to_slot: Slot,
        purge_type: PurgeType,
    ) -> Result<bool> {
        let columns_purged = self
            .db
            .delete_range_cf::<cf::SlotMeta>(write_batch, from_slot, to_slot)
            .is_ok()
            & self
                .db
                .delete_range_cf::<cf::BankHash>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Root>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ShredData>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ShredCode>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::DeadSlots>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::DuplicateSlots>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ErasureMeta>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Orphans>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Index>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Rewards>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Blocktime>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::PerfSamples>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::BlockHeight>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::OptimisticSlots>(write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::MerkleRootMeta>(write_batch, from_slot, to_slot)
                .is_ok();

        match purge_type {
            PurgeType::Exact => {
                self.purge_special_columns_exact(write_batch, from_slot, to_slot)?;
            }
            PurgeType::CompactionFilter => {
                // No explicit action is required here because this purge type completely and
                // indefinitely relies on the proper working of compaction filter for those
                // special column families, never toggling the primary index from the current
                // one. Overall, this enables well uniformly distributed writes, resulting
                // in no spiky periodic huge delete_range for them.
            }
        }
        Ok(columns_purged)
    }

    fn purge_files_in_range(&self, from_slot: Slot, to_slot: Slot) -> bool {
        self.db
            .delete_file_in_range_cf::<cf::SlotMeta>(from_slot, to_slot)
            .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::BankHash>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Root>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::ShredData>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::ShredCode>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::DeadSlots>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::DuplicateSlots>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::ErasureMeta>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Orphans>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Index>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Rewards>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::Blocktime>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::PerfSamples>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::BlockHeight>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::OptimisticSlots>(from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_file_in_range_cf::<cf::MerkleRootMeta>(from_slot, to_slot)
                .is_ok()
    }

    /// Returns true if the special columns, TransactionStatus and
    /// AddressSignatures, are both empty.
    ///
    /// It should not be the case that one is empty and the other is not, but
    /// just return false in this case.
    fn special_columns_empty(&self) -> Result<bool> {
        let transaction_status_empty = self
            .transaction_status_cf
            .iter(IteratorMode::Start)?
            .next()
            .is_none();
        let address_signatures_empty = self
            .address_signatures_cf
            .iter(IteratorMode::Start)?
            .next()
            .is_none();

        Ok(transaction_status_empty && address_signatures_empty)
    }

    /// Purges special columns (using a non-Slot primary-index) exactly, by
    /// deserializing each slot being purged and iterating through all
    /// transactions to determine the keys of individual records.
    ///
    /// The purge range applies to \[`from_slot`, `to_slot`\].
    ///
    /// **This method is very slow.**
    fn purge_special_columns_exact(
        &self,
        batch: &mut WriteBatch,
        from_slot: Slot,
        to_slot: Slot,
    ) -> Result<()> {
        if self.special_columns_empty()? {
            return Ok(());
        }

        let mut index0 = self.transaction_status_index_cf.get(0)?.unwrap_or_default();
        let mut index1 = self.transaction_status_index_cf.get(1)?.unwrap_or_default();
        let highest_primary_index_slot = self.get_highest_primary_index_slot();
        let slot_indexes = |slot: Slot| -> Vec<u64> {
            let mut indexes = vec![];
            if highest_primary_index_slot.is_none() {
                return indexes;
            }
            if slot <= index0.max_slot && (index0.frozen || slot >= index1.max_slot) {
                indexes.push(0);
            }
            if slot <= index1.max_slot && (index1.frozen || slot >= index0.max_slot) {
                indexes.push(1);
            }
            indexes
        };

        for slot in from_slot..=to_slot {
            let primary_indexes = slot_indexes(slot);

            let (slot_entries, _, _) =
                self.get_slot_entries_with_shred_info(slot, 0, true /* allow_dead_slots */)?;
            let transactions = slot_entries
                .into_iter()
                .flat_map(|entry| entry.transactions);
            for (i, transaction) in transactions.enumerate() {
                if let Some(&signature) = transaction.signatures.first() {
                    batch.delete::<cf::TransactionStatus>((signature, slot))?;
                    batch.delete::<cf::TransactionMemos>((signature, slot))?;
                    if !primary_indexes.is_empty() {
                        batch.delete_raw::<cf::TransactionMemos>(
                            &cf::TransactionMemos::deprecated_key(signature),
                        )?;
                    }
                    for primary_index in &primary_indexes {
                        batch.delete_raw::<cf::TransactionStatus>(
                            &cf::TransactionStatus::deprecated_key((
                                *primary_index,
                                signature,
                                slot,
                            )),
                        )?;
                    }

                    let meta = self.read_transaction_status((signature, slot))?;
                    let loaded_addresses = meta.map(|meta| meta.loaded_addresses);
                    let account_keys = AccountKeys::new(
                        transaction.message.static_account_keys(),
                        loaded_addresses.as_ref(),
                    );

                    let transaction_index =
                        u32::try_from(i).map_err(|_| BlockstoreError::TransactionIndexOverflow)?;
                    for pubkey in account_keys.iter() {
                        batch.delete::<cf::AddressSignatures>((
                            *pubkey,
                            slot,
                            transaction_index,
                            signature,
                        ))?;
                        for primary_index in &primary_indexes {
                            batch.delete_raw::<cf::AddressSignatures>(
                                &cf::AddressSignatures::deprecated_key((
                                    *primary_index,
                                    *pubkey,
                                    slot,
                                    signature,
                                )),
                            )?;
                        }
                    }
                }
            }
        }
        let mut update_highest_primary_index_slot = false;
        if index0.max_slot >= from_slot && index0.max_slot <= to_slot {
            index0.max_slot = from_slot.saturating_sub(1);
            batch.put::<cf::TransactionStatusIndex>(0, &index0)?;
            update_highest_primary_index_slot = true;
        }
        if index1.max_slot >= from_slot && index1.max_slot <= to_slot {
            index1.max_slot = from_slot.saturating_sub(1);
            batch.put::<cf::TransactionStatusIndex>(1, &index1)?;
            update_highest_primary_index_slot = true
        }
        if update_highest_primary_index_slot {
            self.set_highest_primary_index_slot(Some(max(index0.max_slot, index1.max_slot)))
        }
        Ok(())
    }
}
