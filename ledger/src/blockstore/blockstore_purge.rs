use {super::*, solana_sdk::message::AccountKeys, std::time::Instant};

#[derive(Default)]
pub struct PurgeStats {
    delete_range: u64,
    write_batch: u64,
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
            ("write_batch_us", purge_stats.write_batch as i64, i64)
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
    }

    pub fn purge_and_compact_slots(&self, from_slot: Slot, to_slot: Slot) {
        self.purge_slots(from_slot, to_slot, PurgeType::Exact);
        if let Err(e) = self.compact_storage(from_slot, to_slot) {
            // This error is not fatal and indicates an internal error?
            error!(
                "Error: {:?}; Couldn't compact storage from {:?} to {:?}",
                e, from_slot, to_slot
            );
        }
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

    pub(crate) fn run_purge(
        &self,
        from_slot: Slot,
        to_slot: Slot,
        purge_type: PurgeType,
    ) -> Result<bool> {
        self.run_purge_with_stats(from_slot, to_slot, purge_type, &mut PurgeStats::default())
    }

    /// A helper function to `purge_slots` that executes the ledger clean up
    /// from `from_slot` to `to_slot`.
    pub(crate) fn run_purge_with_stats(
        &self,
        from_slot: Slot,
        to_slot: Slot,
        purge_type: PurgeType,
        purge_stats: &mut PurgeStats,
    ) -> Result<bool> {
        let mut write_batch = self
            .db
            .batch()
            .expect("Database Error: Failed to get write batch");
        // delete range cf is not inclusive
        let to_slot = to_slot.saturating_add(1);

        let mut delete_range_timer = Measure::start("delete_range");
        let mut columns_purged = self
            .db
            .delete_range_cf::<cf::SlotMeta>(&mut write_batch, from_slot, to_slot)
            .is_ok()
            & self
                .db
                .delete_range_cf::<cf::BankHash>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Root>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ShredData>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ShredCode>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::DeadSlots>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::DuplicateSlots>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::ErasureMeta>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Orphans>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Index>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Rewards>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::Blocktime>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::PerfSamples>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::BlockHeight>(&mut write_batch, from_slot, to_slot)
                .is_ok()
            & self
                .db
                .delete_range_cf::<cf::OptimisticSlots>(&mut write_batch, from_slot, to_slot)
                .is_ok();
        let mut w_active_transaction_status_index =
            self.active_transaction_status_index.write().unwrap();
        match purge_type {
            PurgeType::Exact => {
                self.purge_special_columns_exact(&mut write_batch, from_slot, to_slot)?;
            }
            PurgeType::PrimaryIndex => {
                self.purge_special_columns_with_primary_index(
                    &mut write_batch,
                    &mut columns_purged,
                    &mut w_active_transaction_status_index,
                    to_slot,
                )?;
            }
            PurgeType::CompactionFilter => {
                // No explicit action is required here because this purge type completely and
                // indefinitely relies on the proper working of compaction filter for those
                // special column families, never toggling the primary index from the current
                // one. Overall, this enables well uniformly distributed writes, resulting
                // in no spiky periodic huge delete_range for them.
            }
        }
        delete_range_timer.stop();
        let mut write_timer = Measure::start("write_batch");
        if let Err(e) = self.db.write(write_batch) {
            error!(
                "Error: {:?} while submitting write batch for slot {:?} retrying...",
                e, from_slot
            );
            return Err(e);
        }
        write_timer.stop();
        purge_stats.delete_range += delete_range_timer.as_us();
        purge_stats.write_batch += write_timer.as_us();
        // only drop w_active_transaction_status_index after we do db.write(write_batch);
        // otherwise, readers might be confused with inconsistent state between
        // self.active_transaction_status_index and RockDb's TransactionStatusIndex contents
        drop(w_active_transaction_status_index);
        Ok(columns_purged)
    }

    pub fn compact_storage(&self, from_slot: Slot, to_slot: Slot) -> Result<bool> {
        if self.no_compaction {
            info!("compact_storage: compaction disabled");
            return Ok(false);
        }
        info!("compact_storage: from {} to {}", from_slot, to_slot);
        let mut compact_timer = Measure::start("compact_range");
        let result = self
            .meta_cf
            .compact_range(from_slot, to_slot)
            .unwrap_or(false)
            && self
                .db
                .column::<cf::Root>()
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .data_shred_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .code_shred_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .dead_slots_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .duplicate_slots_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .erasure_meta_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .orphans_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .bank_hash_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .index_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .transaction_status_cf
                .compact_range(0, 2)
                .unwrap_or(false)
            && self
                .address_signatures_cf
                .compact_range(0, 2)
                .unwrap_or(false)
            && self
                .transaction_status_index_cf
                .compact_range(0, 2)
                .unwrap_or(false)
            && self
                .rewards_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .blocktime_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .perf_samples_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .block_height_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false)
            && self
                .optimistic_slots_cf
                .compact_range(from_slot, to_slot)
                .unwrap_or(false);
        compact_timer.stop();
        if !result {
            info!("compact_storage incomplete");
        }
        datapoint_info!(
            "blockstore-compact",
            ("compact_range_us", compact_timer.as_us() as i64, i64),
        );
        Ok(result)
    }

    /// Purges special columns (using a non-Slot primary-index) exactly, by
    /// deserializing each slot being purged and iterating through all
    /// transactions to determine the keys of individual records.
    ///
    /// **This method is very slow.**
    fn purge_special_columns_exact(
        &self,
        batch: &mut WriteBatch,
        from_slot: Slot,
        to_slot: Slot, // Exclusive
    ) -> Result<()> {
        let mut index0 = self.transaction_status_index_cf.get(0)?.unwrap_or_default();
        let mut index1 = self.transaction_status_index_cf.get(1)?.unwrap_or_default();
        for slot in from_slot..to_slot {
            let slot_entries = self.get_any_valid_slot_entries(slot, 0);
            let transactions = slot_entries
                .into_iter()
                .flat_map(|entry| entry.transactions);
            for transaction in transactions {
                if let Some(&signature) = transaction.signatures.get(0) {
                    batch.delete::<cf::TransactionStatus>((0, signature, slot))?;
                    batch.delete::<cf::TransactionStatus>((1, signature, slot))?;

                    let meta = self.read_transaction_status((signature, slot))?;
                    let loaded_addresses = meta.map(|meta| meta.loaded_addresses);
                    let account_keys = AccountKeys::new(
                        transaction.message.static_account_keys(),
                        loaded_addresses.as_ref(),
                    );

                    for pubkey in account_keys.iter() {
                        batch.delete::<cf::AddressSignatures>((0, *pubkey, slot, signature))?;
                        batch.delete::<cf::AddressSignatures>((1, *pubkey, slot, signature))?;
                    }
                }
            }
        }
        if index0.max_slot >= from_slot && index0.max_slot <= to_slot {
            index0.max_slot = from_slot.saturating_sub(1);
            batch.put::<cf::TransactionStatusIndex>(0, &index0)?;
        }
        if index1.max_slot >= from_slot && index1.max_slot <= to_slot {
            index1.max_slot = from_slot.saturating_sub(1);
            batch.put::<cf::TransactionStatusIndex>(1, &index1)?;
        }
        Ok(())
    }

    /// Purges special columns (using a non-Slot primary-index) by range. Purge
    /// occurs if frozen primary index has a max-slot less than the highest slot
    /// being purged.
    fn purge_special_columns_with_primary_index(
        &self,
        write_batch: &mut WriteBatch,
        columns_purged: &mut bool,
        w_active_transaction_status_index: &mut u64,
        to_slot: Slot,
    ) -> Result<()> {
        if let Some(purged_index) = self.toggle_transaction_status_index(
            write_batch,
            w_active_transaction_status_index,
            to_slot,
        )? {
            *columns_purged &= self
                .db
                .delete_range_cf::<cf::TransactionStatus>(
                    write_batch,
                    purged_index,
                    purged_index + 1,
                )
                .is_ok()
                & self
                    .db
                    .delete_range_cf::<cf::AddressSignatures>(
                        write_batch,
                        purged_index,
                        purged_index + 1,
                    )
                    .is_ok();
        }
        Ok(())
    }
}
