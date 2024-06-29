//! Service to calculate accounts hashes

use {
    crossbeam_channel::{Receiver, Sender},
    solana_accounts_db::{
        accounts_db::CalcAccountsHashKind,
        accounts_hash::{
            AccountsHash, AccountsHashKind, CalcAccountsHashConfig, HashStats,
            IncrementalAccountsHash,
        },
        sorted_storages::SortedStorages,
    },
    solana_measure::measure_us,
    solana_runtime::{
        serde_snapshot::BankIncrementalSnapshotPersistence,
        snapshot_config::SnapshotConfig,
        snapshot_package::{
            self, AccountsPackage, AccountsPackageKind, SnapshotKind, SnapshotPackage,
        },
        snapshot_utils,
    },
    solana_sdk::clock::{Slot, DEFAULT_MS_PER_SLOT},
    std::{
        io::Result as IoResult,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct AccountsHashVerifier {
    t_accounts_hash_verifier: JoinHandle<()>,
}

impl AccountsHashVerifier {
    pub fn new(
        accounts_package_sender: Sender<AccountsPackage>,
        accounts_package_receiver: Receiver<AccountsPackage>,
        snapshot_package_sender: Option<Sender<SnapshotPackage>>,
        exit: Arc<AtomicBool>,
        snapshot_config: SnapshotConfig,
    ) -> Self {
        // If there are no accounts packages to process, limit how often we re-check
        const LOOP_LIMITER: Duration = Duration::from_millis(DEFAULT_MS_PER_SLOT);
        let t_accounts_hash_verifier = Builder::new()
            .name("solAcctHashVer".to_string())
            .spawn(move || {
                info!("AccountsHashVerifier has started");
                loop {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }

                    let Some((
                        accounts_package,
                        num_outstanding_accounts_packages,
                        num_re_enqueued_accounts_packages,
                    )) = Self::get_next_accounts_package(
                        &accounts_package_sender,
                        &accounts_package_receiver,
                    )
                    else {
                        std::thread::sleep(LOOP_LIMITER);
                        continue;
                    };
                    info!("handling accounts package: {accounts_package:?}");
                    let enqueued_time = accounts_package.enqueued.elapsed();

                    let (result, handling_time_us) = measure_us!(Self::process_accounts_package(
                        accounts_package,
                        snapshot_package_sender.as_ref(),
                        &snapshot_config,
                        &exit,
                    ));
                    if let Err(err) = result {
                        error!("Stopping AccountsHashVerifier! Fatal error while processing accounts package: {err}");
                        exit.store(true, Ordering::Relaxed);
                        break;
                    }

                    datapoint_info!(
                        "accounts_hash_verifier",
                        (
                            "num_outstanding_accounts_packages",
                            num_outstanding_accounts_packages,
                            i64
                        ),
                        (
                            "num_re_enqueued_accounts_packages",
                            num_re_enqueued_accounts_packages,
                            i64
                        ),
                        ("enqueued_time_us", enqueued_time.as_micros(), i64),
                        ("handling_time_us", handling_time_us, i64),
                    );
                }
                info!("AccountsHashVerifier has stopped");
            })
            .unwrap();
        Self {
            t_accounts_hash_verifier,
        }
    }

    /// Get the next accounts package to handle
    ///
    /// Look through the accounts package channel to find the highest priority one to handle next.
    /// If there are no accounts packages in the channel, return None.  Otherwise return the
    /// highest priority one.  Unhandled accounts packages with slots GREATER-THAN the handled one
    /// will be re-enqueued.  The remaining will be dropped.
    ///
    /// Also return the number of accounts packages initially in the channel, and the number of
    /// ones re-enqueued.
    fn get_next_accounts_package(
        accounts_package_sender: &Sender<AccountsPackage>,
        accounts_package_receiver: &Receiver<AccountsPackage>,
    ) -> Option<(
        AccountsPackage,
        /*num outstanding accounts packages*/ usize,
        /*num re-enqueued accounts packages*/ usize,
    )> {
        let mut accounts_packages: Vec<_> = accounts_package_receiver.try_iter().collect();
        let accounts_packages_len = accounts_packages.len();
        debug!("outstanding accounts packages ({accounts_packages_len}): {accounts_packages:?}");

        // NOTE: This code to select the next request is mirrored in AccountsBackgroundService.
        // Please ensure they stay in sync.
        match accounts_packages_len {
            0 => None,
            1 => {
                // SAFETY: We know the len is 1, so `pop` will return `Some`
                let accounts_package = accounts_packages.pop().unwrap();
                Some((accounts_package, 1, 0))
            }
            _ => {
                let num_eah_packages = accounts_packages
                    .iter()
                    .filter(|account_package| {
                        account_package.package_kind == AccountsPackageKind::EpochAccountsHash
                    })
                    .count();
                assert!(
                    num_eah_packages <= 1,
                    "Only a single EAH accounts package is allowed at a time! count: {num_eah_packages}"
                );

                // Get the two highest priority requests, `y` and `z`.
                // By asking for the second-to-last element to be in its final sorted position, we
                // also ensure that the last element is also sorted.
                let (_, y, z) = accounts_packages.select_nth_unstable_by(
                    accounts_packages_len - 2,
                    snapshot_package::cmp_accounts_packages_by_priority,
                );
                assert_eq!(z.len(), 1);
                let z = z.first().unwrap();
                let y: &_ = y; // reborrow to remove `mut`

                // If the highest priority request (`z`) is EpochAccountsHash, we need to check if
                // there's a FullSnapshot request with a lower slot in `y` that is about to be
                // dropped.  We do not want to drop a FullSnapshot request in this case because it
                // will cause subsequent IncrementalSnapshot requests to fail.
                //
                // So, if `z` is an EpochAccountsHash request, check `y`.  We know there can only
                // be at most one EpochAccountsHash request, so `y` is the only other request we
                // need to check.  If `y` is a FullSnapshot request *with a lower slot* than `z`,
                // then handle `y` first.
                let accounts_package = if z.package_kind == AccountsPackageKind::EpochAccountsHash
                    && y.package_kind == AccountsPackageKind::Snapshot(SnapshotKind::FullSnapshot)
                    && y.slot < z.slot
                {
                    // SAFETY: We know the len is > 1, so both `pop`s will return `Some`
                    let z = accounts_packages.pop().unwrap();
                    let y = accounts_packages.pop().unwrap();
                    accounts_packages.push(z);
                    y
                } else {
                    // SAFETY: We know the len is > 1, so `pop` will return `Some`
                    accounts_packages.pop().unwrap()
                };

                let handled_accounts_package_slot = accounts_package.slot;
                // re-enqueue any remaining accounts packages for slots GREATER-THAN the accounts package
                // that will be handled
                let num_re_enqueued_accounts_packages = accounts_packages
                    .into_iter()
                    .filter(|accounts_package| {
                        accounts_package.slot > handled_accounts_package_slot
                    })
                    .map(|accounts_package| {
                        accounts_package_sender
                            .try_send(accounts_package)
                            .expect("re-enqueue accounts package")
                    })
                    .count();

                Some((
                    accounts_package,
                    accounts_packages_len,
                    num_re_enqueued_accounts_packages,
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_accounts_package(
        accounts_package: AccountsPackage,
        snapshot_package_sender: Option<&Sender<SnapshotPackage>>,
        snapshot_config: &SnapshotConfig,
        exit: &AtomicBool,
    ) -> IoResult<()> {
        let (accounts_hash_kind, bank_incremental_snapshot_persistence) =
            Self::calculate_and_verify_accounts_hash(&accounts_package, snapshot_config)?;

        Self::save_epoch_accounts_hash(&accounts_package, accounts_hash_kind);

        Self::purge_old_accounts_hashes(&accounts_package, snapshot_config);

        Self::submit_for_packaging(
            accounts_package,
            snapshot_package_sender,
            snapshot_config,
            accounts_hash_kind,
            bank_incremental_snapshot_persistence,
            exit,
        );

        Ok(())
    }

    /// returns calculated accounts hash
    fn calculate_and_verify_accounts_hash(
        accounts_package: &AccountsPackage,
        snapshot_config: &SnapshotConfig,
    ) -> IoResult<(AccountsHashKind, Option<BankIncrementalSnapshotPersistence>)> {
        let accounts_hash_calculation_kind = match accounts_package.package_kind {
            AccountsPackageKind::AccountsHashVerifier => CalcAccountsHashKind::Full,
            AccountsPackageKind::EpochAccountsHash => CalcAccountsHashKind::Full,
            AccountsPackageKind::Snapshot(snapshot_kind) => match snapshot_kind {
                SnapshotKind::FullSnapshot => CalcAccountsHashKind::Full,
                SnapshotKind::IncrementalSnapshot(_) => CalcAccountsHashKind::Incremental,
            },
        };

        let (accounts_hash_kind, bank_incremental_snapshot_persistence) =
            match accounts_hash_calculation_kind {
                CalcAccountsHashKind::Full => {
                    let (accounts_hash, _capitalization) =
                        Self::_calculate_full_accounts_hash(accounts_package);
                    (accounts_hash.into(), None)
                }
                CalcAccountsHashKind::Incremental => {
                    let AccountsPackageKind::Snapshot(SnapshotKind::IncrementalSnapshot(base_slot)) =
                        accounts_package.package_kind
                    else {
                        panic!("Calculating incremental accounts hash requires a base slot");
                    };
                    let accounts_db = &accounts_package.accounts.accounts_db;
                    let Some((base_accounts_hash, base_capitalization)) =
                        accounts_db.get_accounts_hash(base_slot)
                    else {
                        panic!(
                            "incremental snapshot requires accounts hash and capitalization \
                             from the full snapshot it is based on \n\
                             package: {accounts_package:?} \n\
                             accounts hashes: {:?} \n\
                             incremental accounts hashes: {:?} \n\
                             full snapshot archives: {:?} \n\
                             bank snapshots: {:?}",
                            accounts_db.get_accounts_hashes(),
                            accounts_db.get_incremental_accounts_hashes(),
                            snapshot_utils::get_full_snapshot_archives(
                                &snapshot_config.full_snapshot_archives_dir,
                            ),
                            snapshot_utils::get_bank_snapshots(&snapshot_config.bank_snapshots_dir),
                        );
                    };
                    let (incremental_accounts_hash, incremental_capitalization) =
                        Self::_calculate_incremental_accounts_hash(accounts_package, base_slot);
                    let bank_incremental_snapshot_persistence =
                        BankIncrementalSnapshotPersistence {
                            full_slot: base_slot,
                            full_hash: base_accounts_hash.into(),
                            full_capitalization: base_capitalization,
                            incremental_hash: incremental_accounts_hash.into(),
                            incremental_capitalization,
                        };
                    (
                        incremental_accounts_hash.into(),
                        Some(bank_incremental_snapshot_persistence),
                    )
                }
            };

        Ok((accounts_hash_kind, bank_incremental_snapshot_persistence))
    }

    fn _calculate_full_accounts_hash(
        accounts_package: &AccountsPackage,
    ) -> (AccountsHash, /*capitalization*/ u64) {
        let (sorted_storages, storage_sort_us) =
            measure_us!(SortedStorages::new(&accounts_package.snapshot_storages));

        let mut timings = HashStats {
            storage_sort_us,
            ..HashStats::default()
        };
        timings.calc_storage_size_quartiles(&accounts_package.snapshot_storages);

        let calculate_accounts_hash_config = CalcAccountsHashConfig {
            use_bg_thread_pool: true,
            ancestors: None,
            epoch_schedule: &accounts_package.epoch_schedule,
            rent_collector: &accounts_package.rent_collector,
            store_detailed_debug_info_on_failure: false,
        };

        let slot = accounts_package.slot;
        let ((accounts_hash, lamports), measure_hash_us) =
            measure_us!(accounts_package.accounts.accounts_db.update_accounts_hash(
                &calculate_accounts_hash_config,
                &sorted_storages,
                slot,
                timings,
            ));

        if accounts_package.expected_capitalization != lamports {
            // before we assert, run the hash calc again. This helps track down whether it could have been a failure in a race condition possibly with shrink.
            // We could add diagnostics to the hash calc here to produce a per bin cap or something to help narrow down how many pubkeys are different.
            let calculate_accounts_hash_config = CalcAccountsHashConfig {
                // since we're going to assert, use the fg thread pool to go faster
                use_bg_thread_pool: false,
                // now that we've failed, store off the failing contents that produced a bad capitalization
                store_detailed_debug_info_on_failure: true,
                ..calculate_accounts_hash_config
            };
            _ = accounts_package
                .accounts
                .accounts_db
                .calculate_accounts_hash(
                    &calculate_accounts_hash_config,
                    &sorted_storages,
                    HashStats::default(),
                );
        }

        assert_eq!(
            accounts_package.expected_capitalization, lamports,
            "accounts hash capitalization mismatch"
        );
        if let Some(expected_hash) = accounts_package.accounts_hash_for_testing {
            assert_eq!(expected_hash, accounts_hash);
        };

        datapoint_info!(
            "accounts_hash_verifier",
            ("calculate_hash", measure_hash_us, i64),
        );

        (accounts_hash, lamports)
    }

    fn _calculate_incremental_accounts_hash(
        accounts_package: &AccountsPackage,
        base_slot: Slot,
    ) -> (IncrementalAccountsHash, /*capitalization*/ u64) {
        let incremental_storages =
            accounts_package
                .snapshot_storages
                .iter()
                .filter_map(|storage| {
                    let storage_slot = storage.slot();
                    (storage_slot > base_slot).then_some((storage, storage_slot))
                });
        let sorted_storages = SortedStorages::new_with_slots(incremental_storages, None, None);

        let calculate_accounts_hash_config = CalcAccountsHashConfig {
            use_bg_thread_pool: true,
            ancestors: None,
            epoch_schedule: &accounts_package.epoch_schedule,
            rent_collector: &accounts_package.rent_collector,
            store_detailed_debug_info_on_failure: false,
        };

        let (incremental_accounts_hash, measure_hash_us) = measure_us!(accounts_package
            .accounts
            .accounts_db
            .update_incremental_accounts_hash(
                &calculate_accounts_hash_config,
                &sorted_storages,
                accounts_package.slot,
                HashStats::default(),
            ));

        datapoint_info!(
            "accounts_hash_verifier",
            (
                "calculate_incremental_accounts_hash_us",
                measure_hash_us,
                i64
            ),
        );

        incremental_accounts_hash
    }

    fn save_epoch_accounts_hash(
        accounts_package: &AccountsPackage,
        accounts_hash: AccountsHashKind,
    ) {
        if accounts_package.package_kind == AccountsPackageKind::EpochAccountsHash {
            let AccountsHashKind::Full(accounts_hash) = accounts_hash else {
                panic!("EAH requires a full accounts hash!");
            };
            info!(
                "saving epoch accounts hash, slot: {}, hash: {}",
                accounts_package.slot, accounts_hash.0,
            );
            accounts_package
                .accounts
                .accounts_db
                .epoch_accounts_hash_manager
                .set_valid(accounts_hash.into(), accounts_package.slot);
        }
    }

    fn purge_old_accounts_hashes(
        accounts_package: &AccountsPackage,
        snapshot_config: &SnapshotConfig,
    ) {
        let should_purge = match (
            snapshot_config.should_generate_snapshots(),
            accounts_package.package_kind,
        ) {
            (false, _) => {
                // If we are *not* generating snapshots, then it is safe to purge every time.
                true
            }
            (true, AccountsPackageKind::Snapshot(SnapshotKind::FullSnapshot)) => {
                // If we *are* generating snapshots, then only purge old accounts hashes after
                // handling full snapshot packages.  This is because handling incremental snapshot
                // packages requires the accounts hash from the latest full snapshot, and if we
                // purged after every package, we'd remove the accounts hash needed by the next
                // incremental snapshot.
                true
            }
            (true, _) => false,
        };

        if should_purge {
            accounts_package
                .accounts
                .accounts_db
                .purge_old_accounts_hashes(accounts_package.slot);
        }
    }

    fn submit_for_packaging(
        accounts_package: AccountsPackage,
        snapshot_package_sender: Option<&Sender<SnapshotPackage>>,
        snapshot_config: &SnapshotConfig,
        accounts_hash_kind: AccountsHashKind,
        bank_incremental_snapshot_persistence: Option<BankIncrementalSnapshotPersistence>,
        exit: &AtomicBool,
    ) {
        if !snapshot_config.should_generate_snapshots()
            || !matches!(
                accounts_package.package_kind,
                AccountsPackageKind::Snapshot(_)
            )
        {
            return;
        }
        let Some(snapshot_package_sender) = snapshot_package_sender else {
            return;
        };

        let snapshot_package = SnapshotPackage::new(
            accounts_package,
            accounts_hash_kind,
            bank_incremental_snapshot_persistence,
        );
        let send_result = snapshot_package_sender.send(snapshot_package);
        if let Err(err) = send_result {
            // Sending the snapshot package should never fail *unless* we're shutting down.
            let snapshot_package = &err.0;
            assert!(
                exit.load(Ordering::Relaxed),
                "Failed to send snapshot package: {err}, {snapshot_package:?}"
            );
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_accounts_hash_verifier.join()
    }
}
