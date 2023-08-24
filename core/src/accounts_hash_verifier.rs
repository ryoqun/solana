// Service to verify accounts hashes with other known validator nodes.
//
// Each interval, publish the snapshot hash which is the full accounts state
// hash on gossip.

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
    solana_gossip::cluster_info::{ClusterInfo, MAX_ACCOUNTS_HASHES},
    solana_measure::measure_us,
    solana_runtime::{
        serde_snapshot::BankIncrementalSnapshotPersistence,
        snapshot_config::SnapshotConfig,
        snapshot_package::{
            self, retain_max_n_elements, AccountsPackage, AccountsPackageKind, SnapshotKind,
            SnapshotPackage,
        },
        snapshot_utils,
    },
    solana_sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT},
        hash::Hash,
    },
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub type AccountsHashFaultInjector = fn(&Hash, Slot) -> Option<Hash>;

pub struct AccountsHashVerifier {
    t_accounts_hash_verifier: JoinHandle<()>,
}

impl AccountsHashVerifier {
    pub fn new(
        accounts_package_sender: Sender<AccountsPackage>,
        accounts_package_receiver: Receiver<AccountsPackage>,
        snapshot_package_sender: Option<Sender<SnapshotPackage>>,
        exit: Arc<AtomicBool>,
        cluster_info: Arc<ClusterInfo>,
        accounts_hash_fault_injector: Option<AccountsHashFaultInjector>,
        snapshot_config: SnapshotConfig,
    ) -> Self {
        // If there are no accounts packages to process, limit how often we re-check
        const LOOP_LIMITER: Duration = Duration::from_millis(DEFAULT_MS_PER_SLOT);
        let t_accounts_hash_verifier = Builder::new()
            .name("solAcctHashVer".to_string())
            .spawn(move || {
                info!("AccountsHashVerifier has started");
                let mut hashes = vec![];
                // To support fastboot, we must ensure the storages used in the latest POST snapshot are
                // not recycled nor removed early.  Hold an Arc of their AppendVecs to prevent them from
                // expiring.
                let mut last_snapshot_storages = None;
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

                    // If this accounts package is for a snapshot, then clone the storages to
                    // save for fastboot.
                    let snapshot_storages_for_fastboot = accounts_package
                        .snapshot_info
                        .is_some()
                        .then(|| accounts_package.snapshot_storages.clone());

                    let (_, handling_time_us) = measure_us!(Self::process_accounts_package(
                        accounts_package,
                        &cluster_info,
                        snapshot_package_sender.as_ref(),
                        &mut hashes,
                        &snapshot_config,
                        accounts_hash_fault_injector,
                        &exit,
                    ));

                    if let Some(snapshot_storages_for_fastboot) = snapshot_storages_for_fastboot {
                        last_snapshot_storages = Some(snapshot_storages_for_fastboot)
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
                debug!(
                    "Number of snapshot storages kept alive for fastboot: {}",
                    last_snapshot_storages
                        .as_ref()
                        .map(|storages| storages.len())
                        .unwrap_or(0)
                );
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
        cluster_info: &ClusterInfo,
        snapshot_package_sender: Option<&Sender<SnapshotPackage>>,
        hashes: &mut Vec<(Slot, Hash)>,
        snapshot_config: &SnapshotConfig,
        accounts_hash_fault_injector: Option<AccountsHashFaultInjector>,
        exit: &AtomicBool,
    ) {
        let accounts_hash =
            Self::calculate_and_verify_accounts_hash(&accounts_package, snapshot_config);

        Self::save_epoch_accounts_hash(&accounts_package, accounts_hash);

        Self::push_accounts_hashes_to_cluster(
            &accounts_package,
            cluster_info,
            hashes,
            accounts_hash,
            accounts_hash_fault_injector,
        );

        Self::submit_for_packaging(
            accounts_package,
            snapshot_package_sender,
            snapshot_config,
            accounts_hash,
            exit,
        );
    }

    /// returns calculated accounts hash
    fn calculate_and_verify_accounts_hash(
        accounts_package: &AccountsPackage,
        snapshot_config: &SnapshotConfig,
    ) -> AccountsHashKind {
        let accounts_hash_calculation_kind = match accounts_package.package_kind {
            AccountsPackageKind::AccountsHashVerifier => CalcAccountsHashKind::Full,
            AccountsPackageKind::EpochAccountsHash => CalcAccountsHashKind::Full,
            AccountsPackageKind::Snapshot(snapshot_kind) => match snapshot_kind {
                SnapshotKind::FullSnapshot => CalcAccountsHashKind::Full,
                SnapshotKind::IncrementalSnapshot(_) => {
                    if accounts_package.is_incremental_accounts_hash_feature_enabled {
                        CalcAccountsHashKind::Incremental
                    } else {
                        CalcAccountsHashKind::Full
                    }
                }
            },
        };

        let (
            accounts_hash_kind,
            accounts_hash_for_reserialize,
            bank_incremental_snapshot_persistence,
        ) = match accounts_hash_calculation_kind {
            CalcAccountsHashKind::Full => {
                let (accounts_hash, _capitalization) =
                    Self::_calculate_full_accounts_hash(accounts_package);
                (accounts_hash.into(), accounts_hash, None)
            }
            CalcAccountsHashKind::Incremental => {
                let AccountsPackageKind::Snapshot(SnapshotKind::IncrementalSnapshot(base_slot)) =
                    accounts_package.package_kind
                else {
                    panic!("Calculating incremental accounts hash requires a base slot");
                };
                let (base_accounts_hash, base_capitalization) = accounts_package
                    .accounts
                    .accounts_db
                    .get_accounts_hash(base_slot)
                    .expect("incremental snapshot requires accounts hash and capitalization from the full snapshot it is based on");
                let (incremental_accounts_hash, incremental_capitalization) =
                    Self::_calculate_incremental_accounts_hash(accounts_package, base_slot);
                let bank_incremental_snapshot_persistence = BankIncrementalSnapshotPersistence {
                    full_slot: base_slot,
                    full_hash: base_accounts_hash.into(),
                    full_capitalization: base_capitalization,
                    incremental_hash: incremental_accounts_hash.into(),
                    incremental_capitalization,
                };
                (
                    incremental_accounts_hash.into(),
                    AccountsHash(Hash::default()), // value does not matter; not used for incremental snapshots
                    Some(bank_incremental_snapshot_persistence),
                )
            }
        };

        if let Some(snapshot_info) = &accounts_package.snapshot_info {
            solana_runtime::serde_snapshot::reserialize_bank_with_new_accounts_hash(
                &snapshot_info.bank_snapshot_dir,
                accounts_package.slot,
                &accounts_hash_for_reserialize,
                bank_incremental_snapshot_persistence.as_ref(),
            );
        }

        if accounts_package.package_kind
            == AccountsPackageKind::Snapshot(SnapshotKind::FullSnapshot)
        {
            accounts_package
                .accounts
                .accounts_db
                .purge_old_accounts_hashes(accounts_package.slot);
        }

        // After an accounts package has had its accounts hash calculated and
        // has been reserialized to become a BankSnapshotPost, it is now safe
        // to clean up some older bank snapshots.
        //
        // If we are generating snapshots, then this accounts package will be sent
        // to SnapshotPackagerService to be archived.  SPS needs the bank snapshots
        // to make the archives, so we cannot purge any bank snapshots that SPS
        // may still be using. Therefore, we defer purging to SPS.
        //
        // If we are *not* generating snapshots, then purge old bank snapshots here.
        if !snapshot_config.should_generate_snapshots() {
            let (_, purge_bank_snapshots_time_us) =
                measure_us!(snapshot_utils::purge_bank_snapshots_older_than_slot(
                    &snapshot_config.bank_snapshots_dir,
                    accounts_package.slot,
                ));
            datapoint_info!(
                "accounts_hash_verifier",
                (
                    "purge_old_snapshots_time_us",
                    purge_bank_snapshots_time_us,
                    i64
                ),
            );
        }

        accounts_hash_kind
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
            check_hash: false,
            ancestors: None,
            epoch_schedule: &accounts_package.epoch_schedule,
            rent_collector: &accounts_package.rent_collector,
            store_detailed_debug_info_on_failure: false,
            include_slot_in_hash: accounts_package.include_slot_in_hash,
        };

        let slot = accounts_package.slot;
        let ((accounts_hash, lamports), measure_hash_us) = measure_us!(accounts_package
            .accounts
            .accounts_db
            .update_accounts_hash(
                &calculate_accounts_hash_config,
                &sorted_storages,
                slot,
                timings,
            )
            .unwrap()); // unwrap here will never fail since check_hash = false

        if accounts_package.expected_capitalization != lamports {
            // before we assert, run the hash calc again. This helps track down whether it could have been a failure in a race condition possibly with shrink.
            // We could add diagnostics to the hash calc here to produce a per bin cap or something to help narrow down how many pubkeys are different.
            let calculate_accounts_hash_config = CalcAccountsHashConfig {
                // since we're going to assert, use the fg thread pool to go faster
                use_bg_thread_pool: false,
                ..calculate_accounts_hash_config
            };
            let result_with_index = accounts_package
                .accounts
                .accounts_db
                .calculate_accounts_hash_from_index(slot, &calculate_accounts_hash_config);
            info!("hash calc with index: {slot}, {result_with_index:?}",);
            let calculate_accounts_hash_config = CalcAccountsHashConfig {
                // now that we've failed, store off the failing contents that produced a bad capitalization
                store_detailed_debug_info_on_failure: true,
                ..calculate_accounts_hash_config
            };
            _ = accounts_package
                .accounts
                .accounts_db
                .calculate_accounts_hash_from_storages(
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
            check_hash: false,
            ancestors: None,
            epoch_schedule: &accounts_package.epoch_schedule,
            rent_collector: &accounts_package.rent_collector,
            store_detailed_debug_info_on_failure: false,
            include_slot_in_hash: accounts_package.include_slot_in_hash,
        };

        let (incremental_accounts_hash, measure_hash_us) = measure_us!(
            accounts_package
                .accounts
                .accounts_db
                .update_incremental_accounts_hash(
                    &calculate_accounts_hash_config,
                    &sorted_storages,
                    accounts_package.slot,
                    HashStats::default(),
                )
                .unwrap() // unwrap here will never fail since check_hash = false
        );

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

    fn push_accounts_hashes_to_cluster(
        accounts_package: &AccountsPackage,
        cluster_info: &ClusterInfo,
        hashes: &mut Vec<(Slot, Hash)>,
        accounts_hash: AccountsHashKind,
        accounts_hash_fault_injector: Option<AccountsHashFaultInjector>,
    ) {
        let hash = accounts_hash_fault_injector
            .and_then(|f| f(accounts_hash.as_hash(), accounts_package.slot))
            .or(Some(*accounts_hash.as_hash()));
        hashes.push((accounts_package.slot, hash.unwrap()));

        retain_max_n_elements(hashes, MAX_ACCOUNTS_HASHES);

        cluster_info.push_accounts_hashes(hashes.clone());
    }

    fn submit_for_packaging(
        accounts_package: AccountsPackage,
        snapshot_package_sender: Option<&Sender<SnapshotPackage>>,
        snapshot_config: &SnapshotConfig,
        accounts_hash: AccountsHashKind,
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

        let snapshot_package = SnapshotPackage::new(accounts_package, accounts_hash);
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
