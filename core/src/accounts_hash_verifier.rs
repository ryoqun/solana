// Service to verify accounts hashes with other known validator nodes.
//
// Each interval, publish the snapshot hash which is the full accounts state
// hash on gossip. Monitor gossip for messages from validators in the `--known-validator`s
// set and halt the node if a mismatch is detected.

use {
    crossbeam_channel::{Receiver, Sender},
    solana_gossip::cluster_info::{ClusterInfo, MAX_ACCOUNTS_HASHES},
    solana_measure::measure_us,
    solana_runtime::{
        accounts_db::CalcAccountsHashFlavor,
        accounts_hash::{
            AccountsHash, AccountsHashEnum, CalcAccountsHashConfig, HashStats,
            IncrementalAccountsHash,
        },
        serde_snapshot::BankIncrementalSnapshotPersistence,
        snapshot_config::SnapshotConfig,
        snapshot_package::{
            self, retain_max_n_elements, AccountsPackage, AccountsPackageType, SnapshotPackage,
            SnapshotType,
        },
        sorted_storages::SortedStorages,
    },
    solana_sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT},
        hash::Hash,
        pubkey::Pubkey,
    },
    std::{
        collections::{HashMap, HashSet},
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
        known_validators: Option<HashSet<Pubkey>>,
        halt_on_known_validators_accounts_hash_mismatch: bool,
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
                    ) else {
                        std::thread::sleep(LOOP_LIMITER);
                        continue;
                    };
                    info!("handling accounts package: {accounts_package:?}");
                    let enqueued_time = accounts_package.enqueued.elapsed();

                    let snapshot_storages = accounts_package.snapshot_storages.clone();

                    let (_, handling_time_us) = measure_us!(Self::process_accounts_package(
                        accounts_package,
                        &cluster_info,
                        known_validators.as_ref(),
                        halt_on_known_validators_accounts_hash_mismatch,
                        snapshot_package_sender.as_ref(),
                        &mut hashes,
                        &exit,
                        &snapshot_config,
                        accounts_hash_fault_injector,
                    ));

                    // Done processing the current snapshot, so the current snapshot dir
                    // has been converted to POST state.  It is the time to update
                    // last_snapshot_storages to release the reference counts for the
                    // previous POST snapshot dir, and save the new ones for the new
                    // POST snapshot dir.
                    last_snapshot_storages = Some(snapshot_storages);
                    debug!(
                        "Number of snapshot storages kept alive for fastboot: {}",
                        last_snapshot_storages
                            .as_ref()
                            .map(|storages| storages.len())
                            .unwrap_or(0)
                    );

                    datapoint_info!(
                        "accounts_hash_verifier",
                        (
                            "num-outstanding-accounts-packages",
                            num_outstanding_accounts_packages,
                            i64
                        ),
                        (
                            "num-re-enqueued-accounts-packages",
                            num_re_enqueued_accounts_packages,
                            i64
                        ),
                        ("enqueued-time-us", enqueued_time.as_micros(), i64),
                        ("handling-time-us", handling_time_us, i64),
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
        // `select_nth()` panics if the slice is empty, so continue if that's the case
        if accounts_packages.is_empty() {
            return None;
        }
        let accounts_packages_len = accounts_packages.len();
        debug!("outstanding accounts packages ({accounts_packages_len}): {accounts_packages:?}");
        let num_eah_packages = accounts_packages
            .iter()
            .filter(|account_package| {
                account_package.package_type == AccountsPackageType::EpochAccountsHash
            })
            .count();
        assert!(
            num_eah_packages <= 1,
            "Only a single EAH accounts package is allowed at a time! count: {num_eah_packages}"
        );

        accounts_packages.select_nth_unstable_by(
            accounts_packages_len - 1,
            snapshot_package::cmp_accounts_packages_by_priority,
        );
        // SAFETY: We know `accounts_packages` is not empty, so its len is >= 1,
        // therefore there is always an element to pop.
        let accounts_package = accounts_packages.pop().unwrap();
        let handled_accounts_package_slot = accounts_package.slot;
        // re-enqueue any remaining accounts packages for slots GREATER-THAN the accounts package
        // that will be handled
        let num_re_enqueued_accounts_packages = accounts_packages
            .into_iter()
            .filter(|accounts_package| accounts_package.slot > handled_accounts_package_slot)
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

    #[allow(clippy::too_many_arguments)]
    fn process_accounts_package(
        accounts_package: AccountsPackage,
        cluster_info: &ClusterInfo,
        known_validators: Option<&HashSet<Pubkey>>,
        halt_on_known_validator_accounts_hash_mismatch: bool,
        snapshot_package_sender: Option<&Sender<SnapshotPackage>>,
        hashes: &mut Vec<(Slot, Hash)>,
        exit: &AtomicBool,
        snapshot_config: &SnapshotConfig,
        accounts_hash_fault_injector: Option<AccountsHashFaultInjector>,
    ) {
        let accounts_hash = Self::calculate_and_verify_accounts_hash(&accounts_package);

        Self::save_epoch_accounts_hash(&accounts_package, accounts_hash);

        Self::push_accounts_hashes_to_cluster(
            &accounts_package,
            cluster_info,
            known_validators,
            halt_on_known_validator_accounts_hash_mismatch,
            hashes,
            exit,
            accounts_hash,
            accounts_hash_fault_injector,
        );

        Self::submit_for_packaging(
            accounts_package,
            snapshot_package_sender,
            snapshot_config,
            accounts_hash,
        );
    }

    /// returns calculated accounts hash
    fn calculate_and_verify_accounts_hash(accounts_package: &AccountsPackage) -> AccountsHashEnum {
        let accounts_hash_calculation_flavor = match accounts_package.package_type {
            AccountsPackageType::AccountsHashVerifier => CalcAccountsHashFlavor::Full,
            AccountsPackageType::EpochAccountsHash => CalcAccountsHashFlavor::Full,
            AccountsPackageType::Snapshot(snapshot_type) => match snapshot_type {
                SnapshotType::FullSnapshot => CalcAccountsHashFlavor::Full,
                SnapshotType::IncrementalSnapshot(_) => {
                    if accounts_package.is_incremental_accounts_hash_feature_enabled {
                        CalcAccountsHashFlavor::Incremental
                    } else {
                        CalcAccountsHashFlavor::Full
                    }
                }
            },
        };

        let (
            accounts_hash_enum,
            accounts_hash_for_reserialize,
            bank_incremental_snapshot_persistence,
        ) = match accounts_hash_calculation_flavor {
            CalcAccountsHashFlavor::Full => {
                let (accounts_hash, _capitalization) =
                    Self::_calculate_full_accounts_hash(accounts_package);
                (accounts_hash.into(), accounts_hash, None)
            }
            CalcAccountsHashFlavor::Incremental => {
                let AccountsPackageType::Snapshot(SnapshotType::IncrementalSnapshot(base_slot)) = accounts_package.package_type else {
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

        if accounts_package.package_type
            == AccountsPackageType::Snapshot(SnapshotType::FullSnapshot)
        {
            accounts_package
                .accounts
                .accounts_db
                .purge_old_accounts_hashes(accounts_package.slot);
        }
        accounts_hash_enum
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

        let ((accounts_hash, lamports), measure_hash_us) = measure_us!(accounts_package
            .accounts
            .accounts_db
            .calculate_accounts_hash_from_storages(
                &calculate_accounts_hash_config,
                &sorted_storages,
                timings,
            )
            .unwrap()); // unwrap here will never fail since check_hash = false

        let slot = accounts_package.slot;
        let old_accounts_hash = accounts_package
            .accounts
            .accounts_db
            .set_accounts_hash(slot, (accounts_hash, lamports));
        if let Some(old_accounts_hash) = old_accounts_hash {
            warn!("Accounts hash was already set for slot {slot}! old: {old_accounts_hash:?}, new: {accounts_hash:?}");
        }

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
        accounts_hash: AccountsHashEnum,
    ) {
        if accounts_package.package_type == AccountsPackageType::EpochAccountsHash {
            let AccountsHashEnum::Full(accounts_hash) = accounts_hash else {
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
        known_validators: Option<&HashSet<Pubkey>>,
        halt_on_known_validator_accounts_hash_mismatch: bool,
        hashes: &mut Vec<(Slot, Hash)>,
        exit: &AtomicBool,
        accounts_hash: AccountsHashEnum,
        accounts_hash_fault_injector: Option<AccountsHashFaultInjector>,
    ) {
        let hash = accounts_hash_fault_injector
            .and_then(|f| f(accounts_hash.as_hash(), accounts_package.slot))
            .or(Some(*accounts_hash.as_hash()));
        hashes.push((accounts_package.slot, hash.unwrap()));

        retain_max_n_elements(hashes, MAX_ACCOUNTS_HASHES);

        if halt_on_known_validator_accounts_hash_mismatch {
            let mut slot_to_hash = HashMap::new();
            for (slot, hash) in hashes.iter() {
                slot_to_hash.insert(*slot, *hash);
            }
            if Self::should_halt(cluster_info, known_validators, &mut slot_to_hash) {
                exit.store(true, Ordering::Relaxed);
            }
        }

        cluster_info.push_accounts_hashes(hashes.clone());
    }

    fn submit_for_packaging(
        accounts_package: AccountsPackage,
        snapshot_package_sender: Option<&Sender<SnapshotPackage>>,
        snapshot_config: &SnapshotConfig,
        accounts_hash: AccountsHashEnum,
    ) {
        if !snapshot_config.should_generate_snapshots()
            || !matches!(
                accounts_package.package_type,
                AccountsPackageType::Snapshot(_)
            )
        {
            return;
        }
        let Some(snapshot_package_sender) = snapshot_package_sender else {
            return;
        };

        let snapshot_package = SnapshotPackage::new(accounts_package, accounts_hash);
        snapshot_package_sender
            .send(snapshot_package)
            .expect("send snapshot package");
    }

    fn should_halt(
        cluster_info: &ClusterInfo,
        known_validators: Option<&HashSet<Pubkey>>,
        slot_to_hash: &mut HashMap<Slot, Hash>,
    ) -> bool {
        let mut verified_count = 0;
        let mut highest_slot = 0;
        if let Some(known_validators) = known_validators {
            for known_validator in known_validators {
                let is_conflicting = cluster_info.get_accounts_hash_for_node(known_validator, |accounts_hashes|
                {
                    accounts_hashes.iter().any(|(slot, hash)| {
                        if let Some(reference_hash) = slot_to_hash.get(slot) {
                            if *hash != *reference_hash {
                                error!("Fatal! Exiting! Known validator {} produced conflicting hashes for slot: {} ({} != {})",
                                    known_validator,
                                    slot,
                                    hash,
                                    reference_hash,
                                );
                                true
                            } else {
                                verified_count += 1;
                                false
                            }
                        } else {
                            highest_slot = std::cmp::max(*slot, highest_slot);
                            slot_to_hash.insert(*slot, *hash);
                            false
                        }
                    })
                }).unwrap_or(false);

                if is_conflicting {
                    return true;
                }
            }
        }
        datapoint_info!(
            "accounts_hash_verifier",
            ("highest_slot_verified", highest_slot, i64),
            ("num_verified", verified_count, i64),
        );
        false
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_accounts_hash_verifier.join()
    }
}
