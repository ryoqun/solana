// Service to verify accounts hashes with other known validator nodes.
//
// Each interval, publish the snapshot hash which is the full accounts state
// hash on gossip. Monitor gossip for messages from validators in the `--known-validator`s
// set and halt the node if a mismatch is detected.

use {
    crossbeam_channel::{Receiver, Sender},
    solana_gossip::cluster_info::{ClusterInfo, MAX_SNAPSHOT_HASHES},
    solana_measure::{measure, measure::Measure},
    solana_runtime::{
        accounts_hash::{AccountsHash, CalcAccountsHashConfig, HashStats},
        epoch_accounts_hash::EpochAccountsHash,
        snapshot_config::SnapshotConfig,
        snapshot_package::{
            self, retain_max_n_elements, AccountsPackage, AccountsPackageType,
            PendingSnapshotPackage, SnapshotPackage, SnapshotType,
        },
        sorted_storages::SortedStorages,
    },
    solana_sdk::{
        clock::{Slot, SLOT_MS},
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

pub struct AccountsHashVerifier {
    t_accounts_hash_verifier: JoinHandle<()>,
}

impl AccountsHashVerifier {
    pub fn new(
        accounts_package_sender: Sender<AccountsPackage>,
        accounts_package_receiver: Receiver<AccountsPackage>,
        pending_snapshot_package: Option<PendingSnapshotPackage>,
        exit: &Arc<AtomicBool>,
        cluster_info: &Arc<ClusterInfo>,
        known_validators: Option<HashSet<Pubkey>>,
        halt_on_known_validators_accounts_hash_mismatch: bool,
        fault_injection_rate_slots: u64,
        snapshot_config: Option<SnapshotConfig>,
    ) -> Self {
        // If there are no accounts packages to process, limit how often we re-check
        const LOOP_LIMITER: Duration = Duration::from_millis(SLOT_MS);
        let exit = exit.clone();
        let cluster_info = cluster_info.clone();
        let t_accounts_hash_verifier = Builder::new()
            .name("solAcctHashVer".to_string())
            .spawn(move || {
                let mut hashes = vec![];
                loop {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }

                    if let Some((
                        accounts_package,
                        num_outstanding_accounts_packages,
                        num_re_enqueued_accounts_packages,
                    )) = Self::get_next_accounts_package(
                        &accounts_package_sender,
                        &accounts_package_receiver,
                    ) {
                        info!("handling accounts package: {accounts_package:?}");
                        let enqueued_time = accounts_package.enqueued.elapsed();

                        let (_, measure) = measure!(Self::process_accounts_package(
                            accounts_package,
                            &cluster_info,
                            known_validators.as_ref(),
                            halt_on_known_validators_accounts_hash_mismatch,
                            pending_snapshot_package.as_ref(),
                            &mut hashes,
                            &exit,
                            fault_injection_rate_slots,
                            snapshot_config.as_ref(),
                        ));

                        datapoint_info!(
                            "accounts_hash_verifier",
                            (
                                "num-outstanding-accounts-packages",
                                num_outstanding_accounts_packages as i64,
                                i64
                            ),
                            (
                                "num-re-enqueued-accounts-packages",
                                num_re_enqueued_accounts_packages as i64,
                                i64
                            ),
                            ("enqueued-time-us", enqueued_time.as_micros() as i64, i64),
                            ("total-processing-time-us", measure.as_us() as i64, i64),
                        );
                    } else {
                        std::thread::sleep(LOOP_LIMITER);
                    }
                }
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
        pending_snapshot_package: Option<&PendingSnapshotPackage>,
        hashes: &mut Vec<(Slot, Hash)>,
        exit: &Arc<AtomicBool>,
        fault_injection_rate_slots: u64,
        snapshot_config: Option<&SnapshotConfig>,
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
            fault_injection_rate_slots,
            accounts_hash,
        );

        Self::submit_for_packaging(
            accounts_package,
            pending_snapshot_package,
            snapshot_config,
            accounts_hash,
        );
    }

    /// returns calculated accounts hash
    fn calculate_and_verify_accounts_hash(accounts_package: &AccountsPackage) -> AccountsHash {
        let mut measure_hash = Measure::start("hash");
        let mut sort_time = Measure::start("sort_storages");
        let sorted_storages = SortedStorages::new(&accounts_package.snapshot_storages);
        sort_time.stop();

        let mut timings = HashStats {
            storage_sort_us: sort_time.as_us(),
            ..HashStats::default()
        };
        timings.calc_storage_size_quartiles(&accounts_package.snapshot_storages);

        let (accounts_hash, lamports) = accounts_package
            .accounts
            .accounts_db
            .calculate_accounts_hash_from_storages(
                &CalcAccountsHashConfig {
                    use_bg_thread_pool: true,
                    check_hash: false,
                    ancestors: None,
                    epoch_schedule: &accounts_package.epoch_schedule,
                    rent_collector: &accounts_package.rent_collector,
                    store_detailed_debug_info_on_failure: false,
                    full_snapshot: None,
                },
                &sorted_storages,
                timings,
            )
            .unwrap();

        if accounts_package.expected_capitalization != lamports {
            // before we assert, run the hash calc again. This helps track down whether it could have been a failure in a race condition possibly with shrink.
            // We could add diagnostics to the hash calc here to produce a per bin cap or something to help narrow down how many pubkeys are different.
            let result_with_index = accounts_package
                .accounts
                .accounts_db
                .calculate_accounts_hash_from_index(
                    accounts_package.slot,
                    &CalcAccountsHashConfig {
                        use_bg_thread_pool: false,
                        check_hash: false,
                        ancestors: None,
                        epoch_schedule: &accounts_package.epoch_schedule,
                        rent_collector: &accounts_package.rent_collector,
                        store_detailed_debug_info_on_failure: false,
                        full_snapshot: None,
                    },
                );
            info!(
                "hash calc with index: {}, {:?}",
                accounts_package.slot, result_with_index
            );
            let _ = accounts_package
                .accounts
                .accounts_db
                .calculate_accounts_hash_from_storages(
                    &CalcAccountsHashConfig {
                        use_bg_thread_pool: false,
                        check_hash: false,
                        ancestors: None,
                        epoch_schedule: &accounts_package.epoch_schedule,
                        rent_collector: &accounts_package.rent_collector,
                        // now that we've failed, store off the failing contents that produced a bad capitalization
                        store_detailed_debug_info_on_failure: true,
                        full_snapshot: None,
                    },
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

        accounts_package
            .accounts
            .accounts_db
            .notify_accounts_hash_calculated_complete(
                sorted_storages.max_slot_inclusive(),
                &accounts_package.epoch_schedule,
            );

        measure_hash.stop();
        if let Some(snapshot_info) = &accounts_package.snapshot_info {
            solana_runtime::serde_snapshot::reserialize_bank_with_new_accounts_hash(
                snapshot_info.snapshot_links.path(),
                accounts_package.slot,
                &accounts_hash,
                None,
            );
        }
        datapoint_info!(
            "accounts_hash_verifier",
            ("calculate_hash", measure_hash.as_us(), i64),
        );
        accounts_hash
    }

    fn save_epoch_accounts_hash(accounts_package: &AccountsPackage, accounts_hash: AccountsHash) {
        if accounts_package.package_type == AccountsPackageType::EpochAccountsHash {
            info!(
                "saving epoch accounts hash, slot: {}, hash: {}",
                accounts_package.slot, accounts_hash.0,
            );
            let epoch_accounts_hash = EpochAccountsHash::from(accounts_hash);
            accounts_package
                .accounts
                .accounts_db
                .epoch_accounts_hash_manager
                .set_valid(epoch_accounts_hash, accounts_package.slot);
        }
    }

    fn generate_fault_hash(original_hash: &Hash) -> Hash {
        use {
            rand::{thread_rng, Rng},
            solana_sdk::hash::extend_and_hash,
        };

        let rand = thread_rng().gen_range(0, 10);
        extend_and_hash(original_hash, &[rand])
    }

    fn push_accounts_hashes_to_cluster(
        accounts_package: &AccountsPackage,
        cluster_info: &ClusterInfo,
        known_validators: Option<&HashSet<Pubkey>>,
        halt_on_known_validator_accounts_hash_mismatch: bool,
        hashes: &mut Vec<(Slot, Hash)>,
        exit: &Arc<AtomicBool>,
        fault_injection_rate_slots: u64,
        accounts_hash: AccountsHash,
    ) {
        if fault_injection_rate_slots != 0
            && accounts_package.slot % fault_injection_rate_slots == 0
        {
            // For testing, publish an invalid hash to gossip.
            let fault_hash = Self::generate_fault_hash(&accounts_hash.0);
            warn!("inserting fault at slot: {}", accounts_package.slot);
            hashes.push((accounts_package.slot, fault_hash));
        } else {
            hashes.push((accounts_package.slot, accounts_hash.0));
        }

        retain_max_n_elements(hashes, MAX_SNAPSHOT_HASHES);

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
        pending_snapshot_package: Option<&PendingSnapshotPackage>,
        snapshot_config: Option<&SnapshotConfig>,
        accounts_hash: AccountsHash,
    ) {
        if pending_snapshot_package.is_none()
            || !snapshot_config
                .map(|snapshot_config| snapshot_config.should_generate_snapshots())
                .unwrap_or(false)
            || !matches!(
                accounts_package.package_type,
                AccountsPackageType::Snapshot(_)
            )
        {
            return;
        }

        let snapshot_package = SnapshotPackage::new(accounts_package, accounts_hash);
        let pending_snapshot_package = pending_snapshot_package.unwrap();

        // If the snapshot package is an Incremental Snapshot, do not submit it if there's already
        // a pending Full Snapshot.
        let can_submit = match snapshot_package.snapshot_type {
            SnapshotType::FullSnapshot => true,
            SnapshotType::IncrementalSnapshot(_) => pending_snapshot_package
                .lock()
                .unwrap()
                .as_ref()
                .map_or(true, |snapshot_package| {
                    snapshot_package.snapshot_type.is_incremental_snapshot()
                }),
        };

        if can_submit {
            *pending_snapshot_package.lock().unwrap() = Some(snapshot_package);
        }
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
        inc_new_counter_info!("accounts_hash_verifier-hashes_verified", verified_count);
        datapoint_info!(
            "accounts_hash_verifier",
            ("highest_slot_verified", highest_slot, i64),
        );
        false
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_accounts_hash_verifier.join()
    }
}
