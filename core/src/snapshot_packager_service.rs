use {
    solana_gossip::cluster_info::{
        ClusterInfo, MAX_INCREMENTAL_SNAPSHOT_HASHES, MAX_SNAPSHOT_HASHES,
    },
    solana_perf::thread::renice_this_thread,
    solana_runtime::{
        snapshot_archive_info::SnapshotArchiveInfoGetter,
        snapshot_config::SnapshotConfig,
        snapshot_hash::{
            FullSnapshotHash, FullSnapshotHashes, IncrementalSnapshotHash,
            IncrementalSnapshotHashes, StartingSnapshotHashes,
        },
        snapshot_package::{retain_max_n_elements, PendingSnapshotPackage, SnapshotType},
        snapshot_utils,
    },
    solana_sdk::{clock::Slot, hash::Hash},
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct SnapshotPackagerService {
    t_snapshot_packager: JoinHandle<()>,
}

impl SnapshotPackagerService {
    pub fn new(
        pending_snapshot_package: PendingSnapshotPackage,
        starting_snapshot_hashes: Option<StartingSnapshotHashes>,
        exit: &Arc<AtomicBool>,
        cluster_info: &Arc<ClusterInfo>,
        snapshot_config: SnapshotConfig,
        enable_gossip_push: bool,
    ) -> Self {
        let exit = exit.clone();
        let cluster_info = cluster_info.clone();
        let max_full_snapshot_hashes = std::cmp::min(
            MAX_SNAPSHOT_HASHES,
            snapshot_config.maximum_full_snapshot_archives_to_retain,
        );
        let max_incremental_snapshot_hashes = std::cmp::min(
            MAX_INCREMENTAL_SNAPSHOT_HASHES,
            snapshot_config.maximum_incremental_snapshot_archives_to_retain,
        );

        let t_snapshot_packager = Builder::new()
            .name("solSnapshotPkgr".to_string())
            .spawn(move || {
                renice_this_thread(snapshot_config.packager_thread_niceness_adj).unwrap();
                let mut snapshot_gossip_manager = if enable_gossip_push {
                    Some(SnapshotGossipManager {
                        cluster_info,
                        max_full_snapshot_hashes,
                        max_incremental_snapshot_hashes,
                        full_snapshot_hashes: FullSnapshotHashes::default(),
                        incremental_snapshot_hashes: IncrementalSnapshotHashes::default(),
                    })
                } else {
                    None
                };
                if let Some(snapshot_gossip_manager) = snapshot_gossip_manager.as_mut() {
                    snapshot_gossip_manager.push_starting_snapshot_hashes(starting_snapshot_hashes);
                }

                loop {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }

                    let snapshot_package = pending_snapshot_package.lock().unwrap().take();
                    if snapshot_package.is_none() {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    let snapshot_package = snapshot_package.unwrap();

                    // Archiving the snapshot package is not allowed to fail.
                    // AccountsBackgroundService calls `clean_accounts()` with a value for
                    // last_full_snapshot_slot that requires this archive call to succeed.
                    snapshot_utils::archive_snapshot_package(
                        &snapshot_package,
                        &snapshot_config.full_snapshot_archives_dir,
                        &snapshot_config.incremental_snapshot_archives_dir,
                        snapshot_config.maximum_full_snapshot_archives_to_retain,
                        snapshot_config.maximum_incremental_snapshot_archives_to_retain,
                    )
                    .expect("failed to archive snapshot package");

                    if let Some(snapshot_gossip_manager) = snapshot_gossip_manager.as_mut() {
                        snapshot_gossip_manager.push_snapshot_hash(
                            snapshot_package.snapshot_type,
                            (snapshot_package.slot(), snapshot_package.hash().0),
                        );
                    }
                }
            })
            .unwrap();

        Self {
            t_snapshot_packager,
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_snapshot_packager.join()
    }
}

struct SnapshotGossipManager {
    cluster_info: Arc<ClusterInfo>,
    max_full_snapshot_hashes: usize,
    max_incremental_snapshot_hashes: usize,
    full_snapshot_hashes: FullSnapshotHashes,
    incremental_snapshot_hashes: IncrementalSnapshotHashes,
}

impl SnapshotGossipManager {
    /// If there were starting snapshot hashes, add those to their respective vectors, then push
    /// those vectors to the cluster via CRDS.
    fn push_starting_snapshot_hashes(
        &mut self,
        starting_snapshot_hashes: Option<StartingSnapshotHashes>,
    ) {
        if let Some(starting_snapshot_hashes) = starting_snapshot_hashes {
            let starting_full_snapshot_hash = starting_snapshot_hashes.full;
            self.push_full_snapshot_hash(starting_full_snapshot_hash);

            if let Some(starting_incremental_snapshot_hash) = starting_snapshot_hashes.incremental {
                self.push_incremental_snapshot_hash(starting_incremental_snapshot_hash);
            };
        }
    }

    /// Add `snapshot_hash` to its respective vector of hashes, then push that vector to the
    /// cluster via CRDS.
    fn push_snapshot_hash(&mut self, snapshot_type: SnapshotType, snapshot_hash: (Slot, Hash)) {
        match snapshot_type {
            SnapshotType::FullSnapshot => {
                self.push_full_snapshot_hash(FullSnapshotHash {
                    hash: snapshot_hash,
                });
            }
            SnapshotType::IncrementalSnapshot(base_slot) => {
                let latest_full_snapshot_hash = *self.full_snapshot_hashes.hashes.last().unwrap();
                assert_eq!(
                    base_slot, latest_full_snapshot_hash.0,
                    "the incremental snapshot's base slot ({}) must match the latest full snapshot hash's slot ({})",
                    base_slot, latest_full_snapshot_hash.0,
                );
                self.push_incremental_snapshot_hash(IncrementalSnapshotHash {
                    base: latest_full_snapshot_hash,
                    hash: snapshot_hash,
                });
            }
        }
    }

    /// Add `full_snapshot_hash` to the vector of full snapshot hashes, then push that vector to
    /// the cluster via CRDS.
    fn push_full_snapshot_hash(&mut self, full_snapshot_hash: FullSnapshotHash) {
        self.full_snapshot_hashes
            .hashes
            .push(full_snapshot_hash.hash);

        retain_max_n_elements(
            &mut self.full_snapshot_hashes.hashes,
            self.max_full_snapshot_hashes,
        );

        self.cluster_info
            .push_snapshot_hashes(self.full_snapshot_hashes.hashes.clone());
    }

    /// Add `incremental_snapshot_hash` to the vector of incremental snapshot hashes, then push
    /// that vector to the cluster via CRDS.
    fn push_incremental_snapshot_hash(
        &mut self,
        incremental_snapshot_hash: IncrementalSnapshotHash,
    ) {
        // If the base snapshot hash is different from the one in IncrementalSnapshotHashes, then
        // that means the old incremental snapshot hashes are no longer valid, so clear them all
        // out.
        if incremental_snapshot_hash.base != self.incremental_snapshot_hashes.base {
            self.incremental_snapshot_hashes.hashes.clear();
            self.incremental_snapshot_hashes.base = incremental_snapshot_hash.base;
        }

        self.incremental_snapshot_hashes
            .hashes
            .push(incremental_snapshot_hash.hash);

        retain_max_n_elements(
            &mut self.incremental_snapshot_hashes.hashes,
            self.max_incremental_snapshot_hashes,
        );

        // Pushing incremental snapshot hashes to the cluster should never fail.  The only error
        // case is when the length of the hashes is too big, but we account for that with
        // `max_incremental_snapshot_hashes`.  If this call ever does error, it's a programmer bug!
        // Check to see what changed in `push_incremental_snapshot_hashes()` and handle the new
        // error condition here.
        self.cluster_info
            .push_incremental_snapshot_hashes(
                self.incremental_snapshot_hashes.base,
                self.incremental_snapshot_hashes.hashes.clone(),
            )
            .expect(
                "Bug! The programmer contract has changed for push_incremental_snapshot_hashes() \
                 and a new error case has been added, which has not been handled here.",
            );
    }
}
