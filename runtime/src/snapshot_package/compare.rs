use {
    super::{
        AccountsPackage, AccountsPackageKind, SnapshotArchiveInfoGetter, SnapshotKind,
        SnapshotPackage,
    },
    std::cmp::Ordering::{self, Equal, Greater, Less},
};

/// Compare snapshot packages by priority; first by type, then by slot
#[must_use]
pub fn cmp_snapshot_packages_by_priority(a: &SnapshotPackage, b: &SnapshotPackage) -> Ordering {
    cmp_snapshot_kinds_by_priority(&a.snapshot_kind, &b.snapshot_kind).then(a.slot().cmp(&b.slot()))
}

/// Compare accounts packages by priority; first by type, then by slot
#[must_use]
pub fn cmp_accounts_packages_by_priority(a: &AccountsPackage, b: &AccountsPackage) -> Ordering {
    cmp_accounts_package_kinds_by_priority(&a.package_kind, &b.package_kind)
        .then(a.slot.cmp(&b.slot))
}

/// Compare accounts package kinds by priority
///
/// Priority, from highest to lowest:
/// - Epoch Accounts Hash
/// - Full Snapshot
/// - Incremental Snapshot
/// - Accounts Hash Verifier
///
/// If two `Snapshot`s are compared, their snapshot kinds are the tiebreaker.
#[must_use]
pub fn cmp_accounts_package_kinds_by_priority(
    a: &AccountsPackageKind,
    b: &AccountsPackageKind,
) -> Ordering {
    use AccountsPackageKind::*;
    match (a, b) {
        // Epoch Accounts Hash packages
        (EpochAccountsHash, EpochAccountsHash) => Equal,
        (EpochAccountsHash, _) => Greater,
        (_, EpochAccountsHash) => Less,

        // Snapshot packages
        (Snapshot(snapshot_kind_a), Snapshot(snapshot_kind_b)) => {
            cmp_snapshot_kinds_by_priority(snapshot_kind_a, snapshot_kind_b)
        }
        (Snapshot(_), _) => Greater,
        (_, Snapshot(_)) => Less,

        // Accounts Hash Verifier packages
        (AccountsHashVerifier, AccountsHashVerifier) => Equal,
    }
}

/// Compare snapshot kinds by priority
///
/// Full snapshots are higher in priority than incremental snapshots.
/// If two `IncrementalSnapshot`s are compared, their base slots are the tiebreaker.
#[must_use]
pub fn cmp_snapshot_kinds_by_priority(a: &SnapshotKind, b: &SnapshotKind) -> Ordering {
    use SnapshotKind::*;
    match (a, b) {
        (FullSnapshot, FullSnapshot) => Equal,
        (FullSnapshot, IncrementalSnapshot(_)) => Greater,
        (IncrementalSnapshot(_), FullSnapshot) => Less,
        (IncrementalSnapshot(base_slot_a), IncrementalSnapshot(base_slot_b)) => {
            base_slot_a.cmp(base_slot_b)
        }
    }
}
