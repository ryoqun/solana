#[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
use solana_rbpf::error::EbpfError;
use {
    crate::{invoke_context::InvokeContext, timings::ExecuteDetailsTimings},
    itertools::Itertools,
    log::{debug, log_enabled, trace},
    percentage::PercentageInteger,
    solana_measure::measure::Measure,
    solana_rbpf::{elf::Executable, verifier::RequisiteVerifier, vm::BuiltInProgram},
    solana_sdk::{
        bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, clock::Slot, loader_v4,
        pubkey::Pubkey, saturating_add_assign,
    },
    std::{
        collections::HashMap,
        fmt::{Debug, Formatter},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    },
};

const MAX_LOADED_ENTRY_COUNT: usize = 256;
pub const DELAY_VISIBILITY_SLOT_OFFSET: Slot = 1;

/// Relationship between two fork IDs
#[derive(Copy, Clone, PartialEq)]
pub enum BlockRelation {
    /// The slot is on the same fork and is an ancestor of the other slot
    Ancestor,
    /// The two slots are equal and are on the same fork
    Equal,
    /// The slot is on the same fork and is a descendant of the other slot
    Descendant,
    /// The slots are on two different forks and may have had a common ancestor at some point
    Unrelated,
    /// Either one or both of the slots are either older than the latest root, or are in future
    Unknown,
}

/// Maps relationship between two slots.
pub trait ForkGraph {
    /// Returns the BlockRelation of A to B
    fn relationship(&self, a: Slot, b: Slot) -> BlockRelation;
}

/// Provides information about current working slot, and its ancestors
pub trait WorkingSlot {
    /// Returns the current slot value
    fn current_slot(&self) -> Slot;

    /// Returns true if the `other` slot is an ancestor of self, false otherwise
    fn is_ancestor(&self, other: Slot) -> bool;
}

#[derive(Default)]
pub enum LoadedProgramType {
    /// Tombstone for undeployed, closed or unloadable programs
    #[default]
    FailedVerification,
    Closed,
    DelayVisibility,
    /// Successfully verified but not currently compiled, used to track usage statistics when a compiled program is evicted from memory.
    Unloaded,
    LegacyV0(Executable<RequisiteVerifier, InvokeContext<'static>>),
    LegacyV1(Executable<RequisiteVerifier, InvokeContext<'static>>),
    Typed(Executable<RequisiteVerifier, InvokeContext<'static>>),
    #[cfg(escaped)]
    TestLoaded,
    Builtin(String, BuiltInProgram<InvokeContext<'static>>),
}

impl Debug for LoadedProgramType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadedProgramType::FailedVerification => {
                write!(f, "LoadedProgramType::FailedVerification")
            }
            LoadedProgramType::Closed => write!(f, "LoadedProgramType::Closed"),
            LoadedProgramType::DelayVisibility => write!(f, "LoadedProgramType::DelayVisibility"),
            LoadedProgramType::Unloaded => write!(f, "LoadedProgramType::Unloaded"),
            LoadedProgramType::LegacyV0(_) => write!(f, "LoadedProgramType::LegacyV0"),
            LoadedProgramType::LegacyV1(_) => write!(f, "LoadedProgramType::LegacyV1"),
            LoadedProgramType::Typed(_) => write!(f, "LoadedProgramType::Typed"),
            #[cfg(escaped)]
            LoadedProgramType::TestLoaded => write!(f, "LoadedProgramType::TestLoaded"),
            LoadedProgramType::Builtin(name, _) => {
                write!(f, "LoadedProgramType::Builtin({name})")
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct LoadedProgram {
    /// The program of this entry
    pub program: LoadedProgramType,
    /// Size of account that stores the program and program data
    pub account_size: usize,
    /// Slot in which the program was (re)deployed
    pub deployment_slot: Slot,
    /// Slot in which this entry will become active (can be in the future)
    pub effective_slot: Slot,
    /// Optional expiration slot for this entry, after which it is treated as non-existent
    pub maybe_expiration_slot: Option<Slot>,
    /// How often this entry was used
    pub usage_counter: AtomicU64,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: HashMap<Pubkey, u64>,
    pub insertions: AtomicU64,
    pub replacements: AtomicU64,
    pub one_hit_wonders: AtomicU64,
}

impl Stats {
    /// Logs the measurement values
    pub fn submit(&self, slot: Slot) {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let insertions = self.insertions.load(Ordering::Relaxed);
        let replacements = self.replacements.load(Ordering::Relaxed);
        let one_hit_wonders = self.one_hit_wonders.load(Ordering::Relaxed);
        let evictions: u64 = self.evictions.values().sum();
        datapoint_info!(
            "bank-executor-cache-stats",
            ("slot", slot, i64),
            ("hits", hits, i64),
            ("misses", misses, i64),
            ("evictions", evictions, i64),
            ("insertions", insertions, i64),
            ("replacements", replacements, i64),
            ("one_hit_wonders", one_hit_wonders, i64),
        );
        debug!(
            "Loaded Programs Cache Stats -- Hits: {}, Misses: {}, Evictions: {}, Insertions: {}, Replacements: {}, One-Hit-Wonders: {}",
            hits, misses, evictions, insertions, replacements, one_hit_wonders,
        );
        if log_enabled!(log::Level::Trace) && !self.evictions.is_empty() {
            let mut evictions = self.evictions.iter().collect::<Vec<_>>();
            evictions.sort_by_key(|e| e.1);
            let evictions = evictions
                .into_iter()
                .rev()
                .map(|(program_id, evictions)| {
                    format!("  {:<44}  {}", program_id.to_string(), evictions)
                })
                .collect::<Vec<_>>();
            let evictions = evictions.join("\n");
            trace!(
                "Eviction Details:\n  {:<44}  {}\n{}",
                "Program",
                "Count",
                evictions
            );
        }
    }
}

#[derive(Debug, Default)]
pub struct LoadProgramMetrics {
    pub program_id: String,
    pub register_syscalls_us: u64,
    pub load_elf_us: u64,
    pub verify_code_us: u64,
    pub jit_compile_us: u64,
}

impl LoadProgramMetrics {
    pub fn submit_datapoint(&self, timings: &mut ExecuteDetailsTimings) {
        saturating_add_assign!(
            timings.create_executor_register_syscalls_us,
            self.register_syscalls_us
        );
        saturating_add_assign!(timings.create_executor_load_elf_us, self.load_elf_us);
        saturating_add_assign!(timings.create_executor_verify_code_us, self.verify_code_us);
        saturating_add_assign!(timings.create_executor_jit_compile_us, self.jit_compile_us);
        datapoint_trace!(
            "create_executor_trace",
            ("program_id", self.program_id, String),
            ("register_syscalls_us", self.register_syscalls_us, i64),
            ("load_elf_us", self.load_elf_us, i64),
            ("verify_code_us", self.verify_code_us, i64),
            ("jit_compile_us", self.jit_compile_us, i64),
        );
    }
}

impl PartialEq for LoadedProgram {
    fn eq(&self, other: &Self) -> bool {
        self.effective_slot == other.effective_slot
            && self.deployment_slot == other.deployment_slot
            && self.is_tombstone() == other.is_tombstone()
    }
}

impl LoadedProgram {
    /// Creates a new user program
    pub fn new(
        loader_key: &Pubkey,
        loader: Arc<BuiltInProgram<InvokeContext<'static>>>,
        deployment_slot: Slot,
        effective_slot: Slot,
        maybe_expiration_slot: Option<Slot>,
        elf_bytes: &[u8],
        account_size: usize,
        metrics: &mut LoadProgramMetrics,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut load_elf_time = Measure::start("load_elf_time");
        let executable = Executable::load(elf_bytes, loader.clone())?;
        load_elf_time.stop();
        metrics.load_elf_us = load_elf_time.as_us();

        let mut verify_code_time = Measure::start("verify_code_time");

        // Allowing mut here, since it may be needed for jit compile, which is under a config flag
        #[allow(unused_mut)]
        let mut program = if bpf_loader_deprecated::check_id(loader_key) {
            LoadedProgramType::LegacyV0(Executable::verified(executable)?)
        } else if bpf_loader::check_id(loader_key) || bpf_loader_upgradeable::check_id(loader_key) {
            LoadedProgramType::LegacyV1(Executable::verified(executable)?)
        } else if loader_v4::check_id(loader_key) {
            LoadedProgramType::Typed(Executable::verified(executable)?)
        } else {
            panic!();
        };
        verify_code_time.stop();
        metrics.verify_code_us = verify_code_time.as_us();

        #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
        {
            let mut jit_compile_time = Measure::start("jit_compile_time");
            match &mut program {
                LoadedProgramType::LegacyV0(executable) => executable.jit_compile(),
                LoadedProgramType::LegacyV1(executable) => executable.jit_compile(),
                LoadedProgramType::Typed(executable) => executable.jit_compile(),
                _ => Err(EbpfError::JitNotCompiled),
            }?;
            jit_compile_time.stop();
            metrics.jit_compile_us = jit_compile_time.as_us();
        }

        Ok(Self {
            deployment_slot,
            account_size,
            effective_slot,
            maybe_expiration_slot,
            usage_counter: AtomicU64::new(0),
            program,
        })
    }

    pub fn to_unloaded(&self) -> Self {
        Self {
            program: LoadedProgramType::Unloaded,
            account_size: self.account_size,
            deployment_slot: self.deployment_slot,
            effective_slot: self.effective_slot,
            maybe_expiration_slot: self.maybe_expiration_slot,
            usage_counter: AtomicU64::new(self.usage_counter.load(Ordering::Relaxed)),
        }
    }

    /// Creates a new built-in program
    pub fn new_builtin(
        name: String,
        deployment_slot: Slot,
        program: BuiltInProgram<InvokeContext<'static>>,
    ) -> Self {
        Self {
            deployment_slot,
            account_size: 0,
            effective_slot: deployment_slot.saturating_add(1),
            maybe_expiration_slot: None,
            usage_counter: AtomicU64::new(0),
            program: LoadedProgramType::Builtin(name, program),
        }
    }

    pub fn new_tombstone(slot: Slot, reason: LoadedProgramType) -> Self {
        let maybe_expiration_slot = matches!(reason, LoadedProgramType::DelayVisibility)
            .then_some(slot.saturating_add(DELAY_VISIBILITY_SLOT_OFFSET));
        let tombstone = Self {
            program: reason,
            account_size: 0,
            deployment_slot: slot,
            effective_slot: slot,
            maybe_expiration_slot,
            usage_counter: AtomicU64::default(),
        };
        debug_assert!(tombstone.is_tombstone());
        tombstone
    }

    pub fn is_tombstone(&self) -> bool {
        matches!(
            self.program,
            LoadedProgramType::FailedVerification
                | LoadedProgramType::Closed
                | LoadedProgramType::DelayVisibility
        )
    }

    fn is_loaded(&self) -> bool {
        match self.program {
            LoadedProgramType::LegacyV0(_)
            | LoadedProgramType::LegacyV1(_)
            | LoadedProgramType::Typed(_) => true,
            #[cfg(escaped)]
            LoadedProgramType::TestLoaded => true,
            _ => false,
        }
    }

    fn is_implicit_delay_visibility_tombstone(&self, slot: Slot) -> bool {
        self.effective_slot.saturating_sub(self.deployment_slot) == DELAY_VISIBILITY_SLOT_OFFSET
            && slot >= self.deployment_slot
            && slot < self.effective_slot
    }
}

#[derive(Debug, Default)]
pub struct LoadedPrograms {
    /// A two level index:
    ///
    /// Pubkey is the address of a program, multiple versions can coexists simultaneously under the same address (in different slots).
    entries: HashMap<Pubkey, Vec<Arc<LoadedProgram>>>,

    latest_root: Slot,
    pub stats: Stats,
}

#[derive(Debug, Default)]
pub struct LoadedProgramsForTxBatch {
    /// Pubkey is the address of a program.
    /// LoadedProgram is the corresponding program entry valid for the slot in which a transaction is being executed.
    entries: HashMap<Pubkey, Arc<LoadedProgram>>,
    slot: Slot,
}

impl LoadedProgramsForTxBatch {
    pub fn new(slot: Slot) -> Self {
        Self {
            entries: HashMap::new(),
            slot,
        }
    }

    /// Refill the cache with a single entry. It's typically called during transaction loading, and
    /// transaction processing (for program management instructions).
    /// It replaces the existing entry (if any) with the provided entry. The return value contains
    /// `true` if an entry existed.
    /// The function also returns the newly inserted value.
    pub fn replenish(
        &mut self,
        key: Pubkey,
        entry: Arc<LoadedProgram>,
    ) -> (bool, Arc<LoadedProgram>) {
        (self.entries.insert(key, entry.clone()).is_some(), entry)
    }

    pub fn find(&self, key: &Pubkey) -> Option<Arc<LoadedProgram>> {
        self.entries.get(key).map(|entry| {
            if entry.is_implicit_delay_visibility_tombstone(self.slot) {
                // Found a program entry on the current fork, but it's not effective
                // yet. It indicates that the program has delayed visibility. Return
                // the tombstone to reflect that.
                Arc::new(LoadedProgram::new_tombstone(
                    entry.deployment_slot,
                    LoadedProgramType::DelayVisibility,
                ))
            } else {
                entry.clone()
            }
        })
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn set_slot_for_tests(&mut self, slot: Slot) {
        self.slot = slot;
    }

    pub fn merge(&mut self, other: &Self) {
        other.entries.iter().for_each(|(key, entry)| {
            self.replenish(*key, entry.clone());
        })
    }
}

pub enum LoadedProgramMatchCriteria {
    DeployedOnOrAfterSlot(Slot),
    Tombstone,
    NoCriteria,
}

impl LoadedPrograms {
    /// Refill the cache with a single entry. It's typically called during transaction loading,
    /// when the cache doesn't contain the entry corresponding to program `key`.
    /// The function dedupes the cache, in case some other thread replenished the entry in parallel.
    pub fn replenish(
        &mut self,
        key: Pubkey,
        entry: Arc<LoadedProgram>,
    ) -> (bool, Arc<LoadedProgram>) {
        let second_level = self.entries.entry(key).or_insert_with(Vec::new);
        let index = second_level
            .iter()
            .position(|at| at.effective_slot >= entry.effective_slot);
        if let Some((existing, entry_index)) =
            index.and_then(|index| second_level.get(index).map(|value| (value, index)))
        {
            if existing.deployment_slot == entry.deployment_slot
                && existing.effective_slot == entry.effective_slot
            {
                if matches!(existing.program, LoadedProgramType::Unloaded) {
                    // The unloaded program is getting reloaded
                    // Copy over the usage counter to the new entry
                    entry.usage_counter.store(
                        existing.usage_counter.load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    second_level.swap_remove(entry_index);
                } else if existing.is_tombstone() && !entry.is_tombstone() {
                    // The old entry is tombstone and the new one is not. Let's give the new entry
                    // a chance.
                    second_level.swap_remove(entry_index);
                } else {
                    self.stats.replacements.fetch_add(1, Ordering::Relaxed);
                    return (true, existing.clone());
                }
            }
        }
        self.stats.insertions.fetch_add(1, Ordering::Relaxed);
        second_level.insert(index.unwrap_or(second_level.len()), entry.clone());
        (false, entry)
    }

    /// Assign the program `entry` to the given `key` in the cache.
    /// This is typically called when a deployed program is managed (un-/re-/deployed) via
    /// loader instructions. Because of the cooldown, entires can not have the same
    /// deployment_slot and effective_slot.
    pub fn assign_program(&mut self, key: Pubkey, entry: Arc<LoadedProgram>) -> Arc<LoadedProgram> {
        let (was_occupied, entry) = self.replenish(key, entry);
        debug_assert!(!was_occupied);
        entry
    }

    /// Before rerooting the blockstore this removes all programs of orphan forks
    pub fn prune<F: ForkGraph>(&mut self, fork_graph: &F, new_root: Slot) {
        let previous_root = self.latest_root;
        self.entries.retain(|_key, second_level| {
            let mut first_ancestor_found = false;
            *second_level = second_level
                .iter()
                .rev()
                .filter(|entry| {
                    let relation = fork_graph.relationship(entry.deployment_slot, new_root);
                    if entry.deployment_slot >= new_root {
                        matches!(relation, BlockRelation::Equal | BlockRelation::Descendant)
                    } else if !first_ancestor_found
                        && (matches!(relation, BlockRelation::Ancestor)
                            || entry.deployment_slot < previous_root)
                    {
                        first_ancestor_found = true;
                        first_ancestor_found
                    } else {
                        false
                    }
                })
                .cloned()
                .collect();
            second_level.reverse();
            !second_level.is_empty()
        });

        self.remove_expired_entries(new_root);
        self.remove_programs_with_no_entries();

        self.latest_root = std::cmp::max(self.latest_root, new_root);
    }

    fn matches_loaded_program_criteria(
        program: &Arc<LoadedProgram>,
        criteria: &LoadedProgramMatchCriteria,
    ) -> bool {
        match criteria {
            LoadedProgramMatchCriteria::DeployedOnOrAfterSlot(slot) => {
                program.deployment_slot >= *slot
            }
            LoadedProgramMatchCriteria::Tombstone => program.is_tombstone(),
            LoadedProgramMatchCriteria::NoCriteria => true,
        }
    }

    fn is_entry_usable(
        entry: &Arc<LoadedProgram>,
        current_slot: Slot,
        match_criteria: &LoadedProgramMatchCriteria,
    ) -> bool {
        if entry
            .maybe_expiration_slot
            .map(|expiration_slot| expiration_slot <= current_slot)
            .unwrap_or(false)
        {
            // Found an entry that's already expired. Any further entries in the list
            // are older than the current one. So treat the program as missing in the
            // cache and return early.
            return false;
        }

        Self::matches_loaded_program_criteria(entry, match_criteria)
            // If the program was unloaded. Consider it as unusable, so it can be reloaded.
            && !matches!(entry.program, LoadedProgramType::Unloaded)
    }

    /// Extracts a subset of the programs relevant to a transaction batch
    /// and returns which program accounts the accounts DB needs to load.
    pub fn extract<S: WorkingSlot>(
        &self,
        working_slot: &S,
        keys: impl Iterator<Item = (Pubkey, LoadedProgramMatchCriteria)>,
    ) -> (LoadedProgramsForTxBatch, Vec<Pubkey>) {
        let mut missing = Vec::new();
        let found = keys
            .filter_map(|(key, match_criteria)| {
                if let Some(second_level) = self.entries.get(&key) {
                    for entry in second_level.iter().rev() {
                        let current_slot = working_slot.current_slot();
                        if entry.deployment_slot <= self.latest_root
                            || entry.deployment_slot == current_slot
                            || working_slot.is_ancestor(entry.deployment_slot)
                        {
                            if !Self::is_entry_usable(entry, current_slot, &match_criteria) {
                                missing.push(key);
                                return None;
                            }

                            if current_slot >= entry.effective_slot {
                                return Some((key, entry.clone()));
                            } else if entry.is_implicit_delay_visibility_tombstone(current_slot) {
                                // Found a program entry on the current fork, but it's not effective
                                // yet. It indicates that the program has delayed visibility. Return
                                // the tombstone to reflect that.
                                return Some((
                                    key,
                                    Arc::new(LoadedProgram::new_tombstone(
                                        entry.deployment_slot,
                                        LoadedProgramType::DelayVisibility,
                                    )),
                                ));
                            }
                        }
                    }
                }
                missing.push(key);
                None
            })
            .collect::<HashMap<Pubkey, Arc<LoadedProgram>>>();

        self.stats
            .misses
            .fetch_add(missing.len() as u64, Ordering::Relaxed);
        self.stats
            .hits
            .fetch_add(found.len() as u64, Ordering::Relaxed);
        (
            LoadedProgramsForTxBatch {
                entries: found,
                slot: working_slot.current_slot(),
            },
            missing,
        )
    }

    pub fn merge(&mut self, tx_batch_cache: &LoadedProgramsForTxBatch) {
        tx_batch_cache.entries.iter().for_each(|(key, entry)| {
            self.replenish(*key, entry.clone());
        })
    }

    /// Unloads programs which were used infrequently
    pub fn sort_and_unload(&mut self, shrink_to: PercentageInteger) {
        let sorted_candidates: Vec<(Pubkey, Arc<LoadedProgram>)> = self
            .entries
            .iter()
            .flat_map(|(id, list)| {
                list.iter()
                    .filter_map(move |program| match program.program {
                        LoadedProgramType::LegacyV0(_)
                        | LoadedProgramType::LegacyV1(_)
                        | LoadedProgramType::Typed(_) => Some((*id, program.clone())),
                        #[cfg(escaped)]
                        LoadedProgramType::TestLoaded => Some((*id, program.clone())),
                        LoadedProgramType::Unloaded
                        | LoadedProgramType::FailedVerification
                        | LoadedProgramType::Closed
                        | LoadedProgramType::DelayVisibility
                        | LoadedProgramType::Builtin(_, _) => None,
                    })
            })
            .sorted_by_cached_key(|(_id, program)| program.usage_counter.load(Ordering::Relaxed))
            .collect();

        let num_to_unload = sorted_candidates
            .len()
            .saturating_sub(shrink_to.apply_to(MAX_LOADED_ENTRY_COUNT));
        self.unload_program_entries(sorted_candidates.iter().take(num_to_unload));
        self.remove_programs_with_no_entries();
    }

    /// Removes all the entries at the given keys, if they exist
    pub fn remove_programs(&mut self, keys: impl Iterator<Item = Pubkey>) {
        for k in keys {
            self.entries.remove(&k);
        }
    }

    fn remove_expired_entries(&mut self, current_slot: Slot) {
        for entry in self.entries.values_mut() {
            entry.retain(|program| {
                program
                    .maybe_expiration_slot
                    .map(|expiration| expiration > current_slot)
                    .unwrap_or(true)
            });
        }
    }

    fn unload_program(&mut self, id: &Pubkey) {
        if let Some(entries) = self.entries.get_mut(id) {
            entries.iter_mut().for_each(|entry| {
                if entry.is_loaded() {
                    *entry = Arc::new(entry.to_unloaded());
                }
            });
        }
    }

    pub fn unload_all_programs(&mut self) {
        let keys = self.entries.keys().copied().collect::<Vec<Pubkey>>();
        keys.iter().for_each(|key| self.unload_program(key));
    }

    fn unload_program_entries<'a>(
        &mut self,
        remove: impl Iterator<Item = &'a (Pubkey, Arc<LoadedProgram>)>,
    ) {
        for (id, program) in remove {
            if let Some(entries) = self.entries.get_mut(id) {
                if let Some(candidate) = entries.iter_mut().find(|entry| entry == &program) {
                    if candidate.usage_counter.load(Ordering::Relaxed) == 1 {
                        self.stats.one_hit_wonders.fetch_add(1, Ordering::Relaxed);
                    }
                    self.stats
                        .evictions
                        .entry(*id)
                        .and_modify(|c| saturating_add_assign!(*c, 1))
                        .or_insert(1);
                    *candidate = Arc::new(candidate.to_unloaded());
                }
            }
        }
    }

    fn remove_programs_with_no_entries(&mut self) {
        self.entries.retain(|_, programs| !programs.is_empty())
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl solana_frozen_abi::abi_example::AbiExample for LoadedProgram {
    fn example() -> Self {
        // LoadedProgram isn't serializable by definition.
        Self::default()
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl solana_frozen_abi::abi_example::AbiExample for LoadedPrograms {
    fn example() -> Self {
        // LoadedPrograms isn't serializable by definition.
        Self::default()
    }
}
