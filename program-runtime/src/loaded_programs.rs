#[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
use solana_rbpf::error::EbpfError;
use {
    crate::{invoke_context::InvokeContext, timings::ExecuteDetailsTimings},
    itertools::Itertools,
    percentage::PercentageInteger,
    solana_measure::measure::Measure,
    solana_rbpf::{
        elf::Executable,
        verifier::RequisiteVerifier,
        vm::{BuiltInProgram, VerifiedExecutable},
    },
    solana_sdk::{
        bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, clock::Slot, loader_v3,
        pubkey::Pubkey, saturating_add_assign,
    },
    std::{
        cmp,
        collections::HashMap,
        fmt::{Debug, Formatter},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    },
};

const MAX_LOADED_ENTRY_COUNT: usize = 256;
const MAX_UNLOADED_ENTRY_COUNT: usize = 1024;

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
    LegacyV0(VerifiedExecutable<RequisiteVerifier, InvokeContext<'static>>),
    LegacyV1(VerifiedExecutable<RequisiteVerifier, InvokeContext<'static>>),
    Typed(VerifiedExecutable<RequisiteVerifier, InvokeContext<'static>>),
    #[cfg(escaped)]
    TestLoaded,
    BuiltIn(BuiltInProgram<InvokeContext<'static>>),
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
            LoadedProgramType::BuiltIn(_) => write!(f, "LoadedProgramType::BuiltIn"),
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
            LoadedProgramType::LegacyV0(VerifiedExecutable::from_executable(executable)?)
        } else if bpf_loader::check_id(loader_key) || bpf_loader_upgradeable::check_id(loader_key) {
            LoadedProgramType::LegacyV1(VerifiedExecutable::from_executable(executable)?)
        } else if loader_v3::check_id(loader_key) {
            LoadedProgramType::Typed(VerifiedExecutable::from_executable(executable)?)
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
    pub fn new_built_in(
        deployment_slot: Slot,
        program: BuiltInProgram<InvokeContext<'static>>,
    ) -> Self {
        Self {
            deployment_slot,
            account_size: 0,
            effective_slot: deployment_slot.saturating_add(1),
            maybe_expiration_slot: None,
            usage_counter: AtomicU64::new(0),
            program: LoadedProgramType::BuiltIn(program),
        }
    }

    pub fn new_tombstone(slot: Slot, reason: LoadedProgramType) -> Self {
        let maybe_expiration_slot =
            matches!(reason, LoadedProgramType::DelayVisibility).then_some(slot.saturating_add(1));
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
}

#[derive(Debug, Default)]
pub struct LoadedPrograms {
    /// A two level index:
    ///
    /// Pubkey is the address of a program, multiple versions can coexists simultaneously under the same address (in different slots).
    entries: HashMap<Pubkey, Vec<Arc<LoadedProgram>>>,
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl solana_frozen_abi::abi_example::AbiExample for LoadedPrograms {
    fn example() -> Self {
        // Delegate AbiExample impl to Default before going deep and stuck with
        // not easily impl-able Arc<dyn Executor> due to rust's coherence issue
        // This is safe because LoadedPrograms isn't serializable by definition.
        Self::default()
    }
}

pub enum LoadedProgramMatchCriteria {
    DeployedOnOrAfterSlot(Slot),
    Closed,
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
                } else {
                    return (true, existing.clone());
                }
            }
        }
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
        self.entries.retain(|_key, second_level| {
            let mut first_ancestor_found = false;
            *second_level = second_level
                .iter()
                .rev()
                .filter(|entry| {
                    let relation = fork_graph.relationship(entry.deployment_slot, new_root);
                    if entry.deployment_slot >= new_root {
                        matches!(relation, BlockRelation::Equal | BlockRelation::Descendant)
                    } else if !first_ancestor_found && matches!(relation, BlockRelation::Ancestor) {
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
    }

    fn matches_loaded_program(
        program: &Arc<LoadedProgram>,
        criteria: &LoadedProgramMatchCriteria,
    ) -> bool {
        match criteria {
            LoadedProgramMatchCriteria::DeployedOnOrAfterSlot(slot) => {
                program.deployment_slot >= *slot
            }
            LoadedProgramMatchCriteria::Closed => {
                matches!(program.program, LoadedProgramType::Closed)
            }
            LoadedProgramMatchCriteria::NoCriteria => true,
        }
    }

    /// Extracts a subset of the programs relevant to a transaction batch
    /// and returns which program accounts the accounts DB needs to load.
    pub fn extract<S: WorkingSlot>(
        &self,
        working_slot: &S,
        keys: impl Iterator<Item = (Pubkey, LoadedProgramMatchCriteria)>,
    ) -> (HashMap<Pubkey, Arc<LoadedProgram>>, Vec<Pubkey>) {
        let mut missing = Vec::new();
        let found = keys
            .filter_map(|(key, match_criteria)| {
                if let Some(second_level) = self.entries.get(&key) {
                    for entry in second_level.iter().rev() {
                        let current_slot = working_slot.current_slot();
                        if current_slot == entry.deployment_slot
                            || working_slot.is_ancestor(entry.deployment_slot)
                        {
                            if entry
                                .maybe_expiration_slot
                                .map(|expiration_slot| current_slot >= expiration_slot)
                                .unwrap_or(false)
                            {
                                // Found an entry that's already expired. Any further entries in the list
                                // are older than the current one. So treat the program as missing in the
                                // cache and return early.
                                missing.push(key);
                                return None;
                            }

                            if !Self::matches_loaded_program(entry, &match_criteria) {
                                missing.push(key);
                                return None;
                            }

                            if current_slot >= entry.effective_slot {
                                return Some((key, entry.clone()));
                            }
                        }
                    }
                }
                missing.push(key);
                None
            })
            .collect();
        (found, missing)
    }

    /// Evicts programs which were used infrequently
    pub fn sort_and_evict(&mut self, shrink_to: PercentageInteger) {
        let mut num_loaded: usize = 0;
        let mut num_unloaded: usize = 0;
        // Find eviction candidates and sort by their type and usage counters.
        // Sorted result will have the following order:
        //   Loaded entries with ascending order of their usage count
        //   Unloaded entries with ascending order of their usage count
        let (ordering, sorted_candidates): (Vec<u32>, Vec<(Pubkey, Arc<LoadedProgram>)>) = self
            .entries
            .iter()
            .flat_map(|(id, list)| {
                list.iter()
                    .filter_map(move |program| match program.program {
                        LoadedProgramType::LegacyV0(_)
                        | LoadedProgramType::LegacyV1(_)
                        | LoadedProgramType::Typed(_) => Some((0, (*id, program.clone()))),
                        #[cfg(escaped)]
                        LoadedProgramType::TestLoaded => Some((0, (*id, program.clone()))),
                        LoadedProgramType::Unloaded => Some((1, (*id, program.clone()))),
                        LoadedProgramType::FailedVerification
                        | LoadedProgramType::Closed
                        | LoadedProgramType::DelayVisibility
                        | LoadedProgramType::BuiltIn(_) => None,
                    })
            })
            .sorted_by_cached_key(|(order, (_id, program))| {
                (*order, program.usage_counter.load(Ordering::Relaxed))
            })
            .unzip();

        for order in ordering {
            match order {
                0 => num_loaded = num_loaded.saturating_add(1),
                1 => num_unloaded = num_unloaded.saturating_add(1),
                _ => unreachable!(),
            }
        }

        let num_to_unload = num_loaded.saturating_sub(shrink_to.apply_to(MAX_LOADED_ENTRY_COUNT));
        self.unload_program_entries(sorted_candidates.iter().take(num_to_unload));

        let num_unloaded_to_evict = num_unloaded
            .saturating_add(num_to_unload)
            .saturating_sub(shrink_to.apply_to(MAX_UNLOADED_ENTRY_COUNT));
        let (newly_unloaded_programs, sorted_candidates) = sorted_candidates.split_at(num_loaded);
        let num_old_unloaded_to_evict = cmp::min(sorted_candidates.len(), num_unloaded_to_evict);
        self.remove_program_entries(sorted_candidates.iter().take(num_old_unloaded_to_evict));

        let num_newly_unloaded_to_evict =
            num_unloaded_to_evict.saturating_sub(sorted_candidates.len());
        self.remove_program_entries(
            newly_unloaded_programs
                .iter()
                .take(num_newly_unloaded_to_evict),
        );

        self.remove_programs_with_no_entries();
    }

    /// Removes all the entries at the given keys, if they exist
    pub fn remove_programs(&mut self, keys: impl Iterator<Item = Pubkey>) {
        for k in keys {
            self.entries.remove(&k);
        }
    }

    fn remove_program_entries<'a>(
        &mut self,
        remove: impl Iterator<Item = &'a (Pubkey, Arc<LoadedProgram>)>,
    ) {
        for (id, program) in remove {
            if let Some(entries) = self.entries.get_mut(id) {
                let index = entries.iter().position(|entry| entry == program);
                if let Some(index) = index {
                    entries.swap_remove(index);
                }
            }
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

    fn unload_program_entries<'a>(
        &mut self,
        remove: impl Iterator<Item = &'a (Pubkey, Arc<LoadedProgram>)>,
    ) {
        for (id, program) in remove {
            if let Some(entries) = self.entries.get_mut(id) {
                if let Some(candidate) = entries.iter_mut().find(|entry| entry == &program) {
                    *candidate = Arc::new(candidate.to_unloaded());
                }
            }
        }
    }

    fn remove_programs_with_no_entries(&mut self) {
        self.entries.retain(|_, programs| !programs.is_empty())
    }
}
