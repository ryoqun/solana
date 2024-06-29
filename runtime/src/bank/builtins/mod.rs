pub(crate) mod core_bpf_migration;
pub mod prototypes;

pub use prototypes::{BuiltinPrototype, StatelessBuiltinPrototype};
use {
    core_bpf_migration::CoreBpfMigrationConfig,
    solana_sdk::{bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, feature_set},
};

macro_rules! testable_prototype {
    ($prototype:ident {
        core_bpf_migration_config: $core_bpf_migration_config:expr,
        name: $name:ident,
        $($field:ident : $value:expr),* $(,)?
    }) => {
        $prototype {
            core_bpf_migration_config: {
                {
                    $core_bpf_migration_config
                }
                #[cfg(escaped)]
                {
                    Some( test_only::$name::CONFIG )
                }
            },
            name: stringify!($name),
            $($field: $value),*
        }
    };
}

pub static BUILTINS: &[BuiltinPrototype] = &[
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: system_program,
        enable_feature_id: None,
        program_id: solana_system_program::id(),
        entrypoint: solana_system_program::system_processor::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: vote_program,
        enable_feature_id: None,
        program_id: solana_vote_program::id(),
        entrypoint: solana_vote_program::vote_processor::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: stake_program,
        enable_feature_id: None,
        program_id: solana_stake_program::id(),
        entrypoint: solana_stake_program::stake_instruction::Entrypoint::vm,
    }),
    BuiltinPrototype {
        core_bpf_migration_config: Some(CoreBpfMigrationConfig {
            source_buffer_address: buffer_accounts::config_program::id(),
            upgrade_authority_address: None,
            feature_id: solana_sdk::feature_set::migrate_config_program_to_core_bpf::id(),
            migration_target: core_bpf_migration::CoreBpfMigrationTargetType::Builtin,
            datapoint_name: "migrate_builtin_to_core_bpf_config_program",
        }),
        name: "config_program",
        enable_feature_id: None,
        program_id: solana_config_program::id(),
        entrypoint: solana_config_program::config_processor::Entrypoint::vm,
    },
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: solana_bpf_loader_deprecated_program,
        enable_feature_id: None,
        program_id: bpf_loader_deprecated::id(),
        entrypoint: solana_bpf_loader_program::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: solana_bpf_loader_program,
        enable_feature_id: None,
        program_id: bpf_loader::id(),
        entrypoint: solana_bpf_loader_program::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: solana_bpf_loader_upgradeable_program,
        enable_feature_id: None,
        program_id: bpf_loader_upgradeable::id(),
        entrypoint: solana_bpf_loader_program::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: compute_budget_program,
        enable_feature_id: None,
        program_id: solana_sdk::compute_budget::id(),
        entrypoint: solana_compute_budget_program::Entrypoint::vm,
    }),
    BuiltinPrototype {
        core_bpf_migration_config: Some(CoreBpfMigrationConfig {
            source_buffer_address: buffer_accounts::address_lookup_table_program::id(),
            upgrade_authority_address: None,
            feature_id:
                solana_sdk::feature_set::migrate_address_lookup_table_program_to_core_bpf::id(),
            migration_target: core_bpf_migration::CoreBpfMigrationTargetType::Builtin,
            datapoint_name: "migrate_builtin_to_core_bpf_address_lookup_table_program",
        }),
        name: "address_lookup_table_program",
        enable_feature_id: None,
        program_id: solana_sdk::address_lookup_table::program::id(),
        entrypoint: solana_address_lookup_table_program::processor::Entrypoint::vm,
    },
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: zk_token_proof_program,
        enable_feature_id: Some(feature_set::zk_token_sdk_enabled::id()),
        program_id: solana_zk_token_sdk::zk_token_proof_program::id(),
        entrypoint: solana_zk_token_proof_program::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: loader_v4,
        enable_feature_id: Some(feature_set::enable_program_runtime_v2_and_loader_v4::id()),
        program_id: solana_sdk::loader_v4::id(),
        entrypoint: solana_loader_v4_program::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: zk_elgamal_proof_program,
        enable_feature_id: Some(feature_set::zk_elgamal_proof_program_enabled::id()),
        program_id: solana_zk_sdk::zk_elgamal_proof_program::id(),
        entrypoint: solana_zk_elgamal_proof_program::Entrypoint::vm,
    }),
];

pub static STATELESS_BUILTINS: &[StatelessBuiltinPrototype] = &[StatelessBuiltinPrototype {
    core_bpf_migration_config: Some(CoreBpfMigrationConfig {
        source_buffer_address: buffer_accounts::feature_gate_program::id(),
        upgrade_authority_address: None,
        feature_id: solana_sdk::feature_set::migrate_feature_gate_program_to_core_bpf::id(),
        migration_target: core_bpf_migration::CoreBpfMigrationTargetType::Stateless,
        datapoint_name: "migrate_stateless_to_core_bpf_feature_gate_program",
    }),
    name: "feature_gate_program",
    program_id: solana_sdk::feature::id(),
}];

/// Live source buffer accounts for builtin migrations.
mod buffer_accounts {
    pub mod address_lookup_table_program {
        solana_sdk::declare_id!("AhXWrD9BBUYcKjtpA3zuiiZG4ysbo6C6wjHo1QhERk6A");
    }
    pub mod config_program {
        solana_sdk::declare_id!("BuafH9fBv62u6XjzrzS4ZjAE8963ejqF5rt1f8Uga4Q3");
    }
    pub mod feature_gate_program {
        solana_sdk::declare_id!("3D3ydPWvmEszrSjrickCtnyRSJm1rzbbSsZog8Ub6vLh");
    }
}

// This module contains a number of arbitrary addresses used for testing Core
// BPF migrations.
// Since the list of builtins is static, using `declare_id!` with constant
// values is arguably the least-overhead approach to injecting static addresses
// into the builtins list for both the feature ID and the source program ID.
// These arbitrary IDs can then be used to configure feature-activation runtime
// tests.
