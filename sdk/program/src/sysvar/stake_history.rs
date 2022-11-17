//! named accounts for synthesized data accounts for bank state, etc.
//!
//! this account carries history about stake activations and de-activations
//!
pub use crate::stake_history::StakeHistory;
use crate::sysvar::Sysvar;

crate::declare_sysvar_id!("SysvarStakeHistory1111111111111111111111111", StakeHistory);

impl Sysvar for StakeHistory {
    // override
    fn size_of() -> usize {
        // hard-coded so that we don't have to construct an empty
        16392 // golden, update if MAX_ENTRIES changes
    }
}
