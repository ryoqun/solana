/// There are 10^6 micro-lamports in one lamport
const MICRO_LAMPORTS_PER_LAMPORT: u64 = 1_000_000;

type MicroLamports = u128;

pub enum PrioritizationFeeType {
    ComputeUnitPrice(u64),
    // TODO: remove 'Deprecated' after feature remove_deprecated_request_unit_ix::id() is activated
    Deprecated(u64),
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct PrioritizationFeeDetails {
    fee: u64,
    priority: u64,
}

impl PrioritizationFeeDetails {
    pub fn new(fee_type: PrioritizationFeeType, compute_unit_limit: u64) -> Self {
        match fee_type {
            // TODO: remove support of 'Deprecated' after feature remove_deprecated_request_unit_ix::id() is activated
            PrioritizationFeeType::Deprecated(fee) => {
                let priority = if compute_unit_limit == 0 {
                    0
                } else {
                    let micro_lamport_fee: MicroLamports =
                        (fee as u128).saturating_mul(MICRO_LAMPORTS_PER_LAMPORT as u128);
                    let priority = micro_lamport_fee.saturating_div(compute_unit_limit as u128);
                    u64::try_from(priority).unwrap_or(u64::MAX)
                };

                Self { fee, priority }
            }
            PrioritizationFeeType::ComputeUnitPrice(cu_price) => {
                let fee = {
                    let micro_lamport_fee: MicroLamports =
                        (cu_price as u128).saturating_mul(compute_unit_limit as u128);
                    let fee = micro_lamport_fee
                        .saturating_add(MICRO_LAMPORTS_PER_LAMPORT.saturating_sub(1) as u128)
                        .saturating_div(MICRO_LAMPORTS_PER_LAMPORT as u128);
                    u64::try_from(fee).unwrap_or(u64::MAX)
                };

                Self {
                    fee,
                    priority: cu_price,
                }
            }
        }
    }

    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    pub fn get_priority(&self) -> u64 {
        self.priority
    }
}
