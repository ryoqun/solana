use solana_sdk::pubkey::Pubkey;

#[derive(Debug)]
pub struct PubkeyBinCalculator24 {
    // how many bits from the first 2 bytes to shift away to ignore when calculating bin
    shift_bits: u32,
}

impl PubkeyBinCalculator24 {
    const fn num_bits<T>() -> usize {
        std::mem::size_of::<T>() * 8
    }

    pub(crate) fn log_2(x: u32) -> u32 {
        assert!(x > 0);
        Self::num_bits::<u32>() as u32 - x.leading_zeros() - 1
    }

    pub(crate) fn new(bins: usize) -> Self {
        const MAX_BITS: u32 = 24;
        assert!(bins > 0);
        let max_plus_1 = 1 << MAX_BITS;
        assert!(bins <= max_plus_1);
        assert!(bins.is_power_of_two());
        let bits = Self::log_2(bins as u32);
        Self {
            shift_bits: MAX_BITS - bits,
        }
    }

    pub(crate) fn bin_from_pubkey(&self, pubkey: &Pubkey) -> usize {
        let as_ref = pubkey.as_ref();
        ((as_ref[0] as usize * 256 + as_ref[1] as usize) * 256 + as_ref[2] as usize)
            >> self.shift_bits
    }
}
