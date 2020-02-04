extern crate proc_macro;

use proc_macro::TokenStream;

// Define dummy macro_attribute and macro_derive for non-default sdk cfgs

#[proc_macro_attribute]
pub fn frozen_abi(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_derive(AbiDigestSample)]
pub fn derive_abi_digest_sample(_item: TokenStream) -> TokenStream {
    "".parse().unwrap()
}
