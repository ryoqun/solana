extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn frozen_abi(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    item
}
