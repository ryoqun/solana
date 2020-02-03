extern crate proc_macro;

use proc_macro::TokenStream;
#[cfg(RUSTC_IS_NIGHTLY)]
use proc_macro2::{Span, TokenTree::Group};
#[cfg(RUSTC_IS_NIGHTLY)]
use quote::quote;
#[cfg(RUSTC_IS_NIGHTLY)]
use syn::{
    parse_macro_input, punctuated::Punctuated, token::Comma, Attribute, AttributeArgs, Ident,
    NestedMeta, Variant, Visibility,
};

#[cfg(RUSTC_IS_NIGHTLY)]
fn filter_serde_attrs(attrs: &mut Vec<Attribute>) -> bool {
    let mut skip = false;

    attrs.retain(|attr| {
        let ss = &attr.path.segments.first().unwrap().ident.to_string();
        if ss.starts_with("serde") {
            for token in attr.tokens.clone() {
                if let Group(token) = token {
                    for ident in token.stream() {
                        if ident.to_string() == "skip" {
                            skip = true;
                        }
                    }
                }
            }
            return true;
        }
        false
    });

    skip
}

#[cfg(RUSTC_IS_STABLE)]
#[proc_macro_attribute]
pub fn frozen_abi(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[cfg(RUSTC_IS_NIGHTLY)]
#[proc_macro_attribute]
pub fn frozen_abi(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as AttributeArgs);
    let mut expected_digest: Option<String> = None;
    for arg in args {
        match arg {
            NestedMeta::Meta(syn::Meta::NameValue(nv)) if nv.path.is_ident("digest") => {
                if let syn::Lit::Str(lit) = nv.lit {
                    expected_digest = Some(lit.value());
                }
            }
            _ => {}
        }
    }
    let expected_digest = expected_digest.expect("the required \"digest\" = ... is missing.");

    let item = syn::parse_macro_input!(item as syn::Item);
    if let syn::Item::Struct(input) = item {
        let name = &input.ident;

        let mod_name = Ident::new(
            &format!("frozen_abi_tests_{}", name.to_string()),
            Span::call_site(),
        );
        /*let struct_name = Ident::new(
            &format!("{}ForAbiDigest", name.to_string()),
            Span::call_site(),
        );*/

        let mut header = input.clone();
        filter_serde_attrs(&mut header.attrs);
        header.fields = syn::Fields::Unit;
        header.vis = Visibility::Inherited;
        let mut body = quote! {
            digester.update(&["attrs", stringify!(#header)]);
        };
        let fields = &input.fields;
        let mut struct_body = quote! {};
        let mut struct_body2 = quote! {};
        let mut struct_body3 = quote! {};
        for mut field in fields.clone() {
            let field_ident = &field.ident;
            let field_type = &field.ty;
            match fields {
                syn::Fields::Named(_) => {
                    struct_body2 = quote! {
                        #struct_body2
                        #field_ident: AbiDigestSample::sample(),
                    };
                }
                syn::Fields::Unnamed(_) => {
                    struct_body2 = quote! {
                        #struct_body2
                        AbiDigestSample::sample(),
                    };
                }
                _ => panic!("bad"),
            }
            if filter_serde_attrs(&mut field.attrs) {
                continue;
            }
            field.vis = Visibility::Inherited;

            body = quote! {
                #body;
                digester.update(&["field", stringify!(#field)]);
            };
            struct_body = quote! {
                #struct_body
                #field,
            };
            struct_body3 = quote! {
                #struct_body3
                //let #field_ident: #field_type = ::solana_sdk::abi_digester::AbiDigest::abi_digest();
                //#field_ident: ::solana_sdk::abi_digester::AbiDigest::abi_digest(),
                //::solana_sdk::abi_digester::AbiDigest::abi_digest::<#field_type>();
                digester.update_with_type2::<#field_type>(concat!("field ", stringify!(#field_ident)));
                <#field_type>::abi_digest(&mut digester.child_digester());
            };
        }
        match fields {
            syn::Fields::Named(_) => {
                struct_body2 = quote! {
                    { #struct_body2 }
                }
            }
            syn::Fields::Unnamed(_) => {
                struct_body2 = quote! {
                    ( #struct_body2 )
                }
            }
            _ => panic!("bad"),
        }

        let result = quote! {
            #input
            #[automatically_derived]
            impl ::solana_sdk::abi_digester::AbiDigestSample for #name {
                fn sample() -> #name {
                    ::log::info!(
                        "AbiDigestSample for struct: {}",
                        std::any::type_name::<#name>()
                    );
                    use ::solana_sdk::abi_digester::AbiDigestSample;
                    #name #struct_body2
                }
            }
            #[automatically_derived]
            impl ::solana_sdk::abi_digester::AbiDigest for #name {
                fn abi_digest(digester: &mut ::solana_sdk::abi_digester::AbiDigester) {
                    ::log::info!("AbiDigest for (struct): {}", std::any::type_name::<#name>());
                    #struct_body3
                    //return #name {
                    //    #struct_body3
                    //};
                }
            }
            #[cfg(test)]
            mod #mod_name {
                use super::*;
                use serde::ser::Serialize;

                #[test]
                fn test_frozen_abi() {
                    ::solana_logger::setup();
                    let mut digester = ::solana_sdk::abi_digester::AbiDigester::create();
                    /*
                    #[derive(Default, Serialize)]
                    struct #struct_name {
                      #struct_body
                    };
                    impl AbiDigestSample for #struct_name {
                        fn sample() -> #struct_name {
                            return #struct_name {
                                #struct_body2
                            };
                        }
                    };*/
                    use ::solana_sdk::abi_digester::AbiDigest;
                    <#name>::abi_digest(&mut digester);
                    /*
                    let value = #name::sample();
                    digester = value.serialize(digester).unwrap();
                    #body
                    */
                    let mut hash = digester.finalize();
                    assert_eq!(#expected_digest, format!("{}", hash));
                }
            }
        };
        result.into()
    } else if let syn::Item::Enum(input) = item {
        let name = &input.ident;
        let mod_name = Ident::new(
            &format!("frozen_abi_tests_{}", name.to_string()),
            Span::call_site(),
        );
        let mut header = input.clone();
        filter_serde_attrs(&mut header.attrs);
        header.variants = Punctuated::<Variant, Comma>::default();
        header.vis = Visibility::Inherited;
        let mut body = quote! {
            digester.update(&["attrs", stringify!(#header)]);
        };
        let mut struct_body3 = quote! {};
        let mut enum_body2 = quote! {};
        let mut enum_body2_found = false;
        for mut variant in input.variants.clone() {
            if filter_serde_attrs(&mut variant.attrs) {
                continue;
            };
            body = quote! {
                #body;
                digester.update(&["variant", stringify!(#variant)]);
            };
            let vi = &variant.ident;
            let vt = &variant.fields;
            if *vt == syn::Fields::Unit {
                struct_body3 = quote! {
                    #struct_body3;
                    let v = #name::#vi;
                }
            } else if let syn::Fields::Unnamed(vt) = vt {
                //::_logger::info!("{:#?}", vt);
                let mut uc = quote! {};
                for u in &vt.unnamed {
                    if !(u.ident.is_none() && u.colon_token.is_none()) {
                        unimplemented!();
                    }
                    let ty = &u.ty;
                    uc = quote! {
                        #uc
                        <#ty>::sample(),
                    };
                }
                struct_body3 = quote! {
                    #struct_body3;
                    let v = #name::#vi(#uc);
                }
            } else if let syn::Fields::Named(vt) = vt {
                let mut uc = quote! {};
                for u in &vt.named {
                    if u.ident.is_none() || u.colon_token.is_none() {
                        unimplemented!();
                    }
                    let ty = &u.ty;
                    let ident = &u.ident;
                    uc = quote! {
                        #uc
                        #ident: <#ty>::sample(),
                    };
                }
                struct_body3 = quote! {
                    #struct_body3;
                    let v = #name::#vi{#uc};
                }
            } else {
                unimplemented!("{:?}", vt);
            }
            if !enum_body2_found {
                enum_body2_found = true;
                enum_body2 = quote! {
                    #struct_body3;
                }
            }
            struct_body3 = quote! {
                #struct_body3;
                v.serialize(digester.forced_child_digester()).unwrap();
            }
        }

        let result = quote! {
            #input
            #[automatically_derived]
            impl ::solana_sdk::abi_digester::AbiDigestSample for #name {
                fn sample() -> #name {
                    ::log::info!(
                        "AbiDigestSample for enum: {}",
                        std::any::type_name::<#name>()
                    );
                    #enum_body2;
                    v
                }
            }
            #[automatically_derived]
            impl ::solana_sdk::abi_digester::AbiDigest for #name {
                fn abi_digest(digester: &mut ::solana_sdk::abi_digester::AbiDigester) {
                    use serde::ser::Serialize;
                    use ::solana_sdk::abi_digester::AbiDigestSample;
                    ::log::info!("AbiDigest for (enum): {}", std::any::type_name::<#name>());
                    #struct_body3
                    //return #name {
                    //    #struct_body3
                    //};
                }
            }
            #[cfg(test)]
            mod #mod_name {
                use super::*;
                use serde::ser::Serialize;
                #[test]
                fn test_frozen_abi() {
                    ::solana_logger::setup();
                    let mut digester = ::solana_sdk::abi_digester::AbiDigester::create();
                    //#body
                    use ::solana_sdk::abi_digester::AbiDigest;
                    <#name>::abi_digest(&mut digester);
                    let hash = digester.finalize();
                    assert_eq!(#expected_digest, format!("{}", hash));
                }
            }
        };
        result.into()
    } else {
        panic!("not applicable to ????");
    }
}
