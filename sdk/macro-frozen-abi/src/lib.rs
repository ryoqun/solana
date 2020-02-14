extern crate proc_macro;

// This file littered with these essential cfgs so ensure them.
#[cfg(not(any(RUSTC_WITH_SPECIALIZATION, RUSTC_WITHOUT_SPECIALIZATION)))]
compile_error!("rustc_version is missing in build dependency and build.rs is not specified");

#[cfg(any(RUSTC_WITH_SPECIALIZATION, RUSTC_WITHOUT_SPECIALIZATION))]
use proc_macro::TokenStream;

// Define dummy macro_attribute and macro_derive for stable rustc

#[cfg(RUSTC_WITHOUT_SPECIALIZATION)]
#[proc_macro_attribute]
pub fn frozen_abi(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[cfg(RUSTC_WITHOUT_SPECIALIZATION)]
#[proc_macro_derive(AbiDigestSample)]
pub fn derive_abi_digest_sample(_item: TokenStream) -> TokenStream {
    "".parse().unwrap()
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
use proc_macro2::{Span, TokenStream as TokenStream2, TokenTree::Group};
#[cfg(RUSTC_WITH_SPECIALIZATION)]
use quote::quote;
#[cfg(RUSTC_WITH_SPECIALIZATION)]
use syn::{
    parse_macro_input, Attribute, AttributeArgs, Fields, Ident, Item, ItemEnum, ItemStruct,
    ItemType, Lit, Meta, NestedMeta, Variant,
};

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn filter_serde_attrs(attrs: &[Attribute]) -> bool {
    let mut skip = false;

    for attr in attrs {
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
        }
    }

    skip
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn filter_allow_attrs(attrs: &mut Vec<Attribute>) {
    attrs.retain(|attr| {
        let ss = &attr.path.segments.first().unwrap().ident.to_string();
        ss.starts_with("allow")
    });
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn derive_abi_digest_sample_enum_type(input: ItemEnum) -> TokenStream {
    let type_name = &input.ident;

    let mut sample_variant = quote! {};
    let mut sample_variant_found = false;

    for variant in &input.variants {
        let variant_name = &variant.ident;
        let variant = &variant.fields;
        if *variant == Fields::Unit {
            sample_variant.extend(quote! {
                #type_name::#variant_name
            });
        } else if let Fields::Unnamed(variant_fields) = variant {
            let mut fields = quote! {};
            for field in &variant_fields.unnamed {
                if !(field.ident.is_none() && field.colon_token.is_none()) {
                    unimplemented!("tuple enum: {:?}", field);
                }
                let field_type = &field.ty;
                fields.extend(quote! {
                    <#field_type>::sample(),
                });
            }
            sample_variant.extend(quote! {
                #type_name::#variant_name(#fields)
            });
        } else if let Fields::Named(variant_fields) = variant {
            let mut fields = quote! {};
            for field in &variant_fields.named {
                if field.ident.is_none() || field.colon_token.is_none() {
                    unimplemented!("tuple enum: {:?}", field);
                }
                let field_type = &field.ty;
                let field_name = &field.ident;
                fields.extend(quote! {
                    #field_name: <#field_type>::sample(),
                });
            }
            sample_variant.extend(quote! {
                #type_name::#variant_name{#fields}
            });
        } else {
            unimplemented!("{:?}", variant);
        }

        if !sample_variant_found {
            sample_variant_found = true;
            break;
        }
    }

    if !sample_variant_found {
        unimplemented!("empty enum");
    }

    let mut attrs = input.attrs.clone();
    filter_allow_attrs(&mut attrs);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let result = quote! {
        #[automatically_derived]
        #( #attrs )*
        impl #impl_generics ::solana_sdk::abi_digester::AbiDigestSample for #type_name #ty_generics #where_clause {
            fn sample() -> #type_name {
                ::log::info!(
                    "AbiDigestSample for enum: {}",
                    std::any::type_name::<#type_name>()
                );
                #sample_variant
            }
        }
    };
    result.into()
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn derive_abi_digest_sample_struct_type(input: ItemStruct) -> TokenStream {
    let type_name = &input.ident;
    let mut sample_fields = quote! {};
    let fields = &input.fields;

    match fields {
        Fields::Named(_) => {
            for field in fields {
                let field_name = &field.ident;
                sample_fields.extend(quote! {
                    #field_name: AbiDigestSample::sample(),
                });
            }
            sample_fields = quote! {
                { #sample_fields }
            }
        }
        Fields::Unnamed(_) => {
            for _ in fields {
                sample_fields.extend(quote! {
                    AbiDigestSample::sample(),
                });
            }
            sample_fields = quote! {
                ( #sample_fields )
            }
        }
        _ => unimplemented!("fields: {:?}", fields),
    }

    let mut attrs = input.attrs.clone();
    filter_allow_attrs(&mut attrs);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let result = quote! {
        #[automatically_derived]
        #( #attrs )*
        impl #impl_generics ::solana_sdk::abi_digester::AbiDigestSample for #type_name #ty_generics #where_clause {
            fn sample() -> #type_name {
                ::log::info!(
                    "AbiDigestSample for struct: {}",
                    std::any::type_name::<#type_name>()
                );
                use ::solana_sdk::abi_digester::AbiDigestSample;
                #type_name #sample_fields
            }
        }
    };

    result.into()
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
#[proc_macro_derive(AbiDigestSample)]
pub fn derive_abi_digest_sample(item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as Item);

    match item {
        Item::Struct(input) => derive_abi_digest_sample_struct_type(input),
        Item::Enum(input) => derive_abi_digest_sample_enum_type(input),
        _ => panic!("not applicable to {:#?}", item),
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn quote_for_test(
    test_mod_ident: &Ident,
    type_name: &Ident,
    expected_digest: &str,
) -> TokenStream2 {
    quote! {
        #[cfg(test)]
        mod #test_mod_ident {
            use super::*;
            use ::solana_sdk::abi_digester::AbiDigest;

            #[test]
            fn test_digest() {
                ::solana_logger::setup();
                let mut digester = ::solana_sdk::abi_digester::AbiDigester::create();
                <#type_name>::abi_digest(&mut digester);
                let mut hash = digester.finalize();
                assert_eq!(#expected_digest, format!("{}", hash));
            }
        }
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn test_mod_name(type_name: &Ident) -> Ident {
    Ident::new(
        &format!("{}_frozen_abi", type_name.to_string()),
        Span::call_site(),
    )
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn frozen_abi_type_alias(input: ItemType, expected_digest: &str) -> TokenStream {
    let type_name = &input.ident;
    let test = quote_for_test(&test_mod_name(type_name), type_name, &expected_digest);
    let result = quote! {
        #input
        #test
    };
    result.into()
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn frozen_abi_struct_type(input: ItemStruct, expected_digest: &str) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let type_name = &input.ident;
    let test = quote_for_test(&test_mod_name(type_name), type_name, &expected_digest);
    let result = quote! {
        #input
        #[automatically_derived]
        impl #impl_generics ::solana_sdk::abi_digester::AbiDigest for #type_name #ty_generics #where_clause {
            fn abi_digest(digester: &mut ::solana_sdk::abi_digester::AbiDigester) {
                ::log::info!("AbiDigest for (struct): {}", std::any::type_name::<#type_name #ty_generics>());
                use ::solana_sdk::abi_digester::AbiDigestSample;
                use ::serde::ser::Serialize;
                let tested_value = <#type_name #ty_generics>::sample();
                tested_value.serialize(digester.forced_child_digester()).unwrap();
            }
        }
        #test
    };
    result.into()
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn quote_sample_variant(type_name: &Ident, variant: &Variant) -> TokenStream2 {
    let variant_name = &variant.ident;
    let variant = &variant.fields;
    if *variant == Fields::Unit {
        quote! {
            let sample_variant = #type_name::#variant_name;
        }
    } else if let Fields::Unnamed(variant_fields) = variant {
        let mut fields = quote! {};
        for field in &variant_fields.unnamed {
            if !(field.ident.is_none() && field.colon_token.is_none()) {
                unimplemented!();
            }
            let ty = &field.ty;
            fields.extend(quote! {
                <#ty>::sample(),
            });
        }
        quote! {
            let sample_variant = #type_name::#variant_name(#fields);
        }
    } else if let Fields::Named(variant_fields) = variant {
        let mut fields = quote! {};
        for field in &variant_fields.named {
            if field.ident.is_none() || field.colon_token.is_none() {
                unimplemented!();
            }
            let field_type_name = &field.ty;
            let field_name = &field.ident;
            fields.extend(quote! {
                #field_name: <#field_type_name>::sample(),
            });
        }
        quote! {
            let sample_variant = #type_name::#variant_name{#fields};
        }
    } else {
        unimplemented!("variant: {:?}", variant)
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
fn frozen_abi_enum_type(input: ItemEnum, expected_digest: &str) -> TokenStream {
    let type_name = &input.ident;
    let mut serialized_variants = quote! {};
    for variant in &input.variants {
        // Don't digest a variant with serde(skip)
        if filter_serde_attrs(&variant.attrs) {
            continue;
        };
        let sample_variant = quote_sample_variant(&type_name, &variant);
        serialized_variants.extend(quote! {
            #sample_variant;
            sample_variant.serialize(digester.forced_child_digester()).unwrap();
        });
    }

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let test = quote_for_test(&test_mod_name(type_name), type_name, &expected_digest);
    let result = quote! {
        #input
        #[automatically_derived]
        impl #impl_generics ::solana_sdk::abi_digester::AbiDigest for #type_name #ty_generics #where_clause {
            fn abi_digest(digester: &mut ::solana_sdk::abi_digester::AbiDigester) {
                use ::serde::ser::Serialize;
                use ::solana_sdk::abi_digester::AbiDigestSample;
                ::log::info!("AbiDigest for (enum): {}", std::any::type_name::<#type_name>());
                #serialized_variants
            }
        }
        #test
    };
    result.into()
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
#[proc_macro_attribute]
pub fn frozen_abi(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as AttributeArgs);
    let mut expected_digest: Option<String> = None;
    for arg in args {
        match arg {
            NestedMeta::Meta(Meta::NameValue(nv)) if nv.path.is_ident("digest") => {
                if let Lit::Str(lit) = nv.lit {
                    expected_digest = Some(lit.value());
                }
            }
            _ => {}
        }
    }
    let expected_digest = expected_digest.expect("the required \"digest\" = ... is missing.");

    let item = parse_macro_input!(item as Item);
    match item {
        Item::Type(input) => frozen_abi_type_alias(input, &expected_digest),
        Item::Struct(input) => frozen_abi_struct_type(input, &expected_digest),
        Item::Enum(input) => frozen_abi_enum_type(input, &expected_digest),
        _ => panic!("not applicable to {:#?}", item),
    }
}
