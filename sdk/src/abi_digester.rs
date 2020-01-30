use crate::hash::{Hash, Hasher};

use serde::ser::Error as SerdeError;
use serde::Serialize;

use std::io::Write;

pub trait DefaultForAbiDigest: Sized {
    fn default_for_abi_digest() -> Self;
}

impl<T: Default> DefaultForAbiDigest for T {
    fn default_for_abi_digest() -> Self {
        T::default()
    }
}

pub trait AbiDigestSample: Sized {
    fn sample() -> Self;
}

macro_rules! tuple_impls {
    ($(
        $Tuple:ident {
            $(($idx:tt) -> $T:ident)+
        }
    )+) => {
        $(
            impl<$($T:AbiDigestSample),+> AbiDigestSample for ($($T,)+) {
                fn sample() -> ($($T,)+) {
                        ($({ let x: $T = AbiDigestSample::sample(); x},)+)
                }
            }
        )+
    }
}

tuple_impls! {
    Tuple1 {
        (0) -> A
    }
    Tuple2 {
        (0) -> A
        (1) -> B
    }
    Tuple3 {
        (0) -> A
        (1) -> B
        (2) -> C
    }
    Tuple4 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
    }
    Tuple5 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
    }
    Tuple6 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
    }
    Tuple7 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
    }
    Tuple8 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
    }
    Tuple9 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
    }
    Tuple10 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
    }
    Tuple11 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
        (10) -> K
    }
    Tuple12 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
        (10) -> K
        (11) -> L
    }
}

macro_rules! array_impl_default {
    {$n:expr, $t:ident $($ts:ident)*} => {
        impl<T> AbiDigestSample for [T; $n] where T: AbiDigestSample {
            fn sample() -> [T; $n] {
                [$t::sample(), $($ts::sample()),*]
            }
        }
        array_impl_default!{($n - 1), $($ts)*}
    };
    {$n:expr,} => {
        impl<T> AbiDigestSample for [T; $n] {
        fn sample() -> [T; $n] { [] }
        }
    };
}

array_impl_default! {32, T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T}

macro_rules! default_impl {
    ($t:ty, $v:expr) => {
        impl AbiDigestSample for $t {
            fn sample() -> $t {
                $v
            }
        }
    };
}

default_impl! { (), () }
default_impl! { bool, false }
default_impl! { char, '\x00' }

default_impl! { usize, 0 }
default_impl! { u8, 0 }
default_impl! { u16, 0 }
default_impl! { u32, 0 }
default_impl! { u64, 0 }
default_impl! { u128, 0 }

default_impl! { isize, 0 }
default_impl! { i8, 0 }
default_impl! { i16, 0 }
default_impl! { i32, 0 }
default_impl! { i64, 0 }
default_impl! { i128, 0 }

default_impl! { f32, 0.0f32 }
default_impl! { f64, 0.0f64 }

use std::sync::atomic::*;

macro_rules! atomic_int {
    ($atomic_type: ident) => {
        impl AbiDigestSample for $atomic_type {
            fn sample() -> Self {
                Self::new(Default::default())
            }
        }
    };
}
atomic_int! { AtomicU32 }
atomic_int! { AtomicU64 }

// this works like a type erasure and a hatch to escape type error to runtime error
impl<T: Sized> AbiDigestSample for T {
    default fn sample() -> T {
        let v: T = <()>::aaaa();
        v
    }
}

trait DDD<T> {
    fn aaaa() -> T;
}

impl<T: Sized> DDD<T> for () {
    default fn aaaa() -> T {
        panic!(
            "implement AbiDigestSample for {}",
            std::any::type_name::<T>()
        );
    }
}

impl<T: Default> DDD<T> for () {
    default fn aaaa() -> T {
        T::default()
    }
}

/*
impl<T: Serialize + Sized, U: Serialize + Sized, V: Serialize + Sized> AbiDigestSample for (T, U, V) {
    default fn sample() -> (T, U, V) {
        eprintln!(
            "AbiDigestSample for (T, U, V): ({}, {}, {})",
            std::any::type_name::<T>(),
            std::any::type_name::<U>(),
            std::any::type_name::<V>(),
        );
        (T::sample(), U::sample(), V::sample())
    }
}
*/

impl<T: AbiDigestSample> AbiDigestSample for Option<T> {
    fn sample() -> Option<T> {
        eprintln!(
            "AbiDigestSample for (Option<T>): {}",
            std::any::type_name::<Option<T>>()
        );
        Some(T::sample())
    }
}

pub trait AbiDigest: Serialize {
    fn abi_digest(digester: &mut AbiDigester);
}

impl<T: Serialize + ?Sized> AbiDigest for T {
    default fn abi_digest(_digester: &mut AbiDigester) {
        unreachable!(
            "AbiDigest must be implemented for {}",
            std::any::type_name::<T>()
        );
    }
}

impl<T: Serialize + ?Sized + AbiDigestSample> AbiDigest for T {
    default fn abi_digest(digester: &mut AbiDigester) {
        eprintln!("AbiDigest for (default): {}", std::any::type_name::<T>());
        let v = T::sample();
        v.serialize(digester.child_digester()).unwrap();
    }
}

impl<T: Serialize + ?Sized + AbiDigestSample, U: Serialize + ?Sized + AbiDigestSample> AbiDigest
    for (T, U)
{
    default fn abi_digest(digester: &mut AbiDigester) {
        eprintln!(
            "AbiDigest for (default): {}",
            std::any::type_name::<(T, U)>()
        );
        let v = (T::sample(), U::sample());
        v.serialize(digester.child_digester()).unwrap();
    }
}

impl<T: AbiDigest> AbiDigest for Option<T> {
    fn abi_digest(digester: &mut AbiDigester) {
        eprintln!(
            "AbiDigest for (Option<T>): {}",
            std::any::type_name::<Option<T>>()
        );
        <T>::abi_digest(&mut digester.child_digester());
    }
}

#[derive(Debug)]
pub struct AbiDigester {
    data_types: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    forced: bool,
    depth: usize,
}

type DigestResult = Result<AbiDigester, DigestError>;
type NoResult = Result<(), DigestError>;
type Sstr = &'static str;

const INDENT_WIDTH: usize = 4;

impl AbiDigester {
    pub fn create() -> Self {
        AbiDigester {
            data_types: std::rc::Rc::new(std::cell::RefCell::new(vec![])),
            forced: false,
            depth: 0,
        }
    }

    pub fn child_digester(&self) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth + 1,
            forced: false,
        }
    }

    pub fn forced_child_digester(&self) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth + 1,
            forced: true,
        }
    }

    pub fn update(&mut self, strs: &[&str]) {
        let mut start = true;
        let mut buf = String::new();

        for str in strs {
            buf = format!("{}{}{}", buf, (if start { "" } else { " " }), str);
            start = false;
        }
        buf = format!("{:0width$}{}\n", "", buf, width = self.depth * INDENT_WIDTH);
        (*self.data_types.borrow_mut()).push(buf);
    }

    fn update_with_type<T>(&mut self, label: &str, _v: T) {
        self.update(&[label, std::any::type_name::<T>()]);
    }

    pub fn update_with_type2<T>(&mut self, label: &str) {
        self.update(&[label, std::any::type_name::<T>()]);
    }

    fn update_with_pritimive<T>(mut self, v: T) -> Result<AbiDigester, DigestError> {
        self.update_with_type("primitive", v);
        Ok(self)
    }

    pub fn finalize(self) -> Hash {
        let mut file = if let Ok(dir) = std::env::var("SOLANA_ABI_DUMP_DIR") {
            let path = format!(
                "{}/{}",
                dir,
                std::thread::current()
                    .name()
                    .unwrap_or("unknown-test-thread")
            );
            let file = std::fs::File::create(path).unwrap();
            Some(file)
        } else {
            None
        };

        let mut hasher = Hasher::default();

        for buf in (*self.data_types.borrow_mut()).iter() {
            if let Some(file) = &mut file {
                file.write_all(buf.as_bytes()).unwrap();
                file.sync_data().unwrap();
            }
            hasher.hash(buf.as_bytes());
        }

        hasher.result()
    }
}

#[derive(Debug, Default)]
pub struct DigestError();

impl SerdeError for DigestError {
    fn custom<T: std::fmt::Display>(_msg: T) -> DigestError {
        unimplemented!();
    }
}
impl std::error::Error for DigestError {}
impl std::fmt::Display for DigestError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!();
    }
}

impl serde::ser::Serializer for AbiDigester {
    type Ok = Self;
    type Error = DigestError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_i8(self, v: i8) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_i16(self, v: i16) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_i32(self, v: i32) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_i64(self, v: i64) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_i128(self, v: i128) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_u8(self, v: u8) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_u16(self, v: u16) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_u32(self, v: u32) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_u64(self, v: u64) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_u128(self, v: u128) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_f32(self, v: f32) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_f64(self, v: f64) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_char(self, v: char) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_str(self, v: &str) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_bytes(self, v: &[u8]) -> DigestResult {
        self.update_with_pritimive(v)
    }

    fn serialize_none(mut self) -> DigestResult {
        self.update(&[
            "none: SHOULD NOT HAPPEN DERIVE AbiDigestSample FOR THE FOLLOWING TYPE!",
            &self.forced.to_string(),
        ]);
        panic!("odd?");
    }

    fn serialize_some<T>(mut self, v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.update_with_type("some", v);
        //v.serialize(self.child_digester()).unwrap();
        <T>::abi_digest(&mut self);
        Ok(self)
    }

    fn serialize_unit(self) -> DigestResult {
        unimplemented!();
    }

    fn serialize_unit_struct(self, _name: Sstr) -> DigestResult {
        unimplemented!();
    }

    fn serialize_unit_variant(mut self, name: Sstr, _index: u32, variant: Sstr) -> DigestResult {
        if !self.forced {
            panic!(
                "unit_variant: SHOULD NOT HAPPEN DERIVE AbiDigestSample FOR THE ABOVE TYPE! {} {}",
                name, variant
            );
        }
        self.update(&["variant", name, "unit", variant]);
        Ok(self)
    }

    fn serialize_newtype_struct<T>(mut self, name: Sstr, _v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.update(&["newtype", name, "struct", std::any::type_name::<T>()]);
        Ok(self)
    }

    fn serialize_newtype_variant<T>(
        mut self,
        name: Sstr,
        _i: u32,
        variant: Sstr,
        _val: &T,
    ) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        if !self.forced {
            panic!(
                "newtype_variant: SHOULD NOT HAPPEN DERIVE AbiDigestSample FOR THE ABOVE TYPE! {} {}",
                name, variant
            );
        }
        self.update(&[
            "variant",
            name,
            "newtype",
            variant,
            std::any::type_name::<T>(),
        ]);
        <T>::abi_digest(&mut self);

        Ok(self)
    }

    fn serialize_seq(mut self, len: Option<usize>) -> DigestResult {
        self.update(&[
            "seq",
            &len.map(|len| len.to_string())
                .unwrap_or_else(|| "none".to_owned()),
        ]);
        Ok(self)
    }

    fn serialize_tuple(mut self, len: usize) -> DigestResult {
        self.update(&["tuple", len.to_string().as_ref()]);
        Ok(self)
    }

    fn serialize_tuple_struct(self, _name: Sstr, _len: usize) -> DigestResult {
        unimplemented!();
    }

    fn serialize_tuple_variant(
        mut self,
        name: Sstr,
        _i: u32,
        variant: Sstr,
        _len: usize,
    ) -> DigestResult {
        if !self.forced {
            panic!("bad");
        }
        self.update(&["variant", name, "newtype_tuple", variant]);
        Ok(self.child_digester())
    }

    fn serialize_map(mut self, _len: Option<usize>) -> DigestResult {
        self.update(&["map"]);
        Ok(self)
    }

    fn serialize_struct(self, name: Sstr, len: usize) -> DigestResult {
        //self.hash(999);
        eprintln!("serialize_struct {} {}", name, len);
        Ok(self)
    }

    fn serialize_struct_variant(
        mut self,
        name: Sstr,
        _i: u32,
        variant: Sstr,
        _len: usize,
    ) -> DigestResult {
        self.update(&[&format!("variant {} struct {}", name, variant)]);
        Ok(self.child_digester())
    }
}

impl serde::ser::SerializeSeq for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, _v: &T) -> NoResult {
        Ok(())
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}
impl serde::ser::SerializeTuple for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.update_with_type("element", v);
        //eprintln!("aaaaa: {:?}", (&v).abi_digest());
        <T>::abi_digest(&mut self.child_digester());
        Ok(())
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}
impl serde::ser::SerializeTupleStruct for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, _v: &T) -> NoResult {
        unimplemented!();
    }

    fn end(self) -> DigestResult {
        unimplemented!();
    }
}

impl serde::ser::SerializeTupleVariant for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.update_with_type("tuple", v);
        eprintln!("enum: variant: tuple");
        eprintln!("typename: {}", std::any::type_name::<T>());
        //eprintln!("AAAAA: {:?}", T::sample());
        v.serialize(self.child_digester()).unwrap();
        Ok(())
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl serde::ser::SerializeMap for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, _key: &T) -> NoResult {
        panic!("should not happen when digesting for abi");
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, _value: &T) -> NoResult {
        panic!("should not happen when digesting for abi");
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl serde::ser::SerializeStruct for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: Sstr, v: &T) -> NoResult {
        self.update_with_type(&format!("field {}", key), v);
        //eprintln!("struct: field: {}", key);
        //eprintln!("typename: {}", std::any::type_name::<T>());
        //eprintln!("AAAAA: {:?}", T::sample());
        //v.serialize(self.child_digester()).unwrap();
        <T>::abi_digest(&mut self.child_digester());
        Ok(())
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl serde::ser::SerializeStructVariant for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: Sstr, v: &T) -> NoResult {
        self.update_with_type(&format!("field {}", key), v);
        <T>::abi_digest(&mut self.child_digester());
        Ok(())
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}
