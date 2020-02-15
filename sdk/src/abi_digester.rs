use crate::hash::{Hash, Hasher};

use log::*;

use serde::ser::Error as SerdeError;
use serde::ser::*;
use serde::{Serialize, Serializer};

use std::any::type_name;
use std::io::Write;

pub trait AbiSample: Sized {
    fn sample() -> Self;
}

// Following code snippets are copied and adapted from the official rustc implementation to
// implement AbiSample trait for most of basic types.
// These are licensed under Apache-2.0 + MIT (compatible because we're Apache-2.0)

// Source: https://github.com/rust-lang/rust/blob/ba18875557aabffe386a2534a1aa6118efb6ab88/src/libcore/tuple.rs#L7
macro_rules! tuple_sample_impls {
    ($(
        $Tuple:ident {
            $(($idx:tt) -> $T:ident)+
        }
    )+) => {
        $(
            impl<$($T:AbiSample),+> AbiSample for ($($T,)+) {
                fn sample() -> Self {
                        ($({ let x: $T = AbiSample::sample(); x},)+)
                }
            }
        )+
    }
}

// Source: https://github.com/rust-lang/rust/blob/ba18875557aabffe386a2534a1aa6118efb6ab88/src/libcore/tuple.rs#L110
tuple_sample_impls! {
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

// Source: https://github.com/rust-lang/rust/blob/ba18875557aabffe386a2534a1aa6118efb6ab88/src/libcore/array/mod.rs#L417
macro_rules! array_sample_impls {
    {$n:expr, $t:ident $($ts:ident)*} => {
        impl<T> AbiSample for [T; $n] where T: AbiSample {
            fn sample() -> Self {
                [$t::sample(), $($ts::sample()),*]
            }
        }
        array_sample_impls!{($n - 1), $($ts)*}
    };
    {$n:expr,} => {
        impl<T> AbiSample for [T; $n] {
        fn sample() -> Self { [] }
        }
    };
}

array_sample_impls! {32, T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T}

// Source: https://github.com/rust-lang/rust/blob/ba18875557aabffe386a2534a1aa6118efb6ab88/src/libcore/default.rs#L137
macro_rules! sample_impls {
    ($t:ty, $v:expr) => {
        impl AbiSample for $t {
            fn sample() -> Self {
                $v
            }
        }
    };
}

sample_impls! { (), () }
sample_impls! { bool, false }
sample_impls! { char, '\x00' }

sample_impls! { usize, 0 }
sample_impls! { u8, 0 }
sample_impls! { u16, 0 }
sample_impls! { u32, 0 }
sample_impls! { u64, 0 }
sample_impls! { u128, 0 }

sample_impls! { isize, 0 }
sample_impls! { i8, 0 }
sample_impls! { i16, 0 }
sample_impls! { i32, 0 }
sample_impls! { i64, 0 }
sample_impls! { i128, 0 }

sample_impls! { f32, 0.0f32 }
sample_impls! { f64, 0.0f64 }
sample_impls! { String, String::new() }

use std::sync::atomic::*;

// Source: https://github.com/rust-lang/rust/blob/ba18875557aabffe386a2534a1aa6118efb6ab88/src/libcore/sync/atomic.rs#L1199
macro_rules! atomic_sample_impls {
    ($atomic_type: ident) => {
        impl AbiSample for $atomic_type {
            fn sample() -> Self {
                Self::new(AbiSample::sample())
            }
        }
    };
}
atomic_sample_impls! { AtomicU8 }
atomic_sample_impls! { AtomicU16 }
atomic_sample_impls! { AtomicU32 }
atomic_sample_impls! { AtomicU64 }
atomic_sample_impls! { AtomicUsize }
atomic_sample_impls! { AtomicI8 }
atomic_sample_impls! { AtomicI16 }
atomic_sample_impls! { AtomicI32 }
atomic_sample_impls! { AtomicI64 }
atomic_sample_impls! { AtomicIsize }
atomic_sample_impls! { AtomicBool }

impl<T: Sized> AbiSample for T {
    default fn sample() -> Self {
        <()>::type_erased_sample()
    }
}

// this works like a type erasure and a hatch to escape type error to runtime error
trait TypeErasedSample<T> {
    fn type_erased_sample() -> T;
}

impl<T: Sized> TypeErasedSample<T> for () {
    default fn type_erased_sample() -> T {
        panic!("implement AbiSample for {}", type_name::<T>());
    }
}

impl<T: Default> TypeErasedSample<T> for () {
    default fn type_erased_sample() -> T {
        T::default()
    }
}

impl<T: Default + Serialize> TypeErasedSample<T> for () {
    default fn type_erased_sample() -> T {
        let type_name = type_name::<T>();

        if type_name.starts_with("solana") {
            panic!("explicitly derive AbiSample: {}", type_name)
        } else if type_name.starts_with("bv::bit_vec::BitVec")
            || type_name.starts_with("generic_array::GenericArray")
        {
            T::default()
        } else {
            panic!("new unrecognized type for ABI digest!: {}", type_name)
        }
    }
}

impl<T: AbiSample> AbiSample for Option<T> {
    fn sample() -> Self {
        info!("AbiSample for (Option<T>): {}", type_name::<Self>());
        Some(T::sample())
    }
}

impl<O: AbiSample, E: AbiSample> AbiSample for Result<O, E> {
    fn sample() -> Self {
        info!("AbiSample for (Result<O, E>): {}", type_name::<Self>());
        Ok(O::sample())
    }
}

impl<T: AbiSample> AbiSample for Box<T> {
    fn sample() -> Self {
        info!("AbiSample for (Box<T>): {}", type_name::<Self>());
        Box::new(T::sample())
    }
}

impl<T> AbiSample for Box<dyn Fn(&mut T) -> () + Sync + Send> {
    fn sample() -> Self {
        info!("AbiSample for (Box<T>): {}", type_name::<Self>());
        Box::new(move |_t: &mut T| {})
    }
}

impl<T: AbiSample> AbiSample for Box<[T]> {
    fn sample() -> Self {
        info!("AbiSample for (Box<[T]>): {}", type_name::<Self>());
        Box::new([T::sample()])
    }
}

use std::marker::PhantomData;

impl<T: AbiSample> AbiSample for PhantomData<T> {
    fn sample() -> Self {
        info!("AbiSample for (PhantomData<T>): {}", type_name::<Self>());
        <PhantomData<T>>::default()
    }
}

impl<T: AbiSample> AbiSample for std::sync::Arc<T> {
    fn sample() -> Self {
        info!("AbiSample for (Arc<T>): {}", type_name::<Self>());
        std::sync::Arc::new(T::sample())
    }
}

impl<T: AbiSample> AbiSample for std::rc::Rc<T> {
    fn sample() -> Self {
        info!("AbiSample for (Rc<T>): {}", type_name::<Self>());
        std::rc::Rc::new(T::sample())
    }
}

impl<T: AbiSample> AbiSample for std::sync::Mutex<T> {
    fn sample() -> Self {
        info!("AbiSample for (Mutex<T>): {}", type_name::<Self>());
        std::sync::Mutex::new(T::sample())
    }
}

impl<T: AbiSample> AbiSample for std::sync::RwLock<T> {
    fn sample() -> Self {
        info!("AbiSample for (RwLock<T>): {}", type_name::<Self>());
        std::sync::RwLock::new(T::sample())
    }
}

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

impl<
        T: std::cmp::Eq + std::hash::Hash + AbiSample,
        S: AbiSample,
        H: std::hash::BuildHasher + Default,
    > AbiSample for HashMap<T, S, H>
{
    fn sample() -> Self {
        info!("AbiSample for (HashMap<T, S, H>): {}", type_name::<Self>());
        let mut v = HashMap::default();
        v.insert(T::sample(), S::sample());
        v
    }
}

impl<T: std::cmp::Ord + AbiSample, S: AbiSample> AbiSample for BTreeMap<T, S> {
    fn sample() -> Self {
        info!("AbiSample for (BTreeMap<T, S>): {}", type_name::<Self>());
        let mut v = BTreeMap::default();
        v.insert(T::sample(), S::sample());
        v
    }
}

impl<T: AbiSample> AbiSample for Vec<T> {
    fn sample() -> Self {
        info!("AbiSample for (Vec<T>): {}", type_name::<Self>());
        let v: Vec<T> = vec![T::sample()];
        v
    }
}

impl<T: std::cmp::Eq + std::hash::Hash + AbiSample, H: std::hash::BuildHasher + Default> AbiSample
    for HashSet<T, H>
{
    fn sample() -> Self {
        info!("AbiSample for (HashSet<T, H>): {}", type_name::<Self>());
        let mut v: HashSet<T, H> = HashSet::default();
        v.insert(T::sample());
        v
    }
}

impl<T: std::cmp::Ord + AbiSample> AbiSample for BTreeSet<T> {
    fn sample() -> Self {
        info!("AbiSample for (BTreeSet<T>): {}", type_name::<Self>());
        let mut v: BTreeSet<T> = BTreeSet::default();
        v.insert(T::sample());
        v
    }
}

#[cfg(all(not(feature = "program")))]
use memmap::MmapMut;

#[cfg(all(not(feature = "program")))]
impl solana_sdk::abi_digester::AbiSample for MmapMut {
    fn sample() -> Self {
        MmapMut::map_anon(1).expect("failed to map the data file")
    }
}

#[cfg(all(not(feature = "program")))]
impl solana_sdk::abi_digester::AbiSample for std::path::PathBuf {
    fn sample() -> Self {
        std::path::PathBuf::from(String::sample())
    }
}

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
impl solana_sdk::abi_digester::AbiSample for SocketAddr {
    fn sample() -> Self {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    }
}

// This is a control flow indirection needed to digesting all variants of an enum
pub trait AbiDigest: Serialize {
    fn abi_digest(digester: &mut AbiDigester) -> DigestResult;
}

impl<T: Serialize + ?Sized> AbiDigest for T {
    default fn abi_digest(_digester: &mut AbiDigester) -> DigestResult {
        unreachable!("AbiDigest must be implemented for {}", type_name::<T>());
    }
}

impl<T: Serialize + ?Sized + AbiSample> AbiDigest for T {
    default fn abi_digest(digester: &mut AbiDigester) -> DigestResult {
        info!("AbiDigest for (default): {}", type_name::<T>());
        T::sample()
            .serialize(digester.create_child())
            .map_err(DigestError::wrap_by_type::<T>)
    }
}

impl<T: Serialize + Sized> AbiDigest for &T {
    default fn abi_digest(digester: &mut AbiDigester) -> DigestResult {
        digester.update(&["ref", type_name::<T>()]);
        T::sample().serialize(digester.create_child())
    }
}

// Because Option and Result are so common enums we provide generic trait implementations
// The digesting pattern must match with what is derived from #[derive(AbiDigest)]
impl<T: AbiDigest> AbiDigest for Option<T> {
    fn abi_digest(digester: &mut AbiDigester) -> DigestResult {
        info!("AbiDigest for (Option<T>): {}", type_name::<Self>());

        let v: Self = Option::Some(T::sample());
        v.serialize(digester.create_enum_child())
    }
}

impl<O: AbiDigest, E: AbiDigest> AbiDigest for Result<O, E> {
    fn abi_digest(digester: &mut AbiDigester) -> DigestResult {
        info!("AbiDigest for (Result<O, E>): {}", type_name::<Self>());

        let v: Self = Result::Ok(O::sample());
        v.serialize(digester.create_enum_child())?;

        let v: Self = Result::Err(E::sample());
        v.serialize(digester.create_enum_child())?;

        Ok(digester.create_child())
    }
}

#[derive(Debug)]
pub struct AbiDigester {
    data_types: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    for_enum: bool,
    depth: usize,
}

pub type DigestResult = Result<AbiDigester, DigestError>;
type NoResult = Result<(), DigestError>;
type Sstr = &'static str;

impl DigestError {
    fn wrap_by_type<T>(e: DigestError) -> DigestError {
        DigestError::Node(type_name::<T>(), Box::new(e))
    }

    fn wrap_by_str(e: DigestError, s: Sstr) -> DigestError {
        DigestError::Node(s, Box::new(e))
    }
}

impl From<AbiDigester> for () {
    fn from(_: AbiDigester) -> Self {}
}

const INDENT_WIDTH: usize = 4;

impl AbiDigester {
    pub fn create() -> Self {
        AbiDigester {
            data_types: std::rc::Rc::new(std::cell::RefCell::new(vec![])),
            for_enum: false,
            depth: 0,
        }
    }

    // must be created separate instance because we can't pass the single instnace to
    // `.serialize()` multiple times
    pub fn create_child(&self) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth + 1,
            for_enum: false,
        }
    }

    pub fn digest_data<T: ?Sized + Serialize>(&self, value: &T) -> DigestResult {
        let type_name = type_name::<T>();
        if type_name.ends_with("__SerializeWith") || type_name.starts_with("bv::bit_vec") {
            value.serialize(self.create_child())
        } else {
            <T>::abi_digest(&mut self.create_child())
        }
    }

    pub fn create_enum_child(&self) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth + 1,
            for_enum: true,
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
        info!("updating with: {}", buf.trim_end());
        (*self.data_types.borrow_mut()).push(buf);
    }

    fn update_with_type<T>(&mut self, label: &str, _v: T) {
        self.update(&[label, type_name::<T>()]);
    }

    pub fn update_with_type2<T>(&mut self, label: &str) {
        self.update(&[label, type_name::<T>()]);
    }

    fn update_with_primitive<T>(mut self, v: T) -> Result<AbiDigester, DigestError> {
        self.update_with_type("primitive", v);
        Ok(self)
    }

    fn digest_element<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.update_with_type("element", v);
        self.digest_data(v).map(|r| r.into())
    }

    fn digest_named_field<T: ?Sized + Serialize>(&mut self, key: Sstr, v: &T) -> NoResult {
        self.update_with_type(&format!("field {}", key), v);
        self.digest_data(v)
            .map(|r| r.into())
            .map_err(|e| DigestError::wrap_by_str(e, key))
    }

    fn digest_unnamed_field<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.update_with_type("field", v);
        self.digest_data(v).map(|r| r.into())
    }

    pub fn finalize(self) -> Hash {
        let mut hasher = Hasher::default();

        for buf in (*self.data_types.borrow()).iter() {
            hasher.hash(buf.as_bytes());
        }

        let r = hasher.result();

        if let Ok(dir) = std::env::var("SOLANA_ABI_DUMP_DIR") {
            let path = format!(
                "{}/{}_{}",
                dir,
                std::thread::current()
                    .name()
                    .unwrap_or("unknown-test-thread")
                    .replace(':', "_"),
                r,
            );
            let mut file = std::fs::File::create(path).unwrap();
            for buf in (*self.data_types.borrow()).iter() {
                file.write_all(buf.as_bytes()).unwrap();
            }
            file.sync_data().unwrap();
        }

        r
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DigestError {
    #[error("Option::None is serialized; no ABI digest for Option::Some")]
    NoneIsSerialized,
    #[error("a enum's variant of s serialized; no ABI digest for others")]
    DigestNotImplementedForEnum,
    #[error("nested error")]
    Node(Sstr, Box<DigestError>),
}
impl SerdeError for DigestError {
    fn custom<T: std::fmt::Display>(_msg: T) -> DigestError {
        unreachable!("This error should never be used");
    }
}

impl Serializer for AbiDigester {
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
        self.update_with_primitive(v)
    }

    fn serialize_i8(self, v: i8) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_i16(self, v: i16) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_i32(self, v: i32) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_i64(self, v: i64) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_i128(self, v: i128) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_u8(self, v: u8) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_u16(self, v: u16) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_u32(self, v: u32) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_u64(self, v: u64) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_u128(self, v: u128) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_f32(self, v: f32) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_f64(self, v: f64) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_char(self, v: char) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_str(self, v: &str) -> DigestResult {
        self.update_with_primitive(v)
    }

    fn serialize_unit(self) -> DigestResult {
        self.update_with_primitive(())
    }

    fn serialize_bytes(mut self, v: &[u8]) -> DigestResult {
        self.update_with_type2::<&[u8]>(&format!("bytes {}", v.len()));
        Ok(self)
    }

    fn serialize_none(self) -> DigestResult {
        Err(DigestError::NoneIsSerialized)
    }

    fn serialize_some<T>(mut self, v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.update_with_type("some", v);
        self.digest_data(v)
    }

    fn serialize_unit_struct(mut self, name: Sstr) -> DigestResult {
        self.update(&["unit struct", name]);
        Ok(self)
    }

    fn serialize_unit_variant(mut self, name: Sstr, index: u32, variant: Sstr) -> DigestResult {
        if !self.for_enum {
            return Err(DigestError::wrap_by_str(
                DigestError::DigestNotImplementedForEnum,
                "unit_variant",
            ));
        }
        self.update(&[
            "variant",
            name,
            &format!("unit({})", &index.to_string()),
            variant,
        ]);
        Ok(self)
    }

    fn serialize_newtype_struct<T>(mut self, name: Sstr, v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.update(&["newtype", name, "struct", type_name::<T>()]);
        self.digest_data(v)
            .map_err(|e| DigestError::wrap_by_str(e, "newtype_struct"))
    }

    fn serialize_newtype_variant<T>(
        mut self,
        name: Sstr,
        _i: u32,
        variant: Sstr,
        v: &T,
    ) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        if !self.for_enum {
            return Err(DigestError::wrap_by_str(
                DigestError::DigestNotImplementedForEnum,
                "newtype_variant",
            ));
        }
        self.update(&["variant", name, "newtype", variant, type_name::<T>()]);
        self.digest_data(v)
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

    fn serialize_tuple_struct(mut self, name: Sstr, len: usize) -> DigestResult {
        self.update(&["tuple struct", name, len.to_string().as_ref()]);
        Ok(self)
    }

    fn serialize_tuple_variant(
        mut self,
        name: Sstr,
        _i: u32,
        variant: Sstr,
        _len: usize,
    ) -> DigestResult {
        if !self.for_enum {
            return Err(DigestError::wrap_by_str(
                DigestError::DigestNotImplementedForEnum,
                "tuple_variant",
            ));
        }
        self.update(&["variant", name, "newtype_tuple", variant]);
        Ok(self.create_child())
    }

    fn serialize_map(mut self, _len: Option<usize>) -> DigestResult {
        self.update(&["map"]);
        Ok(self)
    }

    fn serialize_struct(self, name: Sstr, len: usize) -> DigestResult {
        // export struct name
        info!("serialize_struct {} {}", name, len);
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
        Ok(self.create_child())
    }
}

impl SerializeSeq for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.digest_element(v)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}
impl SerializeTuple for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.digest_element(v)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}
impl SerializeTupleStruct for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.digest_unnamed_field(v)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeTupleVariant for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.digest_unnamed_field(v)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeMap for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> NoResult {
        self.update_with_type("key", key);
        self.digest_data(key).map(|r| r.into())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> NoResult {
        self.update_with_type("value", value);
        self.digest_data(value).map(|r| r.into())
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeStruct for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: Sstr, v: &T) -> NoResult {
        self.digest_named_field(key, v)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeStructVariant for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: Sstr, v: &T) -> NoResult {
        self.digest_named_field(key, v)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicIsize;

    #[frozen_abi(digest = "72U9RN7GyAN8WfyZekwDjmgNNVqpRr62WYpX69HcSQpT")]
    type TestTypeAlias = i32;

    #[frozen_abi(digest = "C7XEnhpy8Dm6PzUD2wf3we5gxQxtqcqhjWoHwUaiHLQH")]
    #[derive(Serialize, AbiSample)]
    struct TestTupleStruct(i8, i8);

    #[frozen_abi(digest = "4XRyCqXL8H48jwhQu4J9r8L3ZuoVyaWZLTmtwsKxL4Eq")]
    #[derive(Serialize, AbiSample)]
    struct TestNewtypeStruct(i8);

    #[frozen_abi(digest = "54fUCH3yCdTRyg9KGgtA8iM1oEasfGagn2Rdx3xvQNsB")]
    #[derive(Serialize, AbiSample)]
    struct TestStruct {
        test_field: i8,
        test_field2: i8,
    }

    #[frozen_abi(digest = "3CMjKdDzuGBiN3dAZEd2LuPnewxnSUUnRJZGSif7iwGA")]
    #[derive(Serialize, AbiSample)]
    struct TestStructReversed {
        test_field2: i8,
        test_field: i8,
    }

    #[frozen_abi(digest = "Hty5GomFYWGkYzfBxHBfznT944y6ivt8iuyuEx8MGvXR")]
    #[derive(Serialize, AbiSample)]
    struct TestStructAnotherType {
        test_field: i16,
        test_field2: i8,
    }

    #[frozen_abi(digest = "9UUDRfwbqU4XMCyaLZnPGQqigmV8cr5FAXM9Dyd3hR9n")]
    #[derive(Serialize, AbiSample)]
    struct TestNest {
        nested_field: [TestStruct; 5],
    }

    #[frozen_abi(digest = "9uJk94f2q1h7gXv6LNbaZgWwG2ma8kdG8HRoRZWFZt4n")]
    type TestUnitStruct = std::marker::PhantomData<i8>;

    #[frozen_abi(digest = "BnHtuDevCVYuPu6JzKiCz7gyAWjWnDougeLtCbQyizJd")]
    #[derive(Serialize, AbiSample)]
    enum TestEnum {
        VARIANT1,
        VARIANT2,
    }

    #[frozen_abi(digest = "CrmfomDKBiFWXmUDiVQa8Sn9iGr6FTTkarqc7PBd9KeD")]
    #[derive(Serialize, AbiSample)]
    enum TestTupleVariant {
        VARIANT1(u8, u16),
        VARIANT2(u8, u16),
    }

    #[derive(Serialize, AbiSample)]
    struct TestGenericStruct<T: Ord> {
        test_field: T,
    }

    #[frozen_abi(digest = "8UTxNGWuPJqQ8fRrCjR5W6uEHHYPzP7y8rQeYppiRetf")]
    type TestConcreteStruct = TestGenericStruct<i64>;

    #[derive(Serialize, AbiSample, AbiDigest)]
    enum TestGenericEnum<T: serde::Serialize + Sized + Ord> {
        TestVariant(T),
    }

    #[frozen_abi(digest = "GRkoFAhsuC5Jghoff1rmu8qUboowZHFuAUXBdHhWQtpc")]
    type TestConcreteEnum = TestGenericEnum<u128>;

    #[frozen_abi(digest = "DL3KTotmMgUB9FzKc7tyPU3QrG5Qq3LdoRQ7396rciYs")]
    type TestMap = HashMap<char, i128>;

    #[frozen_abi(digest = "GwfBKtcTeAypFpAw1ExXxAcvcnjwS8Tbnos8asMTUbjA")]
    type TestVec = Vec<f32>;

    #[frozen_abi(digest = "6A7R1JRu5ui77qq1NbNhwXaAMwErXppXGRhFC2HN5656")]
    type TestArray = [f64; 10];

    #[frozen_abi(digest = "BEh8ii8iA4iBJvidDkRoTKgjUvZv82SS64iFmSL5Cik3")]
    type TestUnit = ();

    #[frozen_abi(digest = "nWZAZ22vGdD4ECE4gXcKhEf8wQNjjvimUTPRPLFzfo4")]
    type TestResult = Result<u8, u16>;

    #[frozen_abi(digest = "Fcp6HvvGA8PYtoNF1eyg7X6zRdCf3Cb3sX6qqk6LAa6A")]
    type TestAtomic = AtomicIsize;

    mod skip_should_be_same {
        #[frozen_abi(digest = "C7XEnhpy8Dm6PzUD2wf3we5gxQxtqcqhjWoHwUaiHLQH")]
        #[derive(Serialize, AbiSample)]
        struct TestTupleStruct(i8, i8, #[serde(skip)] i8);

        #[frozen_abi(digest = "EbKnnf5eJLYqvAaV2rL4M9Ejh7GBfwXvd3bTEpeojj3G")]
        #[derive(Serialize, AbiSample)]
        struct TestStruct {
            test_field: i8,
            #[serde(skip)]
            _skipped_test_field: i8,
        }

        #[frozen_abi(digest = "BnHtuDevCVYuPu6JzKiCz7gyAWjWnDougeLtCbQyizJd")]
        #[derive(Serialize, AbiSample)]
        enum TestEnum {
            VARIANT1,
            VARIANT2,
            #[serde(skip)]
            #[allow(dead_code)]
            VARIANT3,
        }

        #[frozen_abi(digest = "CrmfomDKBiFWXmUDiVQa8Sn9iGr6FTTkarqc7PBd9KeD")]
        #[derive(Serialize, AbiSample)]
        enum TestTupleVariant {
            VARIANT1(u8, u16),
            VARIANT2(u8, u16, #[serde(skip)] u32),
        }
    }
}
