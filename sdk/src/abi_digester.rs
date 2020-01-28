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
sample_impls! { std::time::Duration, std::time::Duration::from_secs(0) }

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

type Placeholder = ();

impl<T: Sized> AbiSample for T {
    default fn sample() -> Self {
        <Placeholder>::type_erased_sample()
    }
}

// this works like a type erasure and a hatch to escape type error to runtime error
trait TypeErasedSample<T> {
    fn type_erased_sample() -> T;
}

impl<T: Sized> TypeErasedSample<T> for Placeholder {
    default fn type_erased_sample() -> T {
        panic!(
            "derive or implement AbiSample/AbiDigest for {}",
            type_name::<T>()
        );
    }
}

impl<T: Default + Serialize> TypeErasedSample<T> for Placeholder {
    default fn type_erased_sample() -> T {
        let type_name = type_name::<T>();

        if type_name.starts_with("solana") {
            panic!("derive or implement AbiSample/AbiDigest for {}", type_name);
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

impl<T: AbiSample> AbiSample for std::marker::PhantomData<T> {
    fn sample() -> Self {
        info!("AbiSample for (PhantomData<T>): {}", type_name::<Self>());
        <std::marker::PhantomData<T>>::default()
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
        let mut map = HashMap::default();
        map.insert(T::sample(), S::sample());
        map
    }
}

impl<T: std::cmp::Ord + AbiSample, S: AbiSample> AbiSample for BTreeMap<T, S> {
    fn sample() -> Self {
        info!("AbiSample for (BTreeMap<T, S>): {}", type_name::<Self>());
        let mut map = BTreeMap::default();
        map.insert(T::sample(), S::sample());
        map
    }
}

impl<T: AbiSample> AbiSample for Vec<T> {
    fn sample() -> Self {
        info!("AbiSample for (Vec<T>): {}", type_name::<Self>());
        vec![T::sample()]
    }
}

impl<T: std::cmp::Eq + std::hash::Hash + AbiSample, H: std::hash::BuildHasher + Default> AbiSample
    for HashSet<T, H>
{
    fn sample() -> Self {
        info!("AbiSample for (HashSet<T, H>): {}", type_name::<Self>());
        let mut set: HashSet<T, H> = HashSet::default();
        set.insert(T::sample());
        set
    }
}

impl<T: std::cmp::Ord + AbiSample> AbiSample for BTreeSet<T> {
    fn sample() -> Self {
        info!("AbiSample for (BTreeSet<T>): {}", type_name::<Self>());
        let mut set: BTreeSet<T> = BTreeSet::default();
        set.insert(T::sample());
        set
    }
}

#[cfg(all(not(feature = "program")))]
impl solana_sdk::abi_digester::AbiSample for memmap::MmapMut {
    fn sample() -> Self {
        memmap::MmapMut::map_anon(1).expect("failed to map the data file")
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
            .serialize(digester.create_new())
            .map_err(DigestError::wrap_by_type::<T>)
    }
}

// auto-ref hack
impl<T: Serialize + ?Sized + AbiDigest> AbiDigest for &T {
    default fn abi_digest(digester: &mut AbiDigester) -> DigestResult {
        info!("AbiDigest for (&default): {}", type_name::<T>());
        T::abi_digest(digester)
    }
}

// Because Option and Result are so common enums we provide generic trait implementations
// The digesting pattern must match with what is derived from #[derive(AbiDigest)]
impl<T: AbiDigest> AbiDigest for Option<T> {
    fn abi_digest(digester: &mut AbiDigester) -> DigestResult {
        info!("AbiDigest for (Option<T>): {}", type_name::<Self>());

        let variant: Self = Option::Some(T::sample());
        // serde calls serialize_some(); not serialize_variant();
        // so create_new is correct
        variant.serialize(digester.create_new())
    }
}

impl<O: AbiDigest, E: AbiDigest> AbiDigest for Result<O, E> {
    fn abi_digest(digester: &mut AbiDigester) -> DigestResult {
        info!("AbiDigest for (Result<O, E>): {}", type_name::<Self>());

        digester.update(&["enum Result (variants = 2)"]);
        let variant: Self = Result::Ok(O::sample());
        variant.serialize(digester.create_enum_child())?;

        let variant: Self = Result::Err(E::sample());
        variant.serialize(digester.create_enum_child())?;

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

    // must create separate instances because we can't pass the single instnace to
    // `.serialize()` multiple times
    pub fn create_new(&self) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth,
            for_enum: false,
        }
    }

    pub fn create_child(&self) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth + 1,
            for_enum: false,
        }
    }

    pub fn create_enum_child(&self) -> Self {
        Self {
            data_types: self.data_types.clone(),
            depth: self.depth + 1,
            for_enum: true,
        }
    }

    pub fn digest_data<T: ?Sized + Serialize>(&mut self, value: &T) -> DigestResult {
        let type_name = type_name::<T>();
        if type_name.ends_with("__SerializeWith")
            || type_name.starts_with("bv::bit_vec")
            || type_name.starts_with("solana_runtime::serde_snapshot")
            || type_name.starts_with("&solana_runtime::serde_snapshot")
        {
            // we can't use the AbiDigest trait for these cases.
            value.serialize(self.create_new())
        } else {
            <T>::abi_digest(&mut self.create_new())
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

    pub fn update_with_type<T: ?Sized>(&mut self, label: &str) {
        self.update(&[label, type_name::<T>()]);
    }

    pub fn update_with_string(&mut self, label: String) {
        self.update(&[&label]);
    }

    fn digest_primitive<T: Serialize>(mut self) -> Result<AbiDigester, DigestError> {
        self.update_with_type::<T>("primitive");
        Ok(self)
    }

    fn digest_element<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.update_with_type::<T>("element");
        self.create_child().digest_data(v).map(|r| r.into())
    }

    fn digest_named_field<T: ?Sized + Serialize>(&mut self, key: Sstr, v: &T) -> NoResult {
        self.update_with_string(format!("field {}: {}", key, type_name::<T>()));
        self.create_child()
            .digest_data(v)
            .map(|r| r.into())
            .map_err(|e| DigestError::wrap_by_str(e, key))
    }

    fn digest_unnamed_field<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.update_with_type::<T>("field");
        self.create_child().digest_data(v).map(|r| r.into())
    }

    fn check_for_enum(&mut self, label: &'static str, variant: &'static str) -> NoResult {
        if !self.for_enum {
            panic!("derive or implement AbiDigest for the enum, which contains a variant ({}) named {}", label, variant);
        }
        Ok(())
    }

    pub fn finalize(self) -> Hash {
        let mut hasher = Hasher::default();

        for buf in (*self.data_types.borrow()).iter() {
            hasher.hash(buf.as_bytes());
        }

        let r = hasher.result();

        if let Ok(dir) = std::env::var("SOLANA_ABI_DUMP_DIR") {
            // warn when with --threads=1 all thread names are `main` in that case...
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
    #[error("nested error")]
    Node(Sstr, Box<DigestError>),
    #[error("leaf error")]
    Leaf(Sstr, Sstr, Box<DigestError>),
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

    fn serialize_bool(self, _data: bool) -> DigestResult {
        self.digest_primitive::<bool>()
    }

    fn serialize_i8(self, _data: i8) -> DigestResult {
        self.digest_primitive::<i8>()
    }

    fn serialize_i16(self, _data: i16) -> DigestResult {
        self.digest_primitive::<i16>()
    }

    fn serialize_i32(self, _data: i32) -> DigestResult {
        self.digest_primitive::<i32>()
    }

    fn serialize_i64(self, _data: i64) -> DigestResult {
        self.digest_primitive::<i64>()
    }

    fn serialize_i128(self, _data: i128) -> DigestResult {
        self.digest_primitive::<i128>()
    }

    fn serialize_u8(self, _data: u8) -> DigestResult {
        self.digest_primitive::<u8>()
    }

    fn serialize_u16(self, _data: u16) -> DigestResult {
        self.digest_primitive::<u16>()
    }

    fn serialize_u32(self, _data: u32) -> DigestResult {
        self.digest_primitive::<u32>()
    }

    fn serialize_u64(self, _data: u64) -> DigestResult {
        self.digest_primitive::<u64>()
    }

    fn serialize_u128(self, _data: u128) -> DigestResult {
        self.digest_primitive::<u128>()
    }

    fn serialize_f32(self, _data: f32) -> DigestResult {
        self.digest_primitive::<f32>()
    }

    fn serialize_f64(self, _data: f64) -> DigestResult {
        self.digest_primitive::<f64>()
    }

    fn serialize_char(self, _data: char) -> DigestResult {
        self.digest_primitive::<char>()
    }

    fn serialize_str(self, _data: &str) -> DigestResult {
        self.digest_primitive::<&str>()
    }

    fn serialize_unit(self) -> DigestResult {
        self.digest_primitive::<()>()
    }

    fn serialize_bytes(mut self, v: &[u8]) -> DigestResult {
        self.update_with_string(format!("bytes [u8] (len = {})", v.len()));
        Ok(self)
    }

    fn serialize_none(self) -> DigestResult {
        Err(DigestError::NoneIsSerialized)
    }

    fn serialize_some<T>(mut self, v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        // emulate the ABI digest for the Option enum; see TestMyOption
        self.update(&["enum Option (variants = 2)"]);
        let mut variant_digester = self.create_child();

        variant_digester.update_with_string("variant(0) None (unit)".to_owned());
        variant_digester
            .update_with_string(format!("variant(1) Some({}) (newtype)", type_name::<T>()));
        variant_digester.create_child().digest_data(v)
    }

    fn serialize_unit_struct(mut self, name: Sstr) -> DigestResult {
        self.update(&["struct", name, "(unit)"]);
        Ok(self)
    }

    fn serialize_unit_variant(mut self, _name: Sstr, index: u32, variant: Sstr) -> DigestResult {
        self.check_for_enum("unit_variant", variant)?;
        self.update_with_string(format!("variant({}) {} (unit)", index, variant));
        Ok(self)
    }

    fn serialize_newtype_struct<T>(mut self, name: Sstr, v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.update_with_string(format!("struct {}({}) (newtype)", name, type_name::<T>()));
        self.create_child()
            .digest_data(v)
            .map_err(|e| DigestError::wrap_by_str(e, "newtype_struct"))
    }

    fn serialize_newtype_variant<T>(
        mut self,
        _name: Sstr,
        i: u32,
        variant: Sstr,
        v: &T,
    ) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.check_for_enum("newtype_variant", variant)?;
        self.update_with_string(format!(
            "variant({}) {}({}) (newtype)",
            i,
            variant,
            type_name::<T>()
        ));
        self.create_child()
            .digest_data(v)
            .map_err(|e| DigestError::wrap_by_str(e, "newtype_variant"))
    }

    fn serialize_seq(mut self, len: Option<usize>) -> DigestResult {
        self.update_with_string(format!("seq (elements = {})", len.unwrap()));
        Ok(self.create_child())
    }

    fn serialize_tuple(mut self, len: usize) -> DigestResult {
        self.update_with_string(format!("tuple (elements = {})", len));
        Ok(self.create_child())
    }

    fn serialize_tuple_struct(mut self, name: Sstr, len: usize) -> DigestResult {
        self.update_with_string(format!("struct {} (fields = {}) (tuple)", name, len));
        Ok(self.create_child())
    }

    fn serialize_tuple_variant(
        mut self,
        _name: Sstr,
        i: u32,
        variant: Sstr,
        len: usize,
    ) -> DigestResult {
        self.check_for_enum("tuple_variant", variant)?;
        self.update_with_string(format!("variant({}) {} (fields = {})", i, variant, len));
        Ok(self.create_child())
    }

    fn serialize_map(mut self, len: Option<usize>) -> DigestResult {
        self.update_with_string(format!("map (entries = {})", len.unwrap()));
        Ok(self.create_child())
    }

    fn serialize_struct(mut self, name: Sstr, len: usize) -> DigestResult {
        self.update_with_string(format!("struct {} (fields = {})", name, len));
        Ok(self.create_child())
    }

    fn serialize_struct_variant(
        mut self,
        _name: Sstr,
        i: u32,
        variant: Sstr,
        len: usize,
    ) -> DigestResult {
        self.check_for_enum("struct_variant", variant)?;
        self.update_with_string(format!(
            "variant({}) struct {} (fields = {})",
            i, variant, len
        ));
        Ok(self.create_child())
    }
}

impl SerializeSeq for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, data: &T) -> NoResult {
        self.digest_element(data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeTuple for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, data: &T) -> NoResult {
        self.digest_element(data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}
impl SerializeTupleStruct for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, data: &T) -> NoResult {
        self.digest_unnamed_field(data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeTupleVariant for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, data: &T) -> NoResult {
        self.digest_unnamed_field(data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeMap for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> NoResult {
        self.update_with_type::<T>("key");
        self.create_child().digest_data(key).map(|r| r.into())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> NoResult {
        self.update_with_type::<T>("value");
        self.create_child().digest_data(value).map(|r| r.into())
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeStruct for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: Sstr, data: &T) -> NoResult {
        self.digest_named_field(key, data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

impl SerializeStructVariant for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: Sstr, data: &T) -> NoResult {
        self.digest_named_field(key, data)
    }

    fn end(self) -> DigestResult {
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicIsize;

    #[frozen_abi(digest = "CQiGCzsGquChkwffHjZKFqa3tCYtS3GWYRRYX7iDR38Q")]
    type TestTypeAlias = i32;

    #[frozen_abi(digest = "Apwkp9Ah9zKirzwuSzVoU9QRc43EghpkD1nGVakJLfUY")]
    #[derive(Serialize, AbiSample)]
    struct TestStruct {
        test_field: i8,
        test_field2: i8,
    }

    #[frozen_abi(digest = "4LbuvQLX78XPbm4hqqZcHFHpseDJcw4qZL9EUZXSi2Ss")]
    #[derive(Serialize, AbiSample)]
    struct TestTupleStruct(i8, i8);

    #[frozen_abi(digest = "FNHa6mNYJZa59Fwbipep5dXRXcFreaDHn9jEUZEH1YLv")]
    #[derive(Serialize, AbiSample)]
    struct TestNewtypeStruct(i8);

    #[frozen_abi(digest = "5qio5qYurHDv6fq5kcwP2ue2RBEazSZF8CPk2kUuwC2j")]
    #[derive(Serialize, AbiSample)]
    struct TestStructReversed {
        test_field2: i8,
        test_field: i8,
    }

    #[frozen_abi(digest = "DLLrTWprsMjdJGR447A4mui9HpqxbKdsFXBfaWPcwhny")]
    #[derive(Serialize, AbiSample)]
    struct TestStructAnotherType {
        test_field: i16,
        test_field2: i8,
    }

    #[frozen_abi(digest = "Hv597t4PieHYvgiXnwRSpKBRTWqteUS4nHZHY6ZxX69v")]
    #[derive(Serialize, AbiSample)]
    struct TestNest {
        nested_field: [TestStruct; 5],
    }

    #[frozen_abi(digest = "GttWH8FAY3teUjTaSds9mL3YbiDQ7qWw7WAvDXKd4ZzX")]
    type TestUnitStruct = std::marker::PhantomData<i8>;

    #[frozen_abi(digest = "2zvXde11f8sNnFbc9E6ZZeFxV7D2BTVLKEZmNTsCDBpS")]
    #[derive(Serialize, AbiSample, AbiDigest)]
    enum TestEnum {
        VARIANT1,
        VARIANT2,
    }

    #[frozen_abi(digest = "6keb3v7GXLahhL6zoinzCWwSvB3KhmvZMB3tN2mamAm3")]
    #[derive(Serialize, AbiSample, AbiDigest)]
    enum TestTupleVariant {
        VARIANT1(u8, u16),
        VARIANT2(u8, u16),
    }

    #[frozen_abi(digest = "Hnkw3NvGdVPaEURsQDSoiQGfdwk1LhnsvfBg6gdjdkJr")]
    #[derive(Serialize, AbiSample)]
    struct TestVecEnum {
        enums: Vec<TestTupleVariant>,
    }

    #[derive(Serialize, AbiSample)]
    struct TestGenericStruct<T: Ord> {
        test_field: T,
    }

    #[frozen_abi(digest = "2Dr5k3Z513mV4KrGeUfcMwjsVHLmVyLiZarmfnXawEbf")]
    type TestConcreteStruct = TestGenericStruct<i64>;

    #[derive(Serialize, AbiSample, AbiDigest)]
    enum TestGenericEnum<T: serde::Serialize + Sized + Ord> {
        TestVariant(T),
    }

    #[frozen_abi(digest = "2B2HqxHaziSfW3kdxJqV9vEMpCpRaEipXL6Bskv1GV7J")]
    type TestConcreteEnum = TestGenericEnum<u128>;

    #[frozen_abi(digest = "H9qa51FdMo57zCKwK9YPRh2gxMio4ndX3HtyqJatncCB")]
    type TestMap = HashMap<char, i128>;

    #[frozen_abi(digest = "7LQfUPTxoe4bJ56BBDjoo8JqHPgLo9Rru8X1A1RFko9g")]
    type TestVec = Vec<f32>;

    #[frozen_abi(digest = "F5RniBQtNMBiDnyLEf72aQKHskV1TuBrD4jrEH5odPAW")]
    type TestArray = [f64; 10];

    #[frozen_abi(digest = "8cgZGpckC4dFovh3QuZpgvcvK2125ig7P4HsK9KCw39N")]
    type TestUnit = ();

    #[frozen_abi(digest = "FgnBPy2T5iNNbykMteq1M4FRpNeSkzRoi9oXeCjEW6uq")]
    type TestResult = Result<u8, u16>;

    #[frozen_abi(digest = "F5s6YyJkfz7LM56q5j9RzTLa7QX4Utx1ecNkHX5UU9Fp")]
    type TestAtomic = AtomicIsize;

    #[frozen_abi(digest = "7rH7gnEhJ8YouzqPT6VPyUDELvL51DGednSPcoLXG2rg")]
    type TestOptionWithIsize = Option<isize>;

    #[derive(Serialize, AbiSample, AbiDigest)]
    enum TestMyOption<T: serde::Serialize + Sized + Ord> {
        None,
        Some(T),
    }
    #[frozen_abi(digest = "BzXkoRacijFTCPW4PyyvhkqMVgcuhmvPXjZfMsHJCeet")]
    type TestMyOptionWithIsize = TestMyOption<isize>;

    mod skip_should_be_same {
        #[frozen_abi(digest = "4LbuvQLX78XPbm4hqqZcHFHpseDJcw4qZL9EUZXSi2Ss")]
        #[derive(Serialize, AbiSample)]
        struct TestTupleStruct(i8, i8, #[serde(skip)] i8);

        #[frozen_abi(digest = "Hk7BYjZ71upWQJAx2PqoNcapggobPmFbMJd34xVdvRso")]
        #[derive(Serialize, AbiSample)]
        struct TestStruct {
            test_field: i8,
            #[serde(skip)]
            _skipped_test_field: i8,
        }

        #[frozen_abi(digest = "2zvXde11f8sNnFbc9E6ZZeFxV7D2BTVLKEZmNTsCDBpS")]
        #[derive(Serialize, AbiSample, AbiDigest)]
        enum TestEnum {
            VARIANT1,
            VARIANT2,
            #[serde(skip)]
            #[allow(dead_code)]
            VARIANT3,
        }

        #[frozen_abi(digest = "6keb3v7GXLahhL6zoinzCWwSvB3KhmvZMB3tN2mamAm3")]
        #[derive(Serialize, AbiSample, AbiDigest)]
        enum TestTupleVariant {
            VARIANT1(u8, u16),
            VARIANT2(u8, u16, #[serde(skip)] u32),
        }
    }
}
