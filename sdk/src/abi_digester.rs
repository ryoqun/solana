use crate::hash::{Hash, Hasher};

use log::*;

use serde::ser::Error as SerdeError;
use serde::Serialize;

use std::io::Write;

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
                Self::new(AbiDigestSample::sample())
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

impl<T: AbiDigestSample> AbiDigestSample for Option<T> {
    fn sample() -> Option<T> {
        info!(
            "AbiDigestSample for (Option<T>): {}",
            std::any::type_name::<Option<T>>()
        );
        Some(T::sample())
    }
}

impl<T: AbiDigestSample> AbiDigestSample for Box<T> {
    fn sample() -> Box<T> {
        info!(
            "AbiDigestSample for (Box<T>): {}",
            std::any::type_name::<Box<T>>()
        );
        Box::new(T::sample())
    }
}

impl<T: AbiDigestSample> AbiDigestSample for std::sync::Arc<T> {
    fn sample() -> std::sync::Arc<T> {
        info!(
            "AbiDigestSample for (Arc<T>): {}",
            std::any::type_name::<std::sync::Arc<T>>()
        );
        std::sync::Arc::new(T::sample())
    }
}

impl<T: AbiDigestSample> AbiDigestSample for std::rc::Rc<T> {
    fn sample() -> std::rc::Rc<T> {
        info!(
            "AbiDigestSample for (Rc<T>): {}",
            std::any::type_name::<std::rc::Rc<T>>()
        );
        std::rc::Rc::new(T::sample())
    }
}

impl<T: AbiDigestSample> AbiDigestSample for std::sync::Mutex<T> {
    fn sample() -> std::sync::Mutex<T> {
        info!(
            "AbiDigestSample for (Mutex<T>): {}",
            std::any::type_name::<std::sync::Mutex<T>>()
        );
        std::sync::Mutex::new(T::sample())
    }
}

/*
trait AbiDigestSample2 {
    const V: Self;
}

impl<T> AbiDigestSample2 for T {
    default const V: Self = panic!();
}

impl<T: Default> AbiDigestSample2 for T {
    const V: Self = T::default();
}
*/

/*
const C: u64 = 2323;
const D: usize = 2323;
const E: solana_sdk::pubkey::Pubkey = solana_sdk::pubkey::Pubkey([0; 32]);

impl AbiDigestSample for &u64 {
    fn sample() -> &'static u64 {
        info!(
            "AbiDigestSample for &T: {}",
            std::any::type_name::<&u64>()
        );
        &C
    }
}

impl AbiDigestSample for &usize {
    fn sample() -> &'static usize {
        info!(
            "AbiDigestSample for &T: {}",
            std::any::type_name::<&usize>()
        );
        &D
    }
}
*/

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

impl<
        T: std::cmp::Eq + std::hash::Hash + AbiDigestSample,
        S: AbiDigestSample,
        H: ::std::hash::BuildHasher + Default,
    > AbiDigestSample for HashMap<T, S, H>
{
    fn sample() -> HashMap<T, S, H> {
        info!(
            "AbiDigestSample for (HashMap<T, S, H>): {}",
            std::any::type_name::<Self>()
        );
        let mut v = HashMap::default();
        v.insert(T::sample(), S::sample());
        v
        //vec![[S::sample(), T::sample()]].into()
    }
}

impl<T: std::cmp::Ord + AbiDigestSample, S: AbiDigestSample> AbiDigestSample for BTreeMap<T, S> {
    fn sample() -> BTreeMap<T, S> {
        info!(
            "AbiDigestSample for (BTreeMap<T, S>): {}",
            std::any::type_name::<Self>()
        );
        let mut v = BTreeMap::default();
        v.insert(T::sample(), S::sample());
        v
        //vec![[S::sample(), T::sample()]].into()
    }
}

impl<T: AbiDigestSample> AbiDigestSample for Vec<T> {
    fn sample() -> Vec<T> {
        info!(
            "AbiDigestSample for (Vec<T>): {}",
            std::any::type_name::<Vec<T>>()
        );
        let v: Vec<T> = vec![T::sample()];
        v
    }
}

impl<
        T: std::cmp::Eq + std::hash::Hash + AbiDigestSample,
        H: ::std::hash::BuildHasher + Default,
    > AbiDigestSample for HashSet<T, H>
{
    fn sample() -> HashSet<T, H> {
        info!(
            "AbiDigestSample for (HashSet<T, H>): {}",
            std::any::type_name::<Self>()
        );
        let mut v: HashSet<T, H> = HashSet::default();
        v.insert(T::sample());
        v
    }
}

impl<T: std::cmp::Ord + AbiDigestSample> AbiDigestSample for BTreeSet<T> {
    fn sample() -> BTreeSet<T> {
        info!(
            "AbiDigestSample for (BTreeSet<T>): {}",
            std::any::type_name::<Self>()
        );
        let mut v: BTreeSet<T> = BTreeSet::default();
        v.insert(T::sample());
        v
    }
}

use memmap::MmapMut;
impl solana_sdk::abi_digester::AbiDigestSample for MmapMut {
    fn sample() -> Self {
        MmapMut::map_anon(1).expect("failed to map the data file")
    }
}

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
impl solana_sdk::abi_digester::AbiDigestSample for SocketAddr {
    fn sample() -> Self {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
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

impl<T: Serialize + Sized> AbiDigest for &T {
    default fn abi_digest(digester: &mut AbiDigester) {
        digester.update(&["ref", std::any::type_name::<T>()]);
        let v = T::sample();
        v.serialize(digester.child_digester()).unwrap();
    }
}

impl<T: Serialize + ?Sized + AbiDigestSample> AbiDigest for T {
    default fn abi_digest(digester: &mut AbiDigester) {
        info!("AbiDigest for (default): {}", std::any::type_name::<T>());
        let v = T::sample();
        v.serialize(digester.child_digester()).unwrap();
    }
}

impl<T: AbiDigest> AbiDigest for Option<T> {
    fn abi_digest(digester: &mut AbiDigester) {
        info!(
            "AbiDigest for (Option<T>): {}",
            std::any::type_name::<Option<T>>()
        );
        <T>::abi_digest(&mut digester.child_digester());
    }
}

impl<E: AbiDigestSample> AbiDigestSample for ::core::result::Result<(), E> {
    fn sample() -> Self {
        /*
        panic!("aaa");
        info!(
            "AbiDigest for (Result<(), E>): {}",
            std::any::type_name::<Result<(), E>>()
        );
        digester.update(&["result ok", std::any::type_name::<()>()]);
        <()>::abi_digest(&mut digester.child_digester());
        digester.update(&["result error", std::any::type_name::<E>()]);
        <E>::abi_digest(&mut digester.child_digester());
        */
        Err(E::sample())
    }
}

impl<O: AbiDigest, E: AbiDigest> AbiDigest for ::core::result::Result<O, E> {
    fn abi_digest(digester: &mut AbiDigester) {
        info!(
            "AbiDigest for (Result<O, E>): {}",
            std::any::type_name::<Result<O, E>>()
        );

        digester.update(&["result ok", std::any::type_name::<O>()]);
        let v: ::core::result::Result<O, E> = Result::Ok(O::sample());
        v.serialize(digester.forced_child_digester()).unwrap();

        digester.update(&["result error", std::any::type_name::<E>()]);
        let v: ::core::result::Result<O, E> = Result::Err(E::sample());
        v.serialize(digester.forced_child_digester()).unwrap();
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
        info!("updating with: {}", buf.trim_end());
        (*self.data_types.borrow_mut()).push(buf);
    }

    fn update_with_type<T>(&mut self, label: &str, _v: T) {
        self.update(&[label, std::any::type_name::<T>()]);
    }

    pub fn update_with_type2<T>(&mut self, label: &str) {
        self.update(&[label, std::any::type_name::<T>()]);
    }

    fn update_with_primitive<T>(mut self, v: T) -> Result<AbiDigester, DigestError> {
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

    fn serialize_unit_struct(mut self, name: Sstr) -> DigestResult {
        // enable this?
        //if !self.forced {
        //    panic!(
        //        "unit_variant: SHOULD NOT HAPPEN DERIVE AbiDigestSample FOR THE ABOVE TYPE! {} {}",
        //        name, variant
        //    );
        //}
        self.update(&["unit struct", name]);
        Ok(self)
    }

    fn serialize_unit_variant(mut self, name: Sstr, index: u32, variant: Sstr) -> DigestResult {
        if !self.forced {
            //panic!(
            //    "unit_variant: SHOULD NOT HAPPEN DERIVE AbiDigestSample FOR THE ABOVE TYPE! {} {}",
            //    name, variant
            //);
        }
        self.update(&[
            "variant",
            name,
            &format!("unit({})", &index.to_string()),
            variant,
        ]);
        Ok(self)
    }

    fn serialize_newtype_struct<T>(mut self, name: Sstr, _v: &T) -> DigestResult
    where
        T: ?Sized + Serialize,
    {
        self.update(&["newtype", name, "struct", std::any::type_name::<T>()]);
        <T>::abi_digest(&mut self);
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
        /*if !self.forced {
            panic!(
                "newtype_variant: SHOULD NOT HAPPEN DERIVE AbiDigestSample FOR THE ABOVE TYPE! {} {}",
                name, variant
            );
        }*/
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
        Ok(self.child_digester())
    }
}

impl serde::ser::SerializeSeq for AbiDigester {
    type Ok = Self;
    type Error = DigestError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> NoResult {
        self.update_with_type("element", v);
        <T>::abi_digest(&mut self.child_digester());
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
        //info!("aaaaa: {:?}", (&v).abi_digest());
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
        info!("enum: variant: tuple");
        info!("typename: {}", std::any::type_name::<T>());
        //info!("AAAAA: {:?}", T::sample());
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

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> NoResult {
        self.update_with_type("key", key);
        <T>::abi_digest(&mut self.child_digester());
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> NoResult {
        self.update_with_type("value", value);
        <T>::abi_digest(&mut self.child_digester());
        Ok(())
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
        //info!("struct: field: {}", key);
        //info!("typename: {}", std::any::type_name::<T>());
        //info!("AAAAA: {:?}", T::sample());
        let aa = std::any::type_name::<T>();
        if aa.ends_with("__SerializeWith") || aa.starts_with("bv::bit_vec") {
            v.serialize(self.child_digester()).unwrap();
        } else {
            /*let by_rust_type_tree = std::panic::catch_unwind(|| {
                T::sample();
            });
            if by_rust_type_tree.is_ok() {
                <T>::abi_digest(&mut self.child_digester());
            } else if by_rust_type_tree.is_err() && !aa.contains("solana") {
                v.serialize(self.child_digester()).unwrap();
            }*/
            <T>::abi_digest(&mut self.child_digester());
        }
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
