use bincode::{serialize_into, serialized_size};

#[derive(Default)]
pub struct AbiDigester {
    hasher: solana_sdk::hash::Hasher,
}

impl AbiDigester {
    pub fn update(&mut self, strs: &[&str]) {
        let buf_len = serialized_size(strs).unwrap() as usize;
        let mut buf = vec![0; buf_len];
        let mut wr = std::io::Cursor::new(&mut buf[..]);
        serialize_into(&mut wr, strs).unwrap();
        self.hasher.hash(&buf);
    }

    pub fn finalize(self) -> solana_sdk::hash::Hash {
        self.hasher.result()
    }
}
