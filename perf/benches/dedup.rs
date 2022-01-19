#![feature(test)]

extern crate test;

use {
    solana_perf::{packet::to_packet_batches, sigverify, test_tx::test_tx},
    test::Bencher,
};

#[bench]
fn bench_dedup(bencher: &mut Bencher) {
    let tx = test_tx();

    // generate packet vector
    let mut batches = to_packet_batches(&std::iter::repeat(tx).take(128).collect::<Vec<_>>(), 128);

    // verify packets
    bencher.iter(|| {
        let _ans = sigverify::dedup_packets(&mut batches);
    })
}
