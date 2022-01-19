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
    let mut batches = to_packet_batches(
        &std::iter::repeat(tx).take(64 * 1024).collect::<Vec<_>>(),
        128,
    );
    let packet_count = sigverify::count_packets_in_batches(&batches);
    println!("packet_count {} {}", packet_count, batches.len());

    // verify packets
    bencher.iter(|| {
        let _ans = sigverify::dedup_packets(&mut batches);
    })
}
