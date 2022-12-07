#![feature(test)]

extern crate test;

use {
    solana_perf::{packet::to_packet_batches, test_tx::test_tx},
    std::sync::Arc,
    test::Bencher,
};

#[bench]
fn bench_banking_tracer_baseline_overhead(bencher: &mut Bencher) {
    let exit = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();
    let tracer = solana_core::banking_trace::BankingTracer::new(
        std::path::PathBuf::new().join("/tmp/banking-tracer"),
        false,
        exit.clone(),
    )
    .unwrap();
    let (s, r) = tracer.create_channel_non_vote();

    std::thread::spawn(move || {
        solana_core::banking_trace::sender_overhead_minimized_loop(exit.clone(), r, |m| {
            test::black_box(m);
        })
    });

    let len = 4;
    let chunk_size = 10;
    let tx = test_tx();
    let aa = to_packet_batches(&vec![tx; len], chunk_size);
    let m = Arc::new((aa.clone(), None));

    bencher.iter(move || {
        s.send(m.clone()).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_overhead_under_peak_write(bencher: &mut Bencher) {
    let exit = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();
    let tracer = solana_core::banking_trace::BankingTracer::new(
        std::path::PathBuf::new().join("/tmp/banking-tracer"),
        true,
        exit.clone(),
    )
    .unwrap();
    let (s, r) = tracer.create_channel_non_vote();

    std::thread::spawn(move || {
        solana_core::banking_trace::sender_overhead_minimized_loop(exit.clone(), r, |m| {
            test::black_box(m);
        })
    });

    let len = 4;
    let chunk_size = 10;
    let tx = test_tx();
    let aa = to_packet_batches(&vec![tx; len], chunk_size);
    let m = Arc::new((aa.clone(), None));

    bencher.iter(move || {
        s.send(m.clone()).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_overhead_under_sustained_write(bencher: &mut Bencher) {
    let exit = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();
    let tracer = solana_core::banking_trace::BankingTracer::_new(
        std::path::PathBuf::new().join("/tmp/banking-tracer"),
        true,
        exit.clone(),
        1024 * 1024, // cause more frequent trace file rotation
    )
    .unwrap();
    let (s, r) = tracer.create_channel_non_vote();

    std::thread::spawn(move || {
        solana_core::banking_trace::sender_overhead_minimized_loop(exit.clone(), r, |m| {
            test::black_box(m);
        })
    });

    let len = 4;
    let chunk_size = 10;
    let tx = test_tx();
    let aa = to_packet_batches(&vec![tx; len], chunk_size);
    let m = Arc::new((aa.clone(), None));

    bencher.iter(move || {
        s.send(m.clone()).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_throughput_10_1gb(bencher: &mut Bencher) {
    let len = 4;
    let chunk_size = 10;
    let tx = test_tx();
    let aa = to_packet_batches(&vec![tx; len], chunk_size);
    let m = Arc::new((aa.clone(), None));

    bencher.iter(move || {
        let exit = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();

        let tracer = solana_core::banking_trace::BankingTracer::_new(
            std::path::PathBuf::new().join("/tmp/banking-tracer"),
            true,
            exit.clone(),
            1024 * 1024,
        )
        .unwrap();
        let (s, r) = tracer.create_channel_non_vote();

        let t = std::thread::spawn(move || {
            solana_core::banking_trace::sender_overhead_minimized_loop(exit.clone(), r, |m| {
                test::black_box(m);
            })
        });

        for _ in 0..1000 {
            s.send(m.clone()).unwrap();
        }
        drop(s);
        t.join();
    });
}
