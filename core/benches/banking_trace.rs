#![feature(test)]

extern crate test;

use {
    solana_core::banking_trace::{sender_overhead_minimized_receiver_loop, BankingPacketBatch, BankingTracer, TraceError, TracerThreadResult},
    solana_perf::{packet::to_packet_batches, test_tx::test_tx},
    std::{sync::{Arc, atomic::AtomicBool}, path::PathBuf, thread},
    test::Bencher,
    tempfile::TempDir,
};

fn drop_and_clean_temp_dir_unless_suppressed(temp_dir: TempDir) {
    std::env::var("BANKING_TRACE_LEAVE_FILES_FROM_LAST_ITERATION")
        .is_ok()
        .then(|| {
            eprintln!("prevented to remove {:?}", temp_dir.path());
            drop(temp_dir.into_path());
        });
} 


fn ensure_fresh_setup_to_benchmark(path: &PathBuf) {
    // make sure fresh setup; otherwise banking tracer appends and rotates
    // trace files created by prior bench iterations, slightly skewing perf
    // result...
    BankingTracer::ensure_cleanup_path(path).unwrap();
}

fn black_box_packet_batch(packet_batch: BankingPacketBatch) -> TracerThreadResult {
    test::black_box(packet_batch);
    Ok(())
}

#[bench]
fn bench_banking_tracer_main_thread_overhead_noop_baseline(bencher: &mut Bencher) {
    let exit = Arc::<AtomicBool>::default();
    let tracer = BankingTracer::new_disabled();
    let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();

    thread::spawn(move || {
        sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
            exit.clone(),
            non_vote_receiver,
            black_box_packet_batch,
        )
    });

    let packet_batch = BankingPacketBatch::new((to_packet_batches(&vec![test_tx(); 4], 10), None));
    bencher.iter(move || {
        non_vote_sender.send(packet_batch.clone()).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_main_thread_overhead_under_peak_write(bencher: &mut Bencher) {
    let exit = Arc::<AtomicBool>::default();
    let tracer = BankingTracer::new_with_config(Some((
        PathBuf::new().join("/tmp/banking-tracer"),
        exit.clone(),
        solana_core::banking_trace::TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD,
    )))
    .unwrap();
    let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();

    thread::spawn(move || {
        sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
            exit.clone(),
            non_vote_receiver,
            |packet_batch| {
                test::black_box(packet_batch);
                Ok(())
            },
        )
    });

    let packet_batch = BankingPacketBatch::new((to_packet_batches(&vec![test_tx(); 4], 10), None));
    bencher.iter(move || {
        non_vote_sender.send(packet_batch.clone()).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_main_thread_overhead_under_sustained_write(bencher: &mut Bencher) {
    let exit = Arc::<AtomicBool>::default();
    let tracer = BankingTracer::new_with_config(Some((
        PathBuf::new().join("/tmp/banking-tracer"),
        exit.clone(),
        1024 * 1024, // cause more frequent trace file rotation
    )))
    .unwrap();
    let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();

    thread::spawn(move || {
        sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
            exit.clone(),
            non_vote_receiver,
            |packet_batch| {
                test::black_box(packet_batch);
                Ok(())
            },
        )
    });

    let packet_batch = BankingPacketBatch::new((to_packet_batches(&vec![test_tx(); 4], 10), None));
    bencher.iter(move || {
        non_vote_sender.send(Arc::clone(&packet_batch)).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_background_thread_throughput(bencher: &mut Bencher) {
    let packet_batch = BankingPacketBatch::new((to_packet_batches(&vec![test_tx(); 4], 10), None));

    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    bencher.iter(move || {
        let path = base_path.join("banking-trace");
        ensure_fresh_setup_to_benchmark(&path);

        let exit = Arc::<AtomicBool>::default();

        let tracer = BankingTracer::new_with_config(Some((
            path,
            exit.clone(),
            50 * 1024 * 1024,
        )))
        .unwrap();
        let (non_vote_sender, non_vote_receiver) = tracer.create_channel_non_vote();
        let (tracer_join_handle, tracer) = tracer.finalize_under_arc();

        let dummy_main_thread_handle = thread::spawn(move || {
            sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
                exit.clone(),
                non_vote_receiver,
                |packet_batch| {
                    test::black_box(packet_batch);
                    Ok(())
                },
            )
        });

        for _ in 0..1000 {
            non_vote_sender.send(packet_batch.clone()).unwrap();
        }

        drop((non_vote_sender, tracer));
        dummy_main_thread_handle.join().unwrap().unwrap();
        tracer_join_handle.unwrap().join().unwrap().unwrap();
    });

    drop_and_clean_temp_dir_unless_suppressed(temp_dir);
}
