#![feature(test)]

extern crate test;

use {
    solana_core::banking_trace::TraceError,
    solana_perf::{packet::to_packet_batches, test_tx::test_tx},
    std::sync::Arc,
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

#[bench]
fn bench_banking_tracer_main_thread_overhead_noop_baseline(bencher: &mut Bencher) {
    let exit = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();
    let tracer = solana_core::banking_trace::BankingTracer::new_disabled();
    let (s, r) = tracer.create_channel_non_vote();

    std::thread::spawn(move || {
        solana_core::banking_trace::sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
            exit.clone(),
            r,
            |m| {
                test::black_box(m);
                Ok(())
            },
        )
    });

    let len = 4;
    let chunk_size = 10;
    let tx = test_tx();
    let aa = to_packet_batches(&vec![tx; len], chunk_size);
    let m = Arc::new((aa, None));

    bencher.iter(move || {
        s.send(m.clone()).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_main_thread_overhead_under_peak_write(bencher: &mut Bencher) {
    let exit = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();
    let tracer = solana_core::banking_trace::BankingTracer::new_with_config(Some((
        std::path::PathBuf::new().join("/tmp/banking-tracer"),
        exit.clone(),
        solana_core::banking_trace::TRACE_FILE_DEFAULT_ROTATE_BYTE_THRESHOLD,
    )))
    .unwrap();
    let (s, r) = tracer.create_channel_non_vote();

    std::thread::spawn(move || {
        solana_core::banking_trace::sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
            exit.clone(),
            r,
            |m| {
                test::black_box(m);
                Ok(())
            },
        )
    });

    let len = 4;
    let chunk_size = 10;
    let tx = test_tx();
    let aa = to_packet_batches(&vec![tx; len], chunk_size);
    let m = Arc::new((aa, None));

    bencher.iter(move || {
        s.send(m.clone()).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_main_thread_overhead_under_sustained_write(bencher: &mut Bencher) {
    let exit = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();
    let tracer = solana_core::banking_trace::BankingTracer::new_with_config(Some((
        std::path::PathBuf::new().join("/tmp/banking-tracer"),
        exit.clone(),
        1024 * 1024, // cause more frequent trace file rotation
    )))
    .unwrap();
    let (s, r) = tracer.create_channel_non_vote();

    std::thread::spawn(move || {
        solana_core::banking_trace::sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
            exit.clone(),
            r,
            |m| {
                test::black_box(m);
                Ok(())
            },
        )
    });

    let len = 4;
    let chunk_size = 10;
    let tx = test_tx();
    let aa = to_packet_batches(&vec![tx; len], chunk_size);
    let m = Arc::new((aa, None));

    bencher.iter(move || {
        s.send(m.clone()).unwrap();
    });
}

#[bench]
fn bench_banking_tracer_background_thread_throughput(bencher: &mut Bencher) {
    let len = 4;
    let chunk_size = 10;
    let tx = test_tx();
    let aa = to_packet_batches(&vec![tx; len], chunk_size);
    let packet_batch = Arc::new((aa, None));

    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    bencher.iter(move || {
        let exit = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();
        let path = base_path.join("banking-trace");

        // make sure fresh setup; otherwise banking tracer appends and rotates
        // trace files created by prior bench iterations.
        solana_core::banking_trace::BankingTracer::ensure_cleanup_path(&path).unwrap();

        let tracer = solana_core::banking_trace::BankingTracer::new_with_config(Some((
            path,
            exit.clone(),
            50 * 1024 * 1024,
        )))
        .unwrap();
        let (dummy_main_sender, dummy_main_receiver) = tracer.create_channel_non_vote();
        let (tracer_join_handle, tracer) = tracer.finalize_under_arc();

        let dummy_main_thread_handle = std::thread::spawn(move || {
            solana_core::banking_trace::sender_overhead_minimized_receiver_loop::<_, TraceError, 0>(
                exit.clone(),
                dummy_main_receiver,
                |packet_batch| {
                    test::black_box(packet_batch);
                    Ok(())
                },
            )
        });

        for _ in 0..1000 {
            dummy_main_sender.send(packet_batch.clone()).unwrap();
        }

        drop(dummy_main_sender);
        drop(tracer);
        dummy_main_thread_handle.join().unwrap().unwrap();
        tracer_join_handle.unwrap().join().unwrap().unwrap();
    });

    drop_and_clean_temp_dir_unless_suppressed(temp_dir);
}
