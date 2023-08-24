use {
    crate::{
        cluster_info::{ClusterInfo, GOSSIP_SLEEP_MILLIS},
        crds::Cursor,
        duplicate_shred::DuplicateShred,
    },
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, sleep, Builder, JoinHandle},
        time::Duration,
    },
};

pub trait DuplicateShredHandlerTrait: Send {
    fn handle(&mut self, data: DuplicateShred);
}

pub struct DuplicateShredListener {
    thread_hdl: JoinHandle<()>,
}

// Right now we only need to process duplicate proof, in the future the receiver
// should be a map from enum value to handlers.
impl DuplicateShredListener {
    pub fn new(
        exit: Arc<AtomicBool>,
        cluster_info: Arc<ClusterInfo>,
        handler: impl DuplicateShredHandlerTrait + 'static,
    ) -> Self {
        let listen_thread = Builder::new()
            .name("solCiEntryLstnr".to_string())
            .spawn(move || {
                Self::recv_loop(exit, &cluster_info, handler);
            })
            .unwrap();

        Self {
            thread_hdl: listen_thread,
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }

    // Here we are sending data one by one rather than in a batch because in the future
    // we may send different type of CrdsData to different senders.
    fn recv_loop(
        exit: Arc<AtomicBool>,
        cluster_info: &ClusterInfo,
        mut handler: impl DuplicateShredHandlerTrait + 'static,
    ) {
        let mut cursor = Cursor::default();
        while !exit.load(Ordering::Relaxed) {
            let entries: Vec<DuplicateShred> = cluster_info.get_duplicate_shreds(&mut cursor);
            for x in entries {
                handler.handle(x);
            }
            sleep(Duration::from_millis(GOSSIP_SLEEP_MILLIS));
        }
    }
}

