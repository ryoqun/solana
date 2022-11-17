use std::{
    sync::{Condvar, Mutex},
    time::Duration,
};

// encapsulate complications of unneeded mutex and Condvar to give us event behavior of wait and notify
// this will likely be wrapped in an arc somehow
#[derive(Default, Debug)]
pub struct WaitableCondvar {
    pub mutex: Mutex<u8>,
    pub event: Condvar,
}

impl WaitableCondvar {
    pub fn notify_all(&self) {
        self.event.notify_all();
    }
    pub fn notify_one(&self) {
        self.event.notify_one();
    }
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let lock = self.mutex.lock().unwrap();
        let res = self.event.wait_timeout(lock, timeout).unwrap();
        if res.1.timed_out() {
            return true;
        }
        false
    }
}
