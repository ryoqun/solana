use log::*;
use crossbeam_channel::bounded;
use crossbeam_channel::unbounded;

#[derive(Default, Debug)]
struct ExecutionEnvironment {
    accounts: Vec<i8>,
}

fn main() {
    solana_logger::setup();
    error!("hello");
    let (s, r) = unbounded();

    let mut joins = (0..10).map(|_| {
        let s = s.clone();
        std::thread::spawn(move || {
            loop {
                s.send(ExecutionEnvironment::default()).unwrap();
            }
        })
    }).collect::<Vec<_>>();
    joins.push(std::thread::spawn(move || {
        error!("{:?}", r.recv());
    }));
    joins.into_iter().for_each(|j| j.join().unwrap());
}
