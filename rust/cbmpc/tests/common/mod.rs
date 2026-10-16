// In-process 2-party network: each party gets a Transport over std channels, and `run_2p` runs
// one closure per party on its own thread (cb-mpc blocks inside receive).
#![allow(dead_code)]

use cbmpc::{Job2p, Party, Transport, TransportError, Zeroizing};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

pub const NAMES: [&str; 2] = ["client", "server"];

pub struct ChannelTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl Transport for ChannelTransport {
    fn send(&mut self, _receiver: i32, message: &[u8]) -> Result<(), TransportError> {
        self.tx.send(message.to_vec()).map_err(|_| TransportError)
    }
    fn receive(&mut self, _sender: i32) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        self.rx
            .recv_timeout(Duration::from_secs(60))
            .map(Zeroizing::new)
            .map_err(|_| TransportError)
    }
}

pub fn pair() -> (ChannelTransport, ChannelTransport) {
    let (a_tx, b_rx) = channel();
    let (b_tx, a_rx) = channel();
    (
        ChannelTransport { tx: a_tx, rx: a_rx },
        ChannelTransport { tx: b_tx, rx: b_rx },
    )
}

/// Runs `p1` as P1 and `p2` as P2 concurrently and returns both results.
pub fn run_2p<A: Send + 'static, B: Send + 'static>(
    p1: impl FnOnce(&mut Job2p) -> A + Send + 'static,
    p2: impl FnOnce(&mut Job2p) -> B + Send + 'static,
) -> (A, B) {
    let (mut t1, mut t2) = pair();
    let h1 = std::thread::spawn(move || {
        let mut job = Job2p::new(&mut t1, Party::P1, NAMES).unwrap();
        p1(&mut job)
    });
    let h2 = std::thread::spawn(move || {
        let mut job = Job2p::new(&mut t2, Party::P2, NAMES).unwrap();
        p2(&mut job)
    });
    (h1.join().unwrap(), h2.join().unwrap())
}

pub fn parts_ref(parts: &[Zeroizing<Vec<u8>>]) -> Vec<&[u8]> {
    parts.iter().map(|p| p.as_slice()).collect()
}
