// Benchmark: both 2P parties in this process (two threads over channels), cb-mpc via the Rust
// crates. Same ops and output as rust/bench/ts-bench.ts so the backends compare 1:1.
// Usage: cargo run --release --example bench -- [runs_dkg] [runs_sign]
// Prints one JSON line per op ({backend, op, runs, median_ms, p95_ms}) and one with peak RSS.

use cbmpc::{EcKey2p, Ecdsa2pKey, Job2p, Party, Transport, TransportError, Zeroizing};
use cbmpc::{NID_ED25519, NID_SECP256K1};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

const NAMES: [&str; 2] = ["client", "server"];

struct Chan(Sender<Vec<u8>>, Receiver<Vec<u8>>);
impl Transport for Chan {
    fn send(&mut self, _: i32, m: &[u8]) -> Result<(), TransportError> {
        self.0.send(m.to_vec()).map_err(|_| TransportError)
    }
    fn receive(&mut self, _: i32) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        self.1
            .recv()
            .map(Zeroizing::new)
            .map_err(|_| TransportError)
    }
}

/// Runs one protocol with P1 and P2 on two threads; returns both results and the wall time.
fn run2<A: Send + 'static, B: Send + 'static>(
    p1: impl FnOnce(&mut Job2p) -> A + Send + 'static,
    p2: impl FnOnce(&mut Job2p) -> B + Send + 'static,
) -> (A, B, f64) {
    let (a_tx, b_rx) = channel();
    let (b_tx, a_rx) = channel();
    let start = Instant::now();
    let h1 = std::thread::spawn(move || {
        perf_thread();
        let mut t = Chan(a_tx, a_rx);
        let mut job = Job2p::new(&mut t, Party::P1, NAMES).unwrap();
        p1(&mut job)
    });
    let h2 = std::thread::spawn(move || {
        perf_thread();
        let mut t = Chan(b_tx, b_rx);
        let mut job = Job2p::new(&mut t, Party::P2, NAMES).unwrap();
        p2(&mut job)
    });
    let (a, b) = (h1.join().unwrap(), h2.join().unwrap());
    (a, b, start.elapsed().as_secs_f64() * 1000.0)
}

/// macOS schedules threads by QoS (efficiency vs performance cores); raise bench threads to
/// user-initiated so the numbers are not E-core numbers. No-op elsewhere.
fn perf_thread() {
    #[cfg(target_os = "macos")]
    // SAFETY: sets the calling thread's own QoS class.
    unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0);
    }
}

fn report(op: &str, mut ms: Vec<f64>) {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |q: f64| ms[((ms.len() as f64 - 1.0) * q).round() as usize];
    println!(
        "{{\"backend\":\"rust\",\"op\":\"{op}\",\"runs\":{},\"median_ms\":{:.2},\"p95_ms\":{:.2}}}",
        ms.len(),
        pick(0.5),
        pick(0.95)
    );
}

fn peak_rss_mb() -> f64 {
    // SAFETY: plain getrusage on this process.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let raw = ru.ru_maxrss as f64; // bytes on macOS, KiB on Linux
    if cfg!(target_os = "macos") {
        raw / 1048576.0
    } else {
        raw / 1024.0
    }
}

fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let (n_dkg, n_sign) = (
        args.first().copied().unwrap_or(10),
        args.get(1).copied().unwrap_or(30),
    );

    let mut dkg = vec![];
    let mut key = None;
    for _ in 0..n_dkg {
        let (a, b, ms) = run2(
            |j| Ecdsa2pKey::dkg(j, NID_SECP256K1).unwrap(),
            |j| Ecdsa2pKey::dkg(j, NID_SECP256K1).unwrap(),
        );
        dkg.push(ms);
        key = Some((a, b));
    }
    report("ecdsa_dkg", dkg);
    // Keys move into each run's threads and come back (Send, not Sync).
    let (mut k1, mut k2) = key.unwrap();
    for batch in [1usize, 10] {
        let mut t = vec![];
        for i in 0..n_sign {
            // Distinct digests below the curve order q (cb-mpc rejects a message >= q; real hashes
            // are, with probability ~2^-128): byte 0 is 0x01.
            let hashes: Vec<[u8; 32]> = (0..batch)
                .map(|j| {
                    let mut h = [(i * 31 + j) as u8; 32];
                    h[0] = 1;
                    h
                })
                .collect();
            let sid = [i as u8; 32];
            let (h1, h2) = (hashes.clone(), hashes);
            let (a, b, ms) = run2(
                move |j| {
                    k1.sign(j, &sid, &h1.iter().map(|h| &h[..]).collect::<Vec<_>>())
                        .unwrap();
                    k1
                },
                move |j| {
                    k2.sign(j, &sid, &h2.iter().map(|h| &h[..]).collect::<Vec<_>>())
                        .unwrap();
                    k2
                },
            );
            (k1, k2) = (a, b);
            t.push(ms);
        }
        report(&format!("ecdsa_sign_{batch}"), t);
    }

    let mut dkg = vec![];
    let mut key = None;
    for _ in 0..n_dkg {
        let (a, b, ms) = run2(
            |j| EcKey2p::dkg(j, NID_ED25519).unwrap(),
            |j| EcKey2p::dkg(j, NID_ED25519).unwrap(),
        );
        dkg.push(ms);
        key = Some((a, b));
    }
    report("eddsa_dkg", dkg);
    let (mut e1, mut e2) = key.unwrap();
    let mut t = vec![];
    for i in 0..n_sign {
        let msg = [i as u8; 32];
        let (a, b, ms) = run2(
            move |j| {
                e1.eddsa_sign(j, &msg).unwrap();
                e1
            },
            move |j| {
                e2.eddsa_sign(j, &msg).unwrap();
                e2
            },
        );
        (e1, e2) = (a, b);
        t.push(ms);
    }
    report("eddsa_sign", t);
    println!(
        "{{\"backend\":\"rust\",\"peak_rss_mb\":{:.1},\"cpus\":{}}}",
        peak_rss_mb(),
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
}
