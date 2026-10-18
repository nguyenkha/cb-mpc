// Interop with the released TypeScript package: rust/interop/ts-client.ts (npm cb-mpc 0.6.2, WASM)
// plays the kexify client (P1) and this test plays the server (P2) over the child's stdin/stdout.
// Covers ECDSA-2P DKG + 2-hash batch sign, EdDSA-2P DKG + sign, and keys made entirely by cb-mpc-ts
// (server parts loaded here byte for byte) signing across the pipe. Frames: [tag][len u32 BE][bytes].
//
// Needs `bun` and `bun install` in rust/interop. Without them the test is skipped, unless
// CBMPC_REQUIRE_INTEROP=1 (CI), where a missing setup fails it.
mod common;

use cbmpc::{verify_der, EcKey2p, Ecdsa2pKey, Job2p, Party, Transport, TransportError, Zeroizing};
use cbmpc::{NID_ED25519, NID_SECP256K1};
use common::{parts_ref, NAMES};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Pipe {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Pipe {
    fn write(&mut self, tag: u8, data: &[u8]) -> std::io::Result<()> {
        let mut head = [tag, 0, 0, 0, 0];
        head[1..].copy_from_slice(&(data.len() as u32).to_be_bytes());
        self.stdin.write_all(&head)?;
        self.stdin.write_all(data)?;
        self.stdin.flush()
    }
    fn read(&mut self, tag: u8) -> std::io::Result<Vec<u8>> {
        let mut head = [0u8; 5];
        self.stdout.read_exact(&mut head)?;
        assert_eq!(head[0], tag, "unexpected frame tag from the ts client");
        let mut data = vec![0u8; u32::from_be_bytes(head[1..].try_into().unwrap()) as usize];
        self.stdout.read_exact(&mut data)?;
        Ok(data)
    }
    fn control(&mut self) -> Vec<u8> {
        self.read(b'C').expect("control frame from the ts client")
    }
    fn send_control(&mut self, data: &[u8]) {
        self.write(b'C', data)
            .expect("control frame to the ts client")
    }
}

impl Transport for Pipe {
    fn send(&mut self, _receiver: i32, message: &[u8]) -> Result<(), TransportError> {
        self.write(b'M', message).map_err(|_| TransportError)
    }
    fn receive(&mut self, _sender: i32) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        self.read(b'M')
            .map(Zeroizing::new)
            .map_err(|_| TransportError)
    }
}

fn spawn_client(script: &str) -> Option<Pipe> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../interop");
    let required = std::env::var("CBMPC_REQUIRE_INTEROP").as_deref() == Ok("1");
    if !dir.join("node_modules/cb-mpc").exists() {
        assert!(
            !required,
            "rust/interop has no node_modules: run `bun install` there"
        );
        eprintln!("skipping interop: run `bun install` in rust/interop");
        return None;
    }
    let child = Command::new("bun")
        .arg(script)
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            assert!(!required, "cannot start bun: {e}");
            eprintln!("skipping interop: bun not found ({e})");
            return None;
        }
    };
    let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    // Watchdog: a hung client must not hold the test (and CI) until the job timeout.
    let pid = child.id() as libc::pid_t;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(300));
        // SAFETY: plain signal to our own child; harmless if it already exited.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    });
    Some(Pipe {
        child,
        stdin,
        stdout,
    })
}

/// Rust picks the sid and hashes, both sides sign, and the client's signatures must verify here.
fn ecdsa_sign(p: &mut Pipe, key: &Ecdsa2pKey) {
    let sid = [0x51u8; 32];
    let hashes = [[0x11u8; 32], [0x22u8; 32]];
    p.send_control(&sid);
    hashes.iter().for_each(|h| p.send_control(h));
    let mut job = Job2p::new(p, Party::P2, NAMES).unwrap();
    let mine = key.sign(&mut job, &sid, &[&hashes[0], &hashes[1]]).unwrap();
    drop(job);
    assert!(
        mine.len() == 2 && mine.iter().all(|s| s.is_empty()),
        "P2 gets empty placeholders"
    );
    let pk = key.public_key().unwrap();
    for h in &hashes {
        assert!(
            verify_der(NID_SECP256K1, &pk, h, &p.control()).unwrap(),
            "client ECDSA signature does not verify"
        );
    }
}

fn eddsa_sign(p: &mut Pipe, key: &EcKey2p) {
    let msg = b"kexify interop message";
    p.send_control(msg);
    let mut job = Job2p::new(p, Party::P2, NAMES).unwrap();
    key.eddsa_sign(&mut job, msg).unwrap();
    drop(job);
    assert_eq!(p.control().len(), 64); // the client verified it with @noble/curves
}

/// Sends this side's serialized server share to the client, which must load it (cb-mpc-ts
/// deserialize), get the same public key and re-serialize it byte for byte (recovery mode loads
/// the server share in the browser).
fn send_parts(p: &mut Pipe, parts: &[Zeroizing<Vec<u8>>]) {
    p.send_control(&[parts.len() as u8]);
    parts.iter().for_each(|x| p.send_control(x));
    assert_eq!(
        p.control(),
        [1],
        "the ts client did not load the Rust share"
    );
}

/// Reads `n` parts sent by the client and checks they load and re-serialize byte for byte.
fn read_parts(p: &mut Pipe) -> Vec<Vec<u8>> {
    let n = p.control()[0] as usize;
    (0..n).map(|_| p.control()).collect()
}

#[test]
fn rust_server_party_interoperates_with_cb_mpc_ts_0_6_2() {
    let Some(mut p) = spawn_client("ts-client.ts") else { return };

    // 1-2. ECDSA-2P DKG + batch sign.
    let mut job = Job2p::new(&mut p, Party::P2, NAMES).unwrap();
    let ecdsa = Ecdsa2pKey::dkg(&mut job, NID_SECP256K1).unwrap();
    drop(job);
    assert_eq!(
        p.control(),
        ecdsa.public_key().unwrap(),
        "ECDSA joint public key differs"
    );
    send_parts(&mut p, &ecdsa.serialize().unwrap());
    ecdsa_sign(&mut p, &ecdsa);

    // 3-4. EdDSA-2P DKG + sign.
    let mut job = Job2p::new(&mut p, Party::P2, NAMES).unwrap();
    let eddsa = EcKey2p::dkg(&mut job, NID_ED25519).unwrap();
    drop(job);
    assert_eq!(
        p.control(),
        eddsa.public_key().unwrap(),
        "EdDSA joint public key differs"
    );
    send_parts(&mut p, &eddsa.serialize().unwrap());
    eddsa_sign(&mut p, &eddsa);

    // 5. Server shares written by cb-mpc-ts load here unchanged and sign with the ts client.
    let parts = read_parts(&mut p);
    let ts_ecdsa =
        Ecdsa2pKey::deserialize(&parts.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
    assert_eq!(
        parts_ref(&ts_ecdsa.serialize().unwrap()),
        parts.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    assert_eq!(p.control(), ts_ecdsa.public_key().unwrap());
    let parts = read_parts(&mut p);
    let ts_eddsa =
        EcKey2p::deserialize(&parts.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
    assert_eq!(
        parts_ref(&ts_eddsa.serialize().unwrap()),
        parts.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    assert_eq!(p.control(), ts_eddsa.public_key().unwrap());
    ecdsa_sign(&mut p, &ts_ecdsa);
    eddsa_sign(&mut p, &ts_eddsa);

    assert_eq!(p.control(), b"done");
    assert!(p.child.wait().unwrap().success(), "ts client failed");
}

/// One sign over the pipe as P2 with `key`; returns whether the client (P1, which verifies) succeeded.
fn signed_ok(p: &mut Pipe, sign: impl FnOnce(&mut Job2p) -> cbmpc::Result<()>) -> bool {
    let mut job = Job2p::new(p, Party::P2, NAMES).unwrap();
    // P2 sends the last message in both protocols, so its own result says nothing about the pair.
    let _ = sign(&mut job);
    drop(job);
    p.control() == [1]
}

/// Refresh with ts-refresh-client.ts (P1, WASM; a local cb-mpc-ts build via CBMPC_TS_DIR until a release
/// has ecKey2pRefresh): the key stays, new shares sign, and both old/new mixes fail, on both curves.
#[test]
fn rust_server_party_refreshes_with_cb_mpc_ts() {
    let Some(mut p) = spawn_client("ts-refresh-client.ts") else { return };
    if p.control() == b"skip" {
        assert!(
            std::env::var("CBMPC_REQUIRE_INTEROP").as_deref() != Ok("1"),
            "the ts client has no ecKey2pRefresh: set CBMPC_TS_DIR to a cb-mpc-ts build"
        );
        eprintln!("skipping refresh interop: set CBMPC_TS_DIR to a cb-mpc-ts build with ecKey2pRefresh");
        return;
    }
    let runs: usize = std::env::var("REFRESH_BENCH_RUNS").map_or(3, |v| v.parse().unwrap());
    let (sid, hash, msg) = ([0x61u8; 32], [0x33u8; 32], b"kexify refresh");

    // ECDSA-2P.
    let mut job = Job2p::new(&mut p, Party::P2, NAMES).unwrap();
    let old = Ecdsa2pKey::dkg(&mut job, NID_SECP256K1).unwrap();
    drop(job);
    let pk = old.public_key().unwrap();
    assert_eq!(p.control(), pk);
    let mut cur = Ecdsa2pKey::deserialize(&parts_ref(&old.serialize().unwrap())).unwrap();
    for _ in 0..runs {
        let mut job = Job2p::new(&mut p, Party::P2, NAMES).unwrap();
        cur = cur.refresh(&mut job).unwrap();
        drop(job);
        assert_eq!(cur.public_key().unwrap(), pk);
        assert_eq!(cur.role_index().unwrap(), 1);
        assert_eq!(p.control(), pk, "client public key changed by the refresh");
    }
    assert!(signed_ok(&mut p, |j| cur.sign(j, &sid, &[&hash[..]]).map(|_| ())), "ECDSA new + new must sign");
    assert!(!signed_ok(&mut p, |j| cur.sign(j, &sid, &[&hash[..]]).map(|_| ())), "ECDSA old client + new server must fail");
    assert!(!signed_ok(&mut p, |j| old.sign(j, &sid, &[&hash[..]]).map(|_| ())), "ECDSA new client + old server must fail");

    // EdDSA-2P.
    let mut job = Job2p::new(&mut p, Party::P2, NAMES).unwrap();
    let old = EcKey2p::dkg(&mut job, NID_ED25519).unwrap();
    drop(job);
    let pk = old.public_key().unwrap();
    assert_eq!(p.control(), pk);
    let mut cur = EcKey2p::deserialize(&parts_ref(&old.serialize().unwrap())).unwrap();
    for _ in 0..runs {
        let mut job = Job2p::new(&mut p, Party::P2, NAMES).unwrap();
        cur = cur.refresh(&mut job).unwrap();
        drop(job);
        assert_eq!(cur.public_key().unwrap(), pk);
        assert_eq!(cur.role_index().unwrap(), 1);
        assert_eq!(p.control(), pk, "client public key changed by the refresh");
    }
    assert!(signed_ok(&mut p, |j| cur.eddsa_sign(j, msg).map(|_| ())), "EdDSA new + new must sign");
    assert!(!signed_ok(&mut p, |j| cur.eddsa_sign(j, msg).map(|_| ())), "EdDSA old client + new server must fail");
    assert!(!signed_ok(&mut p, |j| old.eddsa_sign(j, msg).map(|_| ())), "EdDSA new client + old server must fail");

    assert_eq!(p.control(), b"done");
    assert!(p.child.wait().unwrap().success(), "ts refresh client failed");
}
