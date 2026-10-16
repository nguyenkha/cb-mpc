// In-process 2-party ECDSA + EdDSA: DKG, batch sign, serialize round trip, key info, PVE.
mod common;

use cbmpc::{
    pve, verify_der, Curve, EcKey2p, Ecdsa2pKey, Error, Job2p, Party, Transport, TransportError,
    Zeroizing,
};
use cbmpc::{NID_ED25519, NID_SECP256K1, TRANSPORT_PANIC};
use common::{parts_ref, run_2p};

fn ecdsa_pair() -> (Ecdsa2pKey, Ecdsa2pKey) {
    let (a, b) = run_2p(
        |j| Ecdsa2pKey::dkg(j, NID_SECP256K1),
        |j| Ecdsa2pKey::dkg(j, NID_SECP256K1),
    );
    (a.unwrap(), b.unwrap())
}

#[test]
fn ecdsa_dkg_batch_sign_and_reload() {
    let (k1, k2) = ecdsa_pair();
    assert_eq!(k1.public_key().unwrap(), k2.public_key().unwrap());
    assert_eq!((k1.role_index().unwrap(), k2.role_index().unwrap()), (0, 1));
    assert_eq!(k2.curve_code().unwrap(), NID_SECP256K1);

    // Reload P2 from its serialized parts: same bytes after a round trip (6 parts, cb-mpc-ts layout).
    let parts = k2.serialize().unwrap();
    assert_eq!(parts.len(), 6);
    let k2 = Ecdsa2pKey::deserialize(&parts_ref(&parts)).unwrap();
    let again = k2.serialize().unwrap();
    assert_eq!(parts_ref(&again), parts_ref(&parts));

    let pubkey = k1.public_key().unwrap();
    let hashes: Vec<[u8; 32]> = vec![[7u8; 32], [9u8; 32]];
    let sid = [3u8; 32];
    let h1 = hashes.clone();
    let (s1, s2) = run_2p(
        move |j| k1.sign(j, &sid, &h1.iter().map(|h| &h[..]).collect::<Vec<_>>()),
        move |j| k2.sign(j, &sid, &[&[7u8; 32][..], &[9u8; 32][..]]),
    );
    let (s1, s2) = (s1.unwrap(), s2.unwrap());
    assert_eq!(s1.len(), 2);
    for (sig, h) in s1.iter().zip(&hashes) {
        assert!(verify_der(NID_SECP256K1, &pubkey, h, sig).unwrap());
    }
    // P2 gets empty placeholders, one per hash (cb-mpc hands the signatures to P1 only).
    assert_eq!(s2.len(), 2);
    assert!(s2.iter().all(|s| s.is_empty()));
}

#[test]
fn eddsa_dkg_sign_and_reload() {
    let (a, b) = run_2p(
        |j| EcKey2p::dkg(j, NID_ED25519),
        |j| EcKey2p::dkg(j, NID_ED25519),
    );
    let (k1, k2) = (a.unwrap(), b.unwrap());
    let pk = k1.public_key().unwrap();
    assert_eq!(pk, k2.public_key().unwrap());
    assert_eq!(pk.len(), 65);
    let parts = k2.serialize().unwrap();
    assert_eq!(parts.len(), 4);
    let k2 = EcKey2p::deserialize(&parts_ref(&parts)).unwrap();
    let (s1, s2) = run_2p(
        move |j| k1.eddsa_sign(j, b"kexify"),
        move |j| k2.eddsa_sign(j, b"kexify"),
    );
    let s1 = s1.unwrap();
    s2.unwrap();
    assert_eq!(s1.len(), 64);
}

#[test]
fn pve_round_trip_on_the_server_share() {
    let (_, k2) = ecdsa_pair();
    let x2 = k2.x_share().unwrap();
    let curve = Curve::new(NID_SECP256K1).unwrap();
    let q2 = curve.mul_generator(&x2).unwrap().to_bytes().unwrap();
    let (ek, dk) = pve::generate_keypair().unwrap();
    let ct = pve::batch_encrypt(NID_SECP256K1, &ek, b"label", &[&x2]).unwrap();
    pve::batch_verify(NID_SECP256K1, &ek, &ct, &[&q2], b"label").unwrap();
    assert!(pve::batch_verify(NID_SECP256K1, &ek, &ct, &[&q2], b"other").is_err());
    let xs = pve::batch_decrypt(NID_SECP256K1, &dk, &ek, &ct, b"label").unwrap();
    // Compare as integers (the decrypted scalar may be encoded at another length).
    let trim = |b: &[u8]| {
        b.iter()
            .skip_while(|x| **x == 0)
            .copied()
            .collect::<Vec<_>>()
    };
    assert_eq!(trim(&xs[0]), trim(&x2));
}

#[test]
fn a_key_used_on_the_other_partys_job_is_refused_before_the_protocol() {
    let (k1, _) = ecdsa_pair();
    let mut t = Closed;
    let mut job = Job2p::new(&mut t, Party::P2, common::NAMES).unwrap();
    let err = k1
        .sign(&mut job, &[0u8; 32], &[&[1u8; 32][..]])
        .err()
        .unwrap();
    assert_eq!(err.code, cbmpc::ROLE_MISMATCH);
}

#[test]
fn bad_parts_are_rejected() {
    assert!(Ecdsa2pKey::deserialize(&[&[1, 2, 3][..]]).is_err());
    assert!(EcKey2p::deserialize(&[&[0u8; 4][..]; 4]).is_err());
}

struct Panicking;
impl Transport for Panicking {
    fn send(&mut self, _: i32, _: &[u8]) -> Result<(), TransportError> {
        panic!("transport bug")
    }
    fn receive(&mut self, _: i32) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        panic!("transport bug")
    }
}

#[test]
fn a_panicking_transport_fails_the_run_instead_of_unwinding_into_cpp() {
    let mut t = Panicking;
    let mut job = Job2p::new(&mut t, Party::P1, common::NAMES).unwrap();
    let err = Ecdsa2pKey::dkg(&mut job, NID_SECP256K1).err().unwrap();
    assert_eq!(
        err,
        Error {
            op: "mpc_ecdsa2p_dkg",
            code: TRANSPORT_PANIC
        }
    );
}

struct Closed;
impl Transport for Closed {
    fn send(&mut self, _: i32, _: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }
    fn receive(&mut self, _: i32) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        Err(TransportError)
    }
}

#[test]
fn a_closed_transport_fails_the_run() {
    let mut t = Closed;
    let mut job = Job2p::new(&mut t, Party::P2, common::NAMES).unwrap();
    assert!(EcKey2p::dkg(&mut job, NID_ED25519).is_err());
}
