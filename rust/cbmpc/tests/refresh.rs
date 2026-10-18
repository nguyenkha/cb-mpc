// 2-party key refresh for ECDSA-2P and EdDSA-2P: same public key, new shares sign, a pair that
// mixes an old and a new share fails, and a share used in the other party's seat is refused.
mod common;

use cbmpc::{verify_der, EcKey2p, Ecdsa2pKey, Job2p, NID_ED25519, NID_SECP256K1};
use common::{parts_ref, run_2p};

const SID: [u8; 32] = [5u8; 32];
const HASH: [u8; 32] = [7u8; 32];

/// Independent copy of a share (keys are Send, not Sync) via the serialized form.
trait Copy2p: Sized {
    fn copy(&self) -> Self;
}
impl Copy2p for Ecdsa2pKey {
    fn copy(&self) -> Self {
        Ecdsa2pKey::deserialize(&parts_ref(&self.serialize().unwrap())).unwrap()
    }
}
impl Copy2p for EcKey2p {
    fn copy(&self) -> Self {
        EcKey2p::deserialize(&parts_ref(&self.serialize().unwrap())).unwrap()
    }
}
fn ec<T: Copy2p>(k: &T) -> T {
    k.copy()
}

fn ecdsa_dkg() -> (Ecdsa2pKey, Ecdsa2pKey) {
    let (a, b) = run_2p(
        |j| Ecdsa2pKey::dkg(j, NID_SECP256K1),
        |j| Ecdsa2pKey::dkg(j, NID_SECP256K1),
    );
    (a.unwrap(), b.unwrap())
}

fn ecdsa_refresh(k1: Ecdsa2pKey, k2: Ecdsa2pKey) -> (Ecdsa2pKey, Ecdsa2pKey) {
    let (a, b) = run_2p(move |j| k1.refresh(j), move |j| k2.refresh(j));
    (a.unwrap(), b.unwrap())
}

/// Signs HASH; returns P1's result (P1 verifies P2's proof and receives the signature).
fn ecdsa_sign(k1: Ecdsa2pKey, k2: Ecdsa2pKey) -> cbmpc::Result<Vec<u8>> {
    let (s1, _s2) = run_2p(
        move |j| k1.sign(j, &SID, &[&HASH[..]]),
        move |j| k2.sign(j, &SID, &[&HASH[..]]),
    );
    s1.map(|mut v| v.remove(0))
}

#[test]
fn ecdsa_refresh_keeps_the_key_and_old_new_shares_do_not_mix() {
    let (o1, o2) = ecdsa_dkg();
    let pk = o1.public_key().unwrap();
    let (n1, n2) = ecdsa_refresh(ec(&o1), ec(&o2));

    assert_eq!(n1.public_key().unwrap(), pk);
    assert_eq!(n2.public_key().unwrap(), pk);
    assert_eq!((n1.role_index().unwrap(), n2.role_index().unwrap()), (0, 1));
    assert_ne!(*n1.x_share().unwrap(), *o1.x_share().unwrap());
    assert_ne!(*n2.x_share().unwrap(), *o2.x_share().unwrap());

    let sig = ecdsa_sign(ec(&n1), ec(&n2)).unwrap();
    assert!(verify_der(NID_SECP256K1, &pk, &HASH, &sig).unwrap());

    assert!(ecdsa_sign(ec(&o1), ec(&n2)).is_err(), "old P1 + new P2 must fail");
    assert!(ecdsa_sign(ec(&n1), ec(&o2)).is_err(), "new P1 + old P2 must fail");

    // A second refresh chains on the first.
    let (m1, m2) = ecdsa_refresh(n1, n2);
    let sig = ecdsa_sign(m1, m2).unwrap();
    assert!(verify_der(NID_SECP256K1, &pk, &HASH, &sig).unwrap());
}

fn eddsa_dkg() -> (EcKey2p, EcKey2p) {
    let (a, b) = run_2p(
        |j| EcKey2p::dkg(j, NID_ED25519),
        |j| EcKey2p::dkg(j, NID_ED25519),
    );
    (a.unwrap(), b.unwrap())
}

fn eddsa_refresh(k1: EcKey2p, k2: EcKey2p) -> (EcKey2p, EcKey2p) {
    let (a, b) = run_2p(move |j| k1.refresh(j), move |j| k2.refresh(j));
    (a.unwrap(), b.unwrap())
}

/// P1's result: P1 assembles and verifies the signature.
fn eddsa_sign(k1: EcKey2p, k2: EcKey2p) -> cbmpc::Result<Vec<u8>> {
    let (s1, _s2) = run_2p(
        move |j| k1.eddsa_sign(j, b"kexify refresh"),
        move |j| k2.eddsa_sign(j, b"kexify refresh"),
    );
    s1
}

#[test]
fn eddsa_refresh_keeps_the_key_and_old_new_shares_do_not_mix() {
    let (o1, o2) = eddsa_dkg();
    let pk = o1.public_key().unwrap();
    let (n1, n2) = eddsa_refresh(ec(&o1), ec(&o2));

    assert_eq!(n1.public_key().unwrap(), pk);
    assert_eq!(n2.public_key().unwrap(), pk);
    assert_eq!((n1.role_index().unwrap(), n2.role_index().unwrap()), (0, 1));
    assert_ne!(*n1.x_share().unwrap(), *o1.x_share().unwrap());
    assert_ne!(*n2.x_share().unwrap(), *o2.x_share().unwrap());

    assert_eq!(eddsa_sign(ec(&n1), ec(&n2)).unwrap().len(), 64);
    assert!(eddsa_sign(ec(&o1), ec(&n2)).is_err(), "old P1 + new P2 must fail");
    assert!(eddsa_sign(ec(&n1), ec(&o2)).is_err(), "new P1 + old P2 must fail");

    let (m1, m2) = eddsa_refresh(n1, n2);
    assert_eq!(eddsa_sign(m1, m2).unwrap().len(), 64);
}

#[test]
fn refresh_with_a_share_of_the_other_seat_is_refused() {
    let (e1, _) = ecdsa_dkg();
    let (d1, _) = eddsa_dkg();
    // A P1 share on a P2 job: refused by the Rust role check before any message is sent.
    let mut t = common::pair().0;
    let mut job = Job2p::new(&mut t, cbmpc::Party::P2, common::NAMES).unwrap();
    assert!(e1.refresh(&mut job).is_err());
    assert!(d1.refresh(&mut job).is_err());
}
