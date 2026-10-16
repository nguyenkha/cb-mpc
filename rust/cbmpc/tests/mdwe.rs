// MemoryDenyWriteExecute smoke test (Linux): turn on the kernel's MDWE for this test process
// (prctl PR_SET_MDWE, Linux >= 6.3, what systemd's MemoryDenyWriteExecute=yes uses on new
// kernels), check it refuses W+X memory, then run 2P ECDSA + EdDSA DKG/sign and PVE. cb-mpc and
// OpenSSL must never need runtime code generation, or the kexify MPC server could not run with
// MemoryDenyWriteExecute=yes. Own test binary: MDWE cannot be turned off once set.
// Kernels without PR_SET_MDWE skip, unless CBMPC_REQUIRE_MDWE=1 (CI).
#![cfg(target_os = "linux")]
mod common;

use cbmpc::{pve, Curve, EcKey2p, Ecdsa2pKey, NID_ED25519, NID_SECP256K1};
use common::run_2p;

const PR_SET_MDWE: libc::c_int = 65;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;

#[test]
fn protocols_run_with_write_xor_execute_enforced() {
    // SAFETY: plain prctl; affects only this process.
    if unsafe { libc::prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) } != 0 {
        let err = std::io::Error::last_os_error();
        assert!(
            std::env::var("CBMPC_REQUIRE_MDWE").as_deref() != Ok("1"),
            "PR_SET_MDWE failed: {err}"
        );
        eprintln!("skipping MDWE test: {err}");
        return;
    }
    // Control: W+X memory is now refused.
    // SAFETY: anonymous mapping request; unmapped if it unexpectedly succeeds.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p != libc::MAP_FAILED {
        unsafe { libc::munmap(p, 4096) };
        panic!("MDWE is not in effect: a W+X mapping succeeded");
    }

    let (a, b) = run_2p(
        |j| Ecdsa2pKey::dkg(j, NID_SECP256K1),
        |j| Ecdsa2pKey::dkg(j, NID_SECP256K1),
    );
    let (k1, k2) = (a.unwrap(), b.unwrap());
    let x2 = k2.x_share().unwrap();
    let (s1, s2) = run_2p(
        move |j| k1.sign(j, &[1u8; 32], &[&[2u8; 32][..]]),
        move |j| k2.sign(j, &[1u8; 32], &[&[2u8; 32][..]]),
    );
    s1.unwrap();
    s2.unwrap();

    let (a, b) = run_2p(
        |j| EcKey2p::dkg(j, NID_ED25519),
        |j| EcKey2p::dkg(j, NID_ED25519),
    );
    let (k1, k2) = (a.unwrap(), b.unwrap());
    let (s1, s2) = run_2p(
        move |j| k1.eddsa_sign(j, b"m"),
        move |j| k2.eddsa_sign(j, b"m"),
    );
    s1.unwrap();
    s2.unwrap();

    let (ek, _dk) = pve::generate_keypair().unwrap();
    let ct = pve::batch_encrypt(NID_SECP256K1, &ek, b"l", &[&x2]).unwrap();
    let q2 = Curve::new(NID_SECP256K1)
        .unwrap()
        .mul_generator(&x2)
        .unwrap()
        .to_bytes()
        .unwrap();
    pve::batch_verify(NID_SECP256K1, &ek, &ct, &[&q2], b"l").unwrap();
}
