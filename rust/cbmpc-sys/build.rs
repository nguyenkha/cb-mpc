// Links cb-mpc + the cb-mpc-ts C ABI (libcbmpc.a) and static OpenSSL 3.6.4 (libcrypto.a).
//
// Where they come from, first match wins:
//   1. CBMPC_NATIVE_DIR=<dir>  an unpacked native artifact (lib/libcbmpc.a, lib/libcrypto.a), e.g.
//      from a native-release.yml run; nothing is downloaded or compiled.
//   2. CBMPC_FROM_SOURCE=1 or CBMPC_SRC=<cb-mpc checkout>  build from source with CMake
//      (cb-mpc-ts/native, CBMPC_NATIVE_STATIC=ON), OpenSSL from CBMPC_OPENSSL_ROOT
//      (scripts/openssl/build-static-openssl-*.sh; default /usr/local/opt/openssl@3.6.4).
//   3. Default: download the release artifact pinned in prebuilt.rs for this target from the
//      nguyenkha/cb-mpc GitHub release and check its sha256 before use. No C++ compile.
//      Targets or versions without a pinned artifact fall back to 2 (with a warning).

use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

include!("prebuilt.rs");

fn main() {
    for var in [
        "CBMPC_NATIVE_DIR",
        "CBMPC_FROM_SOURCE",
        "CBMPC_SRC",
        "CBMPC_OPENSSL_ROOT",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rerun-if-changed=prebuilt.rs");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let (cbmpc_dir, crypto_dir) = if let Ok(dir) = env::var("CBMPC_NATIVE_DIR") {
        artifact_dirs(Path::new(&dir))
    } else if env::var("CBMPC_FROM_SOURCE").as_deref() == Ok("1") || env::var("CBMPC_SRC").is_ok() {
        build_from_source(&target_os)
    } else if let Some((platform, sha256)) = pinned_artifact() {
        artifact_dirs(&download(platform, sha256))
    } else {
        println!(
            "cargo:warning=cbmpc-sys: no prebuilt cb-mpc artifact pinned for {} (release tag '{}'); building from source",
            env::var("TARGET").unwrap(),
            PREBUILT_TAG
        );
        build_from_source(&target_os)
    };

    println!("cargo:rustc-link-search=native={}", cbmpc_dir.display());
    println!("cargo:rustc-link-lib=static=cbmpc");
    println!("cargo:rustc-link-search=native={}", crypto_dir.display());
    println!("cargo:rustc-link-lib=static=crypto");
    match target_os.as_str() {
        "macos" | "ios" => println!("cargo:rustc-link-lib=dylib=c++"),
        _ => {
            println!("cargo:rustc-link-lib=dylib=stdc++");
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=dl");
        }
    }
}

/// The artifact platform name for the Rust target, if native-release.yml builds one.
fn platform() -> Option<&'static str> {
    match env::var("TARGET").unwrap().as_str() {
        "x86_64-unknown-linux-gnu" => Some("linux-x64"),
        "aarch64-apple-darwin" => Some("darwin-arm64"),
        _ => None,
    }
}

fn pinned_artifact() -> Option<(&'static str, &'static str)> {
    let platform = platform()?;
    if PREBUILT_TAG.is_empty() {
        return None;
    }
    PREBUILT
        .iter()
        .find(|(p, _)| *p == platform)
        .map(|(p, sha)| (*p, *sha))
}

fn artifact_dirs(dir: &Path) -> (PathBuf, PathBuf) {
    let lib = dir.join("lib");
    for f in ["libcbmpc.a", "libcrypto.a"] {
        assert!(lib.join(f).exists(), "{} has no lib/{f}", dir.display());
    }
    (lib.clone(), lib)
}

/// Downloads cbmpc-native-<platform>.tar.gz of PREBUILT_TAG into OUT_DIR, checks its sha256 and
/// unpacks it. Uses the system `curl` and `tar` (no network crates in the build).
fn download(platform: &str, sha256: &str) -> PathBuf {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let name = format!("cbmpc-native-{platform}");
    let tarball = out.join(format!("{name}.tar.gz"));
    let dir = out.join(&name);
    if dir.join("lib/libcbmpc.a").exists() && file_sha256(&tarball).as_deref() == Some(sha256) {
        return dir;
    }
    let url = format!("{PREBUILT_BASE_URL}/{PREBUILT_TAG}/{name}.tar.gz");
    let status = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&tarball)
        .arg(&url)
        .status();
    assert!(
        matches!(status, Ok(s) if s.success()),
        "cbmpc-sys: downloading {url} failed; build offline with CBMPC_NATIVE_DIR or CBMPC_FROM_SOURCE=1"
    );
    let got = file_sha256(&tarball).unwrap_or_default();
    if got != sha256 {
        let _ = std::fs::remove_file(&tarball);
        panic!("cbmpc-sys: sha256 mismatch for {url}: got {got}, pinned {sha256}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&out)
        .status();
    assert!(
        matches!(status, Ok(s) if s.success()),
        "cbmpc-sys: unpacking {} failed",
        tarball.display()
    );
    dir
}

fn file_sha256(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// CMake build of cb-mpc-ts/native (CBMPC_NATIVE_STATIC=ON) in CBMPC_SRC or this repo.
fn build_from_source(target_os: &str) -> (PathBuf, PathBuf) {
    let root = match env::var("CBMPC_SRC") {
        Ok(src) => PathBuf::from(src),
        Err(_) => PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../.."),
    }
    .canonicalize()
    .expect("cb-mpc source root");
    for dir in [
        "src/cbmpc",
        "include",
        "include-internal",
        "cb-mpc-ts/capi",
        "cb-mpc-ts/binding.cpp",
        "cb-mpc-ts/native/CMakeLists.txt",
        "cmake",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(dir).display());
    }

    let openssl = PathBuf::from(
        env::var("CBMPC_OPENSSL_ROOT").unwrap_or_else(|_| "/usr/local/opt/openssl@3.6.4".into()),
    );
    let crypto_dir = ["lib64", "lib"]
        .iter()
        .map(|d| openssl.join(d))
        .find(|d| d.join("libcrypto.a").exists())
        .unwrap_or_else(|| {
            panic!(
                "static OpenSSL not found under {} (lib/ or lib64/libcrypto.a). Build it with \
                 scripts/openssl/build-static-openssl-*.sh and set CBMPC_OPENSSL_ROOT.",
                openssl.display()
            )
        });

    let mut cfg = cmake::Config::new(root.join("cb-mpc-ts/native"));
    cfg.define("CBMPC_NATIVE_STATIC", "ON")
        .define("CBMPC_OPENSSL_ROOT", &openssl)
        // The library's own flags carry -O3 -DNDEBUG; keep a release build in debug cargo profiles too.
        .profile("Release")
        .build_target("cbmpc");
    if target_os == "macos" {
        cfg.define("CMAKE_CXX_COMPILER", "clang++");
    }
    let dst = cfg.build();
    let lib_dir =
        find_archive(&dst.join("build")).expect("libcbmpc.a not produced by the CMake build");
    (lib_dir, crypto_dir)
}

/// The directory holding libcbmpc.a (CMake puts it at the top of the build tree; generators may nest it).
fn find_archive(dir: &Path) -> Option<PathBuf> {
    if dir.join("libcbmpc.a").exists() {
        return Some(dir.to_path_buf());
    }
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.path().is_dir())
        .find_map(|e| find_archive(&e.path()))
}
