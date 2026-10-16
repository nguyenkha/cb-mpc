// Builds cb-mpc + the cb-mpc-ts C ABI as a static library with the repo's own CMake build
// (cb-mpc-ts/native, CBMPC_NATIVE_STATIC=ON) and links it with a static OpenSSL 3.6.4.
//
// OpenSSL is not built here (it needs a download): point CBMPC_OPENSSL_ROOT at a build made by
// scripts/openssl/build-static-openssl-{linux,macos-m1}.sh (default /usr/local/opt/openssl@3.6.4,
// the scripts' install prefix). Only libcrypto.a is used.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest
        .join("../..")
        .canonicalize()
        .expect("cb-mpc repo root");
    let native = root.join("cb-mpc-ts/native");

    println!("cargo:rerun-if-env-changed=CBMPC_OPENSSL_ROOT");
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

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let mut cfg = cmake::Config::new(&native);
    cfg.define("CBMPC_NATIVE_STATIC", "ON")
        .define("CBMPC_OPENSSL_ROOT", &openssl)
        // The library's own flags already carry -O3 -DNDEBUG; keep a release build in debug cargo profiles too.
        .profile("Release")
        .build_target("cbmpc");
    if target_os == "macos" {
        cfg.define("CMAKE_CXX_COMPILER", "clang++");
    }
    let dst = cfg.build();

    let lib_dir =
        find_archive(&dst.join("build")).expect("libcbmpc.a not produced by the CMake build");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=cbmpc");
    println!("cargo:rustc-link-search=native={}", crypto_dir.display());
    println!("cargo:rustc-link-lib=static=crypto");
    match target_os.as_str() {
        "macos" => println!("cargo:rustc-link-lib=dylib=c++"),
        _ => {
            println!("cargo:rustc-link-lib=dylib=stdc++");
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=dl");
        }
    }
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
