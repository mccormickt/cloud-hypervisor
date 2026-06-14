// Copyright © 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Build script for `net_util`.
//!
//! When the `net_backend_af_xdp` feature is enabled, this compiles the
//! standalone `xdp-ebpf` crate to a BPF object that is embedded into the binary
//! at compile time (see `src/bpf.rs`). The heavy work is gated on the feature so
//! default builds — and CI, which never enables it — need neither a nightly
//! toolchain nor `bpf-linker`.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");

    #[cfg(feature = "net_backend_af_xdp")]
    build_xdp_ebpf();
}

#[cfg(feature = "net_backend_af_xdp")]
fn build_xdp_ebpf() {
    use std::env;
    use std::path::PathBuf;

    use aya_build::{Package, Toolchain, build_ebpf};

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let ebpf_dir = manifest_dir.join("xdp-ebpf");
    let root_dir = ebpf_dir
        .to_str()
        .expect("xdp-ebpf path is not valid UTF-8")
        .to_owned();

    // `xdp-ebpf` is excluded from the Cloud Hypervisor workspace and forms its
    // own one-package workspace. Run the nested cargo from inside it so that
    // `aya-build`'s `cargo build --package xdp-ebpf` resolves the crate. OUT_DIR
    // (where the object is emitted) is absolute, so it is unaffected.
    env::set_current_dir(&ebpf_dir).expect("failed to chdir into xdp-ebpf");

    build_ebpf(
        [Package {
            name: "xdp-ebpf",
            root_dir: &root_dir,
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )
    .expect("failed to build xdp-ebpf");
}
