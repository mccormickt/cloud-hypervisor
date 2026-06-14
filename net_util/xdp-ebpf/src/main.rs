// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! XDP redirect program for the in-process AF_XDP virtio-net backend.
//!
//! For every received packet, this looks up the AF_XDP socket bound to the
//! packet's RX queue in `XSKS_MAP` and redirects the packet to it. Packets on
//! queues with no registered socket are passed up the normal kernel stack
//! (`XDP_PASS`), so the program is safe to attach to a shared interface.
//!
//! The userspace loader (`net_util::XdpProgram`) populates
//! `XSKS_MAP[queue_id]` with one XSK fd per queue while Cloud Hypervisor still
//! holds `CAP_BPF`/`CAP_NET_ADMIN`, before the guest runs.
//!
//! This crate is excluded from the Cloud Hypervisor workspace: it is compiled
//! for `bpfel-unknown-none` with `-Z build-std=core` by `net_util`'s feature
//! gated `build.rs` (via `aya-build`) and embedded into the binary.

#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::XskMap;
use aya_ebpf::programs::XdpContext;

/// One entry per NIC combined queue. Sized to cover typical multi-queue NICs;
/// the loader only ever inserts indices `0..num_queue_pairs`.
const MAX_QUEUES: u32 = 64;

#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(MAX_QUEUES, 0);

#[xdp]
fn xdp_redirect(ctx: XdpContext) -> u32 {
    let queue_id = ctx.rx_queue_index();
    // `XskMap::get` returns the stored queue id for a registered socket; a match
    // means an XSK is bound to this queue, so redirect the packet to it.
    // Otherwise let the packet continue up the normal network stack.
    if XSKS_MAP.get(queue_id) == Some(queue_id) {
        XSKS_MAP
            .redirect(queue_id, 0)
            .unwrap_or(xdp_action::XDP_ABORTED)
    } else {
        xdp_action::XDP_PASS
    }
}

/// A no-op program that passes every packet up the normal stack.
///
/// Used on the *peer* of a `veth` pair: AF_XDP redirect on `veth` only works
/// when both ends of the pair have an XDP program attached, so the peer (which
/// carries the host-side traffic we must not intercept) gets this pass program.
#[xdp]
fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

// eBPF targets are `no_std` and must provide a panic handler. The body is never
// reached (the program is panic-free); the verifier rejects any program that
// could fall into this infinite loop, which is the intended fail-closed result.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
