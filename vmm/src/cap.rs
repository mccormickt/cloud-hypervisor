// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Linux capability management for the in-process AF_XDP backend.
//!
//! The AF_XDP backend loads its XDP redirect program and populates `xsks_map`
//! during device creation (`Vm::new`), which needs `CAP_BPF` and
//! `CAP_NET_ADMIN`. After that the running guest's datapath only needs
//! `CAP_NET_RAW`. [`drop_xdp_caps`] removes `CAP_BPF` and `CAP_NET_ADMIN` from
//! the calling thread before the vCPU/worker threads are spawned, so those
//! guest-facing threads inherit the reduced capability set.
//!
//! Capabilities are per-thread on Linux. This drops them on the current (vmm)
//! thread only; threads spawned afterwards inherit the reduced set, but
//! long-lived helper threads already running keep their capabilities. A full
//! process-wide drop is a follow-up (see `docs/af_xdp.md`).
//!
//! This is hand-rolled over `libc` (`capget`/`capset`/`prctl`) to avoid a new
//! crate dependency. The libc version in use does not expose the capability
//! structs, so they are declared here.

use std::io;

/// `CAP_NET_ADMIN` from `<linux/capability.h>`. Dropped (used for BPF/XDP
/// program attach).
const CAP_NET_ADMIN: u32 = 12;
/// `CAP_BPF` from `<linux/capability.h>`. Dropped (used for `bpf()` syscalls).
const CAP_BPF: u32 = 39;

/// `_LINUX_CAPABILITY_VERSION_3`: 64-bit capabilities in two 32-bit words.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
/// Number of `CapUserData` words for `_LINUX_CAPABILITY_VERSION_3`.
const LINUX_CAPABILITY_U32S_3: usize = 2;

/// The capabilities the AF_XDP backend drops once the program is loaded.
/// `CAP_NET_RAW` (13) and everything else are retained.
const DROPPED_CAPS: [u32; 2] = [CAP_BPF, CAP_NET_ADMIN];

/// Mirrors `struct __user_cap_header_struct` from `<linux/capability.h>`.
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

/// Mirrors `struct __user_cap_data_struct` from `<linux/capability.h>`. One per
/// 32-bit capability window; `data[0]` holds caps 0–31, `data[1]` holds 32–63.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Clears each capability in `caps` from the effective, permitted, and
/// inheritable sets of `data`. Pure bit math, split out so it is unit-testable
/// without privilege.
fn clear_caps(data: &mut [CapUserData], caps: &[u32]) {
    for &cap in caps {
        let word = (cap / 32) as usize;
        let bit = 1u32 << (cap % 32);
        if let Some(slot) = data.get_mut(word) {
            slot.effective &= !bit;
            slot.permitted &= !bit;
            slot.inheritable &= !bit;
        }
    }
}

/// Drops `CAP_BPF` and `CAP_NET_ADMIN` from the calling thread, retaining
/// `CAP_NET_RAW` (and everything else) for the AF_XDP datapath.
///
/// Must run on the vmm thread before any vCPU/worker thread is spawned so that
/// those threads inherit the reduced set.
pub fn drop_xdp_caps() -> io::Result<()> {
    let mut header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        // pid 0 targets the calling thread.
        pid: 0,
    };
    let mut data = [CapUserData::default(); LINUX_CAPABILITY_U32S_3];

    // SAFETY: `header` is a valid `__user_cap_header_struct` and `data` is an
    // array of `LINUX_CAPABILITY_U32S_3` `__user_cap_data_struct`s, matching the
    // version in the header. capget only writes into `data`. The return value is
    // checked below.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapUserHeader,
            data.as_mut_ptr(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    clear_caps(&mut data, &DROPPED_CAPS);

    // SAFETY: same struct layout/version contract as the capget call above;
    // capset only reads `header`/`data`. The return value is checked below.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapUserHeader,
            data.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Remove the dropped caps from the bounding set so they cannot be
    // re-acquired via a setuid-root exec.
    for cap in DROPPED_CAPS {
        // SAFETY: PR_CAPBSET_DROP takes the capability number in arg2; remaining
        // prctl args are ignored. The return value is checked.
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // Belt-and-braces alongside the seccomp filter: prevent privilege gain
    // through exec. Harmless if already set.
    // SAFETY: PR_SET_NO_NEW_PRIVS takes 1 in arg2; remaining args ignored. The
    // return value is checked.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CAP_NET_RAW` from `<linux/capability.h>`; must be retained.
    const CAP_NET_RAW: u32 = 13;

    #[test]
    fn clears_only_targeted_caps() {
        // Start with every capability bit set in all three sets.
        let mut data = [CapUserData {
            effective: u32::MAX,
            permitted: u32::MAX,
            inheritable: u32::MAX,
        }; LINUX_CAPABILITY_U32S_3];

        clear_caps(&mut data, &DROPPED_CAPS);

        // CAP_NET_ADMIN (12) lives in word 0, bit 12; it must be cleared.
        let net_admin_bit = 1u32 << (CAP_NET_ADMIN % 32);
        assert_eq!(data[0].effective & net_admin_bit, 0);
        assert_eq!(data[0].permitted & net_admin_bit, 0);
        assert_eq!(data[0].inheritable & net_admin_bit, 0);

        // CAP_BPF (39) lives in word 1, bit 7; it must be cleared.
        let bpf_bit = 1u32 << (CAP_BPF % 32);
        assert_eq!((CAP_BPF / 32) as usize, 1);
        assert_eq!(data[1].effective & bpf_bit, 0);
        assert_eq!(data[1].permitted & bpf_bit, 0);
        assert_eq!(data[1].inheritable & bpf_bit, 0);

        // CAP_NET_RAW (13) lives in word 0, bit 13; it must be retained.
        let net_raw_bit = 1u32 << (CAP_NET_RAW % 32);
        assert_eq!(data[0].effective & net_raw_bit, net_raw_bit);
        assert_eq!(data[0].permitted & net_raw_bit, net_raw_bit);
        assert_eq!(data[0].inheritable & net_raw_bit, net_raw_bit);

        // No other bit in word 0 was touched: only bit 12 should differ from MAX.
        assert_eq!(data[0].effective, u32::MAX & !net_admin_bit);
        // No other bit in word 1 was touched: only bit 7 should differ from MAX.
        assert_eq!(data[1].effective, u32::MAX & !bpf_bit);
    }
}
