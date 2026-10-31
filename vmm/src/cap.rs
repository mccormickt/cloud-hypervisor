// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Linux capability management for the in-process AF_XDP backend.
//!
//! The AF_XDP backend loads its XDP redirect program and populates `xsks_map`
//! during device creation (`Vm::new`), which needs `CAP_BPF` and
//! `CAP_NET_ADMIN`. Socket creation also needs `CAP_NET_RAW`. The bound
//! datapath needs none of these capabilities. [`drop_xdp_caps`] removes setup
//! authority before vCPU/worker threads start, including during restore.
//!
//! Capabilities are per-thread on Linux. This drops them on the current (vmm)
//! thread only; threads spawned afterwards inherit the reduced set, but
//! long-lived helper threads already running keep their capabilities. A full
//! process-wide drop is a follow-up (see `docs/af_xdp.md`).
//!
//! This is hand-rolled over `libc` (`capget`/`capset`/`prctl`) to avoid a new
//! crate dependency. The libc version in use does not expose the capability
//! structs, so they are declared here.

use std::cell::Cell;
use std::env::consts;
use std::io;

use seccompiler::{SeccompAction, SeccompFilter, apply_filter};

thread_local! {
    static BPF_RESTRICTED: Cell<bool> = const { Cell::new(false) };
}

/// `CAP_NET_ADMIN` from `<linux/capability.h>`. Dropped (used for BPF/XDP
/// program attach).
const CAP_NET_ADMIN: u32 = 12;
/// `CAP_BPF` from `<linux/capability.h>`. Dropped (used for `bpf()` syscalls).
const CAP_BPF: u32 = 39;
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_SETPCAP: u32 = 8;

/// `_LINUX_CAPABILITY_VERSION_3`: 64-bit capabilities in two 32-bit words.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
/// Number of `CapUserData` words for `_LINUX_CAPABILITY_VERSION_3`.
const LINUX_CAPABILITY_U32S_3: usize = 2;

/// The capabilities the AF_XDP backend drops once the program is loaded.
const DROPPED_CAPS: [u32; 5] = [
    CAP_BPF,
    CAP_NET_ADMIN,
    CAP_NET_RAW,
    CAP_SYS_ADMIN,
    CAP_SETPCAP,
];

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

fn capability_data() -> io::Result<[CapUserData; LINUX_CAPABILITY_U32S_3]> {
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

    Ok(data)
}

/// Rejects attempts to recreate privileged AF_XDP resources in a restricted VMM.
pub(crate) fn check_xdp_setup() -> io::Result<()> {
    if BPF_RESTRICTED.get() {
        return Err(io::Error::other(
            "AF_XDP setup requires a fresh VMM process",
        ));
    }
    let data = capability_data()?;
    for cap in [CAP_BPF, CAP_NET_ADMIN] {
        if data[(cap / 32) as usize].effective & (1 << (cap % 32)) == 0 {
            return Err(io::Error::other(
                "AF_XDP setup requires CAP_BPF and CAP_NET_ADMIN in a fresh VMM process",
            ));
        }
    }
    Ok(())
}

/// Drops setup authority before guest-facing threads are created.
pub(crate) fn drop_xdp_caps() -> io::Result<()> {
    let mut data = capability_data()?;
    // SAFETY: valid PR_SET_NO_NEW_PRIVS arguments; the result is checked.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Modifying the bounding set requires CAP_SETPCAP. File-capability launches
    // need not have it: clearing permitted/inheritable sets plus no_new_privs
    // still prevents reacquisition through exec.
    if data[0].effective & (1 << CAP_SETPCAP) != 0 {
        for cap in DROPPED_CAPS {
            // SAFETY: valid PR_CAPBSET_DROP arguments; the result is checked.
            let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    clear_caps(&mut data, &DROPPED_CAPS);
    let header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };

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

    Ok(())
}

/// Blocks all BPF operations, including updates through existing map FDs.
/// The filter is inherited by subsequently created guest-facing threads.
pub(crate) fn restrict_bpf() -> io::Result<()> {
    if BPF_RESTRICTED.get() {
        return Ok(());
    }
    let filter: seccompiler::BpfProgram = SeccompFilter::new(
        [(libc::SYS_bpf, Vec::new())].into(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        consts::ARCH.try_into().unwrap(),
    )
    .and_then(|filter| filter.try_into())
    .map_err(io::Error::other)?;
    apply_filter(&filter).map_err(io::Error::other)?;
    BPF_RESTRICTED.set(true);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    #[cfg(feature = "kvm")]
    use crate::seccomp_filters::{Thread, get_seccomp_filter};

    #[test]
    fn capability_drop_and_bpf_filter_are_inherited() {
        thread::spawn(|| {
            let before = capability_data().unwrap();
            #[cfg(feature = "kvm")]
            {
                let filter = get_seccomp_filter(
                    &SeccompAction::Errno(libc::EACCES as u32),
                    Thread::Vmm,
                    Some(hypervisor::HypervisorType::Kvm),
                )
                .unwrap();
                apply_filter(&filter).unwrap();
            }
            drop_xdp_caps().unwrap();
            restrict_bpf().unwrap();
            assert!(check_xdp_setup().is_err());
            let check = move || {
                let after = capability_data().unwrap();
                for cap in [8u32, 12, 13, 21, 39] {
                    let word = (cap / 32) as usize;
                    let bit = 1 << (cap % 32);
                    assert_eq!(after[word].effective & bit, 0);
                    assert_eq!(after[word].permitted & bit, 0);
                    assert_eq!(after[word].inheritable & bit, 0);
                }
                assert_eq!(
                    after[0].effective & (1 << 10),
                    before[0].effective & (1 << 10)
                );
                // SAFETY: an invalid BPF command with no attribute pointer.
                let result = unsafe { libc::syscall(libc::SYS_bpf, u32::MAX, 0, 0) };
                assert_eq!(result, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            };
            check();
            thread::spawn(check).join().unwrap();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn bpf_filter_blocks_even_with_setup_capabilities() {
        thread::spawn(|| {
            let data = capability_data().unwrap();
            if data[1].effective & (1 << (39 - 32)) != 0 {
                // SAFETY: invalid command, no attribute pointer. A privileged
                // unfiltered caller receives EINVAL rather than EPERM.
                assert_eq!(unsafe { libc::syscall(libc::SYS_bpf, u32::MAX, 0, 0) }, -1);
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINVAL)
                );
            }
            restrict_bpf().unwrap();
            // SAFETY: invalid command, no attribute pointer.
            assert_eq!(unsafe { libc::syscall(libc::SYS_bpf, u32::MAX, 0, 0) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        })
        .join()
        .unwrap();
    }

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

        // CAP_NET_RAW (13) is only needed to create sockets.
        let net_raw_bit = 1u32 << (CAP_NET_RAW % 32);
        assert_eq!(data[0].effective & net_raw_bit, 0);
        assert_eq!(data[0].permitted & net_raw_bit, 0);
        assert_eq!(data[0].inheritable & net_raw_bit, 0);

        let dropped_low = net_admin_bit | net_raw_bit | (1 << CAP_SYS_ADMIN) | (1 << CAP_SETPCAP);
        assert_eq!(data[0].effective, !dropped_low);
        // No other bit in word 1 was touched: only bit 7 should differ from MAX.
        assert_eq!(data[1].effective, !bpf_bit);
    }
}
