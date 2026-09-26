// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! In-process loader for the AF_XDP redirect program.
//!
//! [`XdpProgram`] loads the eBPF object embedded at build time (see
//! `build.rs`/`xdp-ebpf`), attaches it to the host interface, and exposes its
//! `xsks_map` so the datapath can register one [`Xsk`] per queue. All of this
//! runs at device creation, while Cloud Hypervisor still holds
//! `CAP_BPF`/`CAP_NET_ADMIN`; the map is populated before those capabilities are
//! dropped, so the running guest never depends on `bpf()`.
//!
//! The `Ebpf` handle is kept alive for the device's lifetime: dropping it
//! detaches the program and frees the map.

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use aya::maps::{MapData, MapError, XskMap};
use aya::programs::{ProgramError, Xdp};
use aya::{Ebpf, EbpfLoader};
use thiserror::Error;

use crate::xsk::Xsk;

/// The XDP redirect object, compiled and embedded by `build.rs`. The file name
/// matches the `xdp-redirect` bin target of the `xdp-ebpf` crate.
static PROGRAM_BYTES: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp-redirect"));

/// Name of the `XskMap` static in the eBPF program.
const MAP_NAME: &str = "XSKS_MAP";
/// Name of the `#[xdp]` redirect function in the eBPF program.
const PROGRAM_NAME: &str = "xdp_redirect";
/// Name of the `#[xdp]` pass-through function in the eBPF program.
const PASS_PROGRAM_NAME: &str = "xdp_pass";

#[derive(Error, Debug)]
pub enum XdpProgramError {
    #[error("Failed to load the embedded XDP redirect program")]
    Load(#[source] aya::EbpfError),
    #[error("XDP redirect program is missing the {0:?} map")]
    MissingMap(&'static str),
    #[error("Failed to access the {0:?} map")]
    Map(&'static str, #[source] MapError),
    #[error("XDP redirect program is missing the {0:?} program")]
    MissingProgram(&'static str),
    #[error("Failed to access the {0:?} program")]
    Program(&'static str, #[source] ProgramError),
    #[error("Failed to load the {0:?} program into the kernel")]
    ProgramLoad(&'static str, #[source] ProgramError),
    #[error("Failed to create an FD-owned XDP link on {0:?}")]
    Attach(String, #[source] io::Error),
    #[error("Failed to insert XSK fd for queue {0} into the xsks_map")]
    InsertXsk(u32, #[source] MapError),
}

/// How the XDP redirect program attaches to the host interface.
#[derive(Clone, Copy, Debug, Default)]
pub enum XdpAttachMode {
    /// Let the kernel pick native (driver) mode, falling back to generic (SKB)
    /// mode if the driver has no native XDP support.
    #[default]
    Auto,
    /// Request generic (SKB) mode. Requires kernel support for FD-owned links.
    Skb,
}

/// A loaded-and-attached XDP redirect program plus its `xsks_map` handle.
pub struct XdpProgram {
    // Keeps the loaded program(s) and their attach links alive. Dropping this
    // detaches the program(s) and unloads them. Must outlive the device.
    _ebpf: Ebpf,
    // Owned handle to the program's `xsks_map`. Inserting an XSK fd operates on
    // this map fd and requires no privileged capability, so it stays usable
    // after CAP_BPF is dropped.
    xsks_map: XskMap<MapData>,
    // Closing an FD-owned link detaches without CAP_NET_ADMIN.
    _link: OwnedFd,
    _pass_link: Option<OwnedFd>,
}

impl XdpProgram {
    /// Loads the embedded program and attaches the redirect to `iface`.
    ///
    /// When `peer` is `Some`, a no-op pass-through program is also attached to
    /// it. AF_XDP redirect on a `veth` pair only works when both ends have an
    /// XDP program loaded, so the peer (which carries the host-side traffic)
    /// gets the pass program. For a real NIC, pass `None`.
    pub fn load_and_attach(
        iface: &str,
        peer: Option<&str>,
        mode: XdpAttachMode,
    ) -> Result<Self, XdpProgramError> {
        let mut ebpf = EbpfLoader::new()
            .load(PROGRAM_BYTES)
            .map_err(XdpProgramError::Load)?;

        // Take ownership of the map before loading the program. The map already
        // exists in the kernel (created during `load`), so the program's
        // relocation still resolves to it.
        let xsks_map: XskMap<MapData> = ebpf
            .take_map(MAP_NAME)
            .ok_or(XdpProgramError::MissingMap(MAP_NAME))?
            .try_into()
            .map_err(|e| XdpProgramError::Map(MAP_NAME, e))?;

        let program: &mut Xdp = ebpf
            .program_mut(PROGRAM_NAME)
            .ok_or(XdpProgramError::MissingProgram(PROGRAM_NAME))?
            .try_into()
            .map_err(|e| XdpProgramError::Program(PROGRAM_NAME, e))?;
        program
            .load()
            .map_err(|e| XdpProgramError::ProgramLoad(PROGRAM_NAME, e))?;
        let link = attach(program, iface, mode)?;

        let pass_link = match peer {
            Some(peer) => {
                let pass: &mut Xdp = ebpf
                    .program_mut(PASS_PROGRAM_NAME)
                    .ok_or(XdpProgramError::MissingProgram(PASS_PROGRAM_NAME))?
                    .try_into()
                    .map_err(|e| XdpProgramError::Program(PASS_PROGRAM_NAME, e))?;
                pass.load()
                    .map_err(|e| XdpProgramError::ProgramLoad(PASS_PROGRAM_NAME, e))?;
                Some(attach(pass, peer, mode)?)
            }
            None => None,
        };

        Ok(Self {
            _ebpf: ebpf,
            xsks_map,
            _link: link,
            _pass_link: pass_link,
        })
    }

    /// Registers a bound [`Xsk`] in `xsks_map[queue_id]` so the redirect program
    /// steers traffic on that RX queue into the socket.
    pub fn insert_xsk(&mut self, queue_id: u32, xsk: &Xsk) -> Result<(), XdpProgramError> {
        self.xsks_map
            .set(queue_id, xsk.as_raw_fd(), 0)
            .map_err(|e| XdpProgramError::InsertXsk(queue_id, e))
    }
}

/// Attaches `program` to `iface`, honoring [`XdpAttachMode`].
fn attach(program: &mut Xdp, iface: &str, mode: XdpAttachMode) -> Result<OwnedFd, XdpProgramError> {
    // Linux UAPI bpf_attr.link_create prefix. All optional fields are zero
    // because the kernel zero-extends the supplied attribute size.
    #[repr(C)]
    struct LinkCreate {
        prog_fd: u32,
        target_ifindex: u32,
        attach_type: u32,
        flags: u32,
    }
    const BPF_LINK_CREATE: libc::c_uint = 28;
    const BPF_XDP: u32 = 37;
    const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;

    let attach_err = |e| XdpProgramError::Attach(iface.to_owned(), e);
    let ifindex = crate::iface_index(iface).map_err(|e| attach_err(io::Error::other(e)))?;
    let fd = program.fd().map_err(|e| attach_err(io::Error::other(e)))?;
    let create = |flags| {
        let attr = LinkCreate {
            prog_fd: fd.as_fd().as_raw_fd() as u32,
            target_ifindex: ifindex,
            attach_type: BPF_XDP,
            flags,
        };
        // SAFETY: attr matches the Linux UAPI prefix and is valid for the
        // supplied size. A successful call returns a new owned descriptor.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_LINK_CREATE,
                &attr,
                size_of::<LinkCreate>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: the successful syscall returned a new owned FD.
            Ok(unsafe { OwnedFd::from_raw_fd(result as libc::c_int) })
        }
    };
    // Never use legacy netlink attachment: its cleanup requires capabilities
    // that the VMM drops before guest execution.
    match mode {
        XdpAttachMode::Auto => create(0).or_else(|_| create(XDP_FLAGS_SKB_MODE)),
        XdpAttachMode::Skb => create(XDP_FLAGS_SKB_MODE),
    }
    .map_err(attach_err)
}
