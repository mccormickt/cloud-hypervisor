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
//! The program, map, and FD-owned links stay alive for the device's lifetime.
//! Closing the links detaches the programs without setup capabilities.

use std::io;
use std::os::fd::AsRawFd;

use aya::maps::{MapData, MapError, XskMap};
use aya::programs::links::FdLink;
use aya::programs::{ProgramError, Xdp, XdpMode};
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
    // Keeps the loaded programs alive for the device's lifetime.
    _ebpf: Ebpf,
    // Populate the map before the VMM installs its BPF-denying filter.
    xsks_map: XskMap<MapData>,
    // Closing an FD-owned link detaches without CAP_NET_ADMIN.
    _link: FdLink,
    _pass_link: Option<FdLink>,
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
fn attach(program: &Xdp, iface: &str, mode: XdpAttachMode) -> Result<FdLink, XdpProgramError> {
    let attach_err = |e| XdpProgramError::Attach(iface.to_owned(), e);
    let ifindex = crate::iface_index(iface).map_err(|e| attach_err(io::Error::other(e)))?;
    // Never use legacy netlink attachment: its cleanup requires capabilities
    // that the VMM drops before guest execution.
    match mode {
        XdpAttachMode::Auto => program
            .attach_to_if_index_fd(ifindex, XdpMode::Default)
            .or_else(|_| program.attach_to_if_index_fd(ifindex, XdpMode::Skb)),
        XdpAttachMode::Skb => program.attach_to_if_index_fd(ifindex, XdpMode::Skb),
    }
    .map_err(|e| attach_err(io::Error::other(e)))
}
