// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! AF_XDP (XSK) datapath wrapper for the in-process virtio-net backend.
//!
//! This module is a thin layer over the [`aya::xsk`] socket API. It owns the
//! UMEM backing memory, manages the RX/TX frame pools, and exposes the
//! ring operations the [`crate::XdpQueuePair`] copy core needs.
//!
//! # Privilege model
//!
//! The XDP redirect program and its `xsks_map` are loaded in-process by
//! [`crate::bpf::XdpProgram`] while CH still holds `CAP_BPF`/`CAP_NET_ADMIN`
//! (at device creation). This module only performs the `CAP_NET_RAW` half:
//! it creates and binds the [`aya::xsk::XskSocket`] and drives its rings. Each
//! bound socket fd is inserted into `xsks_map[queue_id]` via
//! [`crate::bpf::XdpProgram::insert_xsk`] before the privileged capabilities are
//! dropped, so the datapath never depends on `bpf()`.

use std::collections::VecDeque;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::{self, NonNull};

use aya::xsk::{XskError, XskSocket, XskSocketConfig, XskUmem, XskUmemConfig};
use thiserror::Error;

use crate::XDP_FRAME_SIZE;

// `sockaddr_xdp::sxdp_flags` bits, from `linux/if_xdp.h`. Defined locally to
// avoid taking a dependency on `aya_obj`'s generated bindings.
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

#[derive(Error, Debug)]
pub enum XdpError {
    #[error("Failed to mmap UMEM region")]
    Mmap(#[source] io::Error),
    #[error("AF_XDP socket error")]
    Xsk(#[from] XskError),
    #[error("Interface {0:?} not found")]
    UnknownInterface(String),
    #[error("Failed to query interface")]
    Interface(#[source] io::Error),
}

/// Parameters for building an [`Xsk`].
#[derive(Clone, Copy, Debug)]
pub struct XdpSocketConfig {
    /// UMEM frame size in bytes (aligned-chunk mode).
    pub frame_size: u32,
    /// RX ring size (descriptors).
    pub rx_size: u32,
    /// TX ring size (descriptors).
    pub tx_size: u32,
    /// FILL ring size (descriptors). Also the number of RX frames.
    pub fill_size: u32,
    /// COMPLETION ring size (descriptors).
    pub completion_size: u32,
    /// Request zero-copy mode. Falls back to copy at bind time on drivers
    /// without zero-copy support.
    pub zerocopy: bool,
}

impl Default for XdpSocketConfig {
    fn default() -> Self {
        Self {
            frame_size: XDP_FRAME_SIZE,
            rx_size: 2048,
            tx_size: 2048,
            fill_size: 2048,
            completion_size: 2048,
            zerocopy: false,
        }
    }
}

/// A page-aligned anonymous memory region backing a UMEM.
///
/// The kernel writes received packets into this region asynchronously while a
/// socket is bound to it, so it must outlive the [`XskSocket`] that registered
/// it. Field ordering in [`Xsk`] guarantees the socket drops first.
struct MmapRegion {
    ptr: NonNull<u8>,
    len: usize,
}

impl MmapRegion {
    fn new(len: usize) -> Result<Self, XdpError> {
        // SAFETY: a fresh anonymous mapping with a NULL hint; the kernel picks a
        // page-aligned address. We check for `MAP_FAILED` below.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(XdpError::Mmap(io::Error::last_os_error()));
        }
        Ok(Self {
            // SAFETY: `mmap` returned a non-NULL, page-aligned pointer.
            ptr: unsafe { NonNull::new_unchecked(ptr.cast::<u8>()) },
            len,
        })
    }

    fn as_slice_ptr(&self) -> NonNull<[u8]> {
        NonNull::slice_from_raw_parts(self.ptr, self.len)
    }
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` describe the mapping created in `new`, and the
        // owning `XskSocket` has already been dropped (field order in `Xsk`).
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast::<libc::c_void>(), self.len);
        }
    }
}

/// An AF_XDP socket bound to one netdev queue, with its UMEM frame pools.
///
/// Frames `[0, fill_size)` form the RX pool (cycled FILL → RX → FILL); frames
/// `[fill_size, fill_size + tx_size)` form the TX pool (handed to the TX ring
/// and reclaimed via the COMPLETION ring).
pub struct Xsk {
    // `socket` must be declared before `umem_mem`: it owns the registered UMEM
    // and must be dropped (closing the fd and unmapping the rings) before the
    // backing memory is unmapped.
    socket: XskSocket,
    // Held purely so its `Drop` munmaps the UMEM backing after `socket`.
    #[expect(dead_code, reason = "RAII guard; unmaps the UMEM backing on drop")]
    umem_mem: MmapRegion,
    frame_size: u32,
    /// RX frames currently published to the FILL ring, in submission order.
    /// FILL is consumed and RX produced in the same order on a single queue, so
    /// the i-th received packet corresponds to `fill_fifo[i]`.
    fill_fifo: VecDeque<u32>,
    /// RX frames the caller has reclaimed and not yet returned to FILL.
    rx_pool: Vec<u32>,
    /// Free TX frame indices.
    tx_free: Vec<u32>,
}

// SAFETY: `Xsk` is moved to exactly one virtio worker thread and accessed only
// from there. The raw pointers it transitively holds (the UMEM mapping and the
// XSK ring mappings) are never shared with another thread.
unsafe impl Send for Xsk {}

impl Xsk {
    /// Creates and binds an AF_XDP socket on `(ifindex, queue_id)` and primes
    /// the FILL ring with the RX frame pool.
    pub fn new(ifindex: u32, queue_id: u32, config: XdpSocketConfig) -> Result<Self, XdpError> {
        let frame_size = config.frame_size;
        let frame_count = config.fill_size + config.tx_size;
        let len = frame_count as usize * frame_size as usize;

        let umem_mem = MmapRegion::new(len)?;
        let umem_config = XskUmemConfig {
            frame_size,
            headroom: 0,
            flags: 0,
        };
        // SAFETY: `umem_mem` is page-aligned (from `mmap`), exactly `frame_count`
        // frames long, owned exclusively by this `Xsk` for its lifetime, and not
        // aliased by any other reference while the socket is bound.
        let umem = unsafe { XskUmem::new(umem_config, umem_mem.as_slice_ptr()) }?;

        let mut bind_flags = XDP_USE_NEED_WAKEUP;
        bind_flags |= if config.zerocopy {
            XDP_ZEROCOPY
        } else {
            XDP_COPY
        };

        let socket_config = XskSocketConfig {
            rx_size: config.rx_size,
            tx_size: config.tx_size,
            fill_size: config.fill_size,
            completion_size: config.completion_size,
            bind_flags,
        };
        let mut socket = XskSocket::new(umem, ifindex, queue_id, socket_config)?;

        let rx_frames: Vec<u32> = (0..config.fill_size).collect();
        let tx_free: Vec<u32> = (config.fill_size..frame_count).collect();

        let submitted = socket.fill(rx_frames.iter().copied())? as usize;
        let mut fill_fifo = VecDeque::with_capacity(rx_frames.len());
        fill_fifo.extend(rx_frames[..submitted].iter().copied());
        let rx_pool = rx_frames[submitted..].to_vec();

        Ok(Self {
            socket,
            umem_mem,
            frame_size,
            fill_fifo,
            rx_pool,
            tx_free,
        })
    }

    /// The number of received packets currently available to read.
    pub fn rx_available(&self) -> u32 {
        self.socket.rx_available()
    }

    /// The bytes of the `index`-th available received packet (raw L2 frame).
    pub fn rx_peek(&self, index: u32) -> Option<&[u8]> {
        self.socket.rx_peek(index)
    }

    /// Releases the `n` oldest received descriptors and recycles their frames
    /// into the RX pool for later refilling.
    pub fn rx_release(&mut self, n: u32) {
        for _ in 0..n {
            if let Some(idx) = self.fill_fifo.pop_front() {
                self.rx_pool.push(idx);
            }
        }
        self.socket.rx_release(n);
    }

    /// Returns reclaimed RX frames to the FILL ring and wakes the driver if
    /// required (zero-copy + need-wakeup mode).
    pub fn refill(&mut self) -> Result<(), XdpError> {
        if !self.rx_pool.is_empty() {
            let submitted = self.socket.fill(self.rx_pool.iter().copied())? as usize;
            self.fill_fifo.extend(self.rx_pool.drain(..submitted));
        }
        self.socket.wake_rx()?;
        Ok(())
    }

    /// Reclaims completed TX frames back into the free pool.
    pub fn complete(&mut self) -> u32 {
        let Self {
            socket,
            tx_free,
            frame_size,
            ..
        } = self;
        let frame_size = u64::from(*frame_size);
        socket.complete(|addr| tx_free.push((addr / frame_size) as u32))
    }

    /// Pops a free TX frame, returning its `(index, umem_addr)`.
    pub fn tx_alloc(&mut self) -> Option<(u32, u64)> {
        let index = self.tx_free.pop()?;
        let addr = self.socket.umem().frame_addr(index).ok()?;
        Some((index, addr))
    }

    /// Returns a free TX frame to the pool (e.g. when the TX ring was full).
    pub fn tx_recycle(&mut self, index: u32) {
        self.tx_free.push(index);
    }

    /// A mutable view of the UMEM frame at `addr` for `len` bytes.
    pub fn tx_frame_mut(&mut self, addr: u64, len: u32) -> Option<&mut [u8]> {
        self.socket.tx_frame_mut(addr, len)
    }

    /// Enqueues one frame on the TX ring. Returns `false` if the ring was full.
    pub fn transmit(&mut self, addr: u64, len: u32) -> Result<bool, XdpError> {
        Ok(self.socket.transmit([(addr, len)])? == 1)
    }

    /// Wakes the kernel to process the TX ring.
    pub fn kick(&mut self) -> Result<(), XdpError> {
        self.socket.kick()?;
        Ok(())
    }
}

impl AsRawFd for Xsk {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Builds an `ifreq` with `ifr_name` set to `name` for an interface ioctl.
fn ifreq_for(name: &str) -> Result<libc::ifreq, XdpError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(XdpError::UnknownInterface(name.to_string()));
    }
    // SAFETY: `ifreq` is plain integer/array fields, so a zeroed value is valid.
    let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in ifreq.ifr_name.iter_mut().zip(name_bytes) {
        *dst = *src as libc::c_char;
    }
    Ok(ifreq)
}

/// Resolves an interface name to its kernel ifindex via `SIOCGIFINDEX`.
///
/// Uses the ioctl directly (rather than `if_nametoindex`) so the call site is
/// deterministic under the VMM seccomp filter, which allowlists `SIOCGIFINDEX`.
pub fn iface_index(name: &str) -> Result<u32, XdpError> {
    let sock = crate::create_unix_socket()
        .map_err(|_| XdpError::Interface(io::Error::other("failed to create query socket")))?;
    let mut ifreq = ifreq_for(name)?;

    // SAFETY: ioctl with a valid socket fd and a correctly-sized `ifreq`; the
    // return value is checked.
    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFINDEX, &mut ifreq) };
    if ret < 0 {
        return Err(XdpError::Interface(io::Error::last_os_error()));
    }
    // SAFETY: the ioctl succeeded and populated the `ifru_ifindex` union field.
    let index = unsafe { ifreq.ifr_ifru.ifru_ifindex };
    if index <= 0 {
        return Err(XdpError::UnknownInterface(name.to_string()));
    }
    Ok(index as u32)
}

/// Queries an interface's MTU via `SIOCGIFMTU`.
pub fn iface_mtu(name: &str) -> Result<u16, XdpError> {
    let sock = crate::create_unix_socket()
        .map_err(|_| XdpError::Interface(io::Error::other("failed to create query socket")))?;
    let mut ifreq = ifreq_for(name)?;

    // SAFETY: ioctl with a valid socket fd and a correctly-sized `ifreq`; the
    // return value is checked.
    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU, &mut ifreq) };
    if ret < 0 {
        return Err(XdpError::Interface(io::Error::last_os_error()));
    }
    // SAFETY: the ioctl succeeded and populated the `ifru_mtu` union field.
    let mtu = unsafe { ifreq.ifr_ifru.ifru_mtu };
    Ok(mtu as u16)
}
