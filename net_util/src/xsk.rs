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

use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::{self, NonNull};
use std::time::{Duration, Instant};
use std::{io, mem};

use aya::xsk::{XskError, XskSocket, XskSocketConfig, XskUmem, XskUmemConfig};
use thiserror::Error;

use crate::XDP_FRAME_SIZE;

// `sockaddr_xdp::sxdp_flags` bits, from `linux/if_xdp.h`. Defined locally to
// avoid taking a dependency on `aya_obj`'s generated bindings.
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
const RX_WAKE_RETRY_WINDOW: Duration = Duration::from_millis(100);

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
    #[error("RX descriptor is outside its UMEM frame pool")]
    InvalidRxFrame,
    #[error("TX frame address or ownership is invalid")]
    InvalidTxFrame,
    #[error("AF_XDP frame count exceeds the supported range")]
    InvalidFrameCount,
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
    /// Require zero-copy support; unsupported drivers fail at bind time.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxFrameState {
    Free,
    Allocated,
    Inflight,
}

/// TX ownership is separate from the RX pool and follows completion identity.
struct TxPool {
    first_frame: u32,
    frame_size: u32,
    states: Vec<TxFrameState>,
    free: Vec<u32>,
    inflight: u32,
}

impl TxPool {
    fn new(first_frame: u32, end_frame: u32, frame_size: u32) -> Self {
        Self {
            first_frame,
            frame_size,
            states: vec![TxFrameState::Free; (end_frame - first_frame) as usize],
            free: (first_frame..end_frame).collect(),
            inflight: 0,
        }
    }

    fn index(&self, addr: u64) -> Result<usize, XdpError> {
        let size = u64::from(self.frame_size);
        if !addr.is_multiple_of(size) {
            return Err(XdpError::InvalidTxFrame);
        }
        let index = (addr / size)
            .checked_sub(u64::from(self.first_frame))
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < self.states.len())
            .ok_or(XdpError::InvalidTxFrame)?;
        Ok(index)
    }

    fn allocated_index(&self, addr: u64) -> Result<usize, XdpError> {
        let index = self.index(addr)?;
        if self.states[index] != TxFrameState::Allocated {
            return Err(XdpError::InvalidTxFrame);
        }
        Ok(index)
    }

    fn alloc(&mut self) -> Option<(u32, u64)> {
        let frame = self.free.pop()?;
        self.states[(frame - self.first_frame) as usize] = TxFrameState::Allocated;
        Some((frame, u64::from(frame) * u64::from(self.frame_size)))
    }

    fn recycle(&mut self, frame: u32) -> Result<(), XdpError> {
        let index = self.allocated_index(u64::from(frame) * u64::from(self.frame_size))?;
        self.states[index] = TxFrameState::Free;
        self.free.push(frame);
        Ok(())
    }

    fn complete(&mut self, addr: u64) -> Result<(), XdpError> {
        let index = self.index(addr)?;
        if self.states[index] != TxFrameState::Inflight {
            return Err(XdpError::InvalidTxFrame);
        }
        self.inflight = self
            .inflight
            .checked_sub(1)
            .ok_or(XdpError::InvalidTxFrame)?;
        self.states[index] = TxFrameState::Free;
        self.free.push(self.first_frame + index as u32);
        Ok(())
    }
}

/// An AF_XDP socket bound to one netdev queue, with its UMEM frame pools.
///
/// Frames `[0, fill_size)` form the RX pool (cycled FILL → RX → FILL); frames
/// `[fill_size, fill_size + tx_size)` form the TX pool (handed to the TX ring
/// and reclaimed via the COMPLETION ring).
pub struct Xsk {
    // `socket` must be declared before `_umem_mem`: it owns the registered UMEM
    // and must be dropped (closing the fd and unmapping the rings) before the
    // backing memory is unmapped.
    socket: XskSocket,
    _umem_mem: MmapRegion,
    frame_size: u32,
    /// Frames published to the kernel and not yet released from RX.
    rx_published: Vec<bool>,
    /// RX frames the caller has reclaimed and not yet returned to FILL.
    rx_pool: Vec<u32>,
    tx_pool: TxPool,
    zerocopy: bool,
    rx_wake_deadline: Option<Instant>,
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
        let frame_count = config
            .fill_size
            .checked_add(config.tx_size)
            .ok_or(XdpError::InvalidFrameCount)?;
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
        let tx_pool = TxPool::new(config.fill_size, frame_count, frame_size);

        // SAFETY: these distinct RX frames have never been published and are
        // disjoint from the TX pool. Only the submitted prefix becomes owned
        // by the kernel; the rest remains in rx_pool.
        let submitted = unsafe { socket.fill(rx_frames.iter().copied()) }? as usize;
        let rx_pool = rx_frames[submitted..].to_vec();
        let mut rx_published = vec![false; config.fill_size as usize];
        rx_published[..submitted].fill(true);
        socket.wake_rx()?;

        Ok(Self {
            socket,
            _umem_mem: umem_mem,
            frame_size,
            rx_published,
            rx_pool,
            tx_pool,
            zerocopy: config.zerocopy,
            rx_wake_deadline: config
                .zerocopy
                .then(|| Instant::now() + RX_WAKE_RETRY_WINDOW),
        })
    }

    /// The number of received packets currently available to read.
    pub fn rx_available(&self) -> u32 {
        self.socket.rx_available()
    }

    /// The bytes of the `index`-th available received packet (raw L2 frame).
    pub fn rx_peek(&self, index: u32) -> Result<&[u8], XdpError> {
        self.socket
            .rx_frame(index)?
            .map(|frame| frame.data)
            .ok_or(XdpError::InvalidRxFrame)
    }

    /// Releases the `n` oldest received descriptors and recycles their frames
    /// into the RX pool for later refilling.
    pub fn rx_release(&mut self, n: u32) -> Result<(), XdpError> {
        for _ in 0..n {
            let frame = self.socket.rx_frame(0)?.ok_or(XdpError::InvalidRxFrame)?;
            // Aya validates descriptor bounds and normalizes the frame address.
            // The device tracks which RX frames were published to the kernel.
            let index = rx_frame_index(frame.frame_addr, self.frame_size, &mut self.rx_published)?;
            self.socket.rx_release(1);
            self.rx_pool.push(index);
            self.rx_wake_deadline = None;
        }
        Ok(())
    }

    /// Returns reclaimed RX frames to the FILL ring and wakes the driver if
    /// required (zero-copy + need-wakeup mode).
    pub fn refill(&mut self) -> Result<(), XdpError> {
        if !self.rx_pool.is_empty() {
            // SAFETY: rx_release validates pool membership and rejects
            // duplicate ownership before adding a frame. Submitted frames
            // are removed, so rx_pool contains only distinct caller-owned
            // frames, with no packet borrow alive across this mutable call.
            let submitted = unsafe { self.socket.fill(self.rx_pool.iter().copied()) }? as usize;
            for index in self.rx_pool.drain(..submitted) {
                self.rx_published[index as usize] = true;
            }
            if submitted != 0 {
                self.retry_rx_wakeup();
            }
        }
        self.socket.wake_rx()?;
        Ok(())
    }

    pub fn has_pending_refill(&self) -> bool {
        !self.rx_pool.is_empty() || self.rx_wakeup_pending()
    }

    pub(crate) fn rx_wakeup_pending(&self) -> bool {
        self.rx_wake_deadline
            .is_some_and(|deadline| Instant::now() < deadline)
    }

    /// Schedule bounded wake retries after publication or worker restart.
    /// A successful wake does not prove ring progress. RX progress or the
    /// deadline ends this retry window.
    pub fn retry_rx_wakeup(&mut self) {
        if self.zerocopy {
            self.rx_wake_deadline = Some(Instant::now() + RX_WAKE_RETRY_WINDOW);
        }
    }

    /// Reclaims completed TX frames back into the free pool.
    pub fn complete(&mut self) -> Result<u32, XdpError> {
        let mut result = Ok(());
        let pool = &mut self.tx_pool;
        let completed = self.socket.complete(|addr| {
            if result.is_ok() {
                result = pool.complete(addr);
            }
        });
        result.map(|()| completed)
    }

    /// Whether submitted frames still need completion and possibly a wakeup.
    pub fn has_pending_tx(&self) -> bool {
        self.tx_pool.inflight != 0
    }

    /// Pops a free TX frame, returning its `(index, umem_addr)`.
    pub fn tx_alloc(&mut self) -> Option<(u32, u64)> {
        self.tx_pool.alloc()
    }

    /// Returns a free TX frame to the pool (e.g. when the TX ring was full).
    pub fn tx_recycle(&mut self, index: u32) -> Result<(), XdpError> {
        self.tx_pool.recycle(index)
    }

    /// A mutable view of the UMEM frame at `addr` for `len` bytes.
    pub fn tx_frame_mut(&mut self, addr: u64, len: u32) -> Option<&mut [u8]> {
        self.tx_pool.allocated_index(addr).ok()?;
        if len > self.frame_size {
            return None;
        }
        // SAFETY: the ledger proves this aligned TX frame is caller-owned,
        // not RX or inflight. The range fits one frame, and &mut self prevents
        // publication or another borrow while the returned slice is alive.
        unsafe { self.socket.tx_frame_mut(addr, len) }
    }

    /// Enqueues one frame on the TX ring. Returns `false` if the ring was full.
    pub fn transmit(&mut self, addr: u64, len: u32) -> Result<bool, XdpError> {
        let index = self.tx_pool.allocated_index(addr)?;
        if len == 0 || len > self.frame_size {
            return Err(XdpError::InvalidTxFrame);
        }
        // SAFETY: this single aligned frame is allocated and caller-owned.
        // The mutable receiver excludes live packet borrows. A successful
        // submission becomes Inflight and cannot be reused before completion.
        let submitted = unsafe { self.socket.transmit([(addr, len)]) }?;
        if submitted == 1 {
            self.tx_pool.states[index] = TxFrameState::Inflight;
            self.tx_pool.inflight += 1;
        }
        Ok(submitted == 1)
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

fn rx_frame_index(
    frame_addr: u64,
    frame_size: u32,
    published: &mut [bool],
) -> Result<u32, XdpError> {
    let index = usize::try_from(frame_addr / u64::from(frame_size))
        .map_err(|_| XdpError::InvalidRxFrame)?;
    if index >= published.len() || !published[index] {
        return Err(XdpError::InvalidRxFrame);
    }
    published[index] = false;
    Ok(index as u32)
}

/// Builds an `ifreq` with `ifr_name` set to `name` for an interface ioctl.
fn ifreq_for(name: &str) -> Result<libc::ifreq, XdpError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(XdpError::UnknownInterface(name.to_string()));
    }
    // SAFETY: `ifreq` is plain integer/array fields, so a zeroed value is valid.
    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
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
    u16::try_from(mtu)
        .map_err(|_| XdpError::Interface(io::Error::other("interface MTU exceeds u16")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_pool_rejects_wrong_ownership_and_completion_addresses() {
        let mut pool = TxPool::new(3, 6, 4096);
        for addr in [0, 2 * 4096, 6 * 4096, 5 * 4096 + 1, u64::MAX] {
            assert!(pool.complete(addr).is_err());
            pool.allocated_index(addr).unwrap_err();
        }
        assert!(pool.complete(5 * 4096).is_err());
        let (frame, addr) = pool.alloc().unwrap();
        assert_eq!((frame, addr), (5, 5 * 4096));
        assert!(pool.complete(addr).is_err());
        let index = pool.allocated_index(addr).unwrap();
        pool.states[index] = TxFrameState::Inflight;
        pool.inflight = 1;
        pool.allocated_index(addr).unwrap_err();
        assert!(pool.recycle(frame).is_err());
        assert!(pool.complete(addr + 256).is_err());
        assert_eq!(pool.inflight, 1);
        pool.complete(addr).unwrap();
        assert!(pool.complete(addr).is_err());
        assert_eq!(pool.inflight, 0);
        assert_eq!(pool.free.len(), 3);
        let (frame, _) = pool.alloc().unwrap();
        pool.recycle(frame).unwrap();
        assert!(pool.recycle(frame).is_err());
        assert_eq!(pool.free.len(), 3);
    }

    #[test]
    fn tx_pool_conserves_frames_across_out_of_order_completions() {
        let mut pool = TxPool::new(2, 5, 4096);
        for _ in 0..10 {
            let mut addresses = Vec::new();
            while let Some((_, addr)) = pool.alloc() {
                let index = pool.allocated_index(addr).unwrap();
                pool.states[index] = TxFrameState::Inflight;
                pool.inflight += 1;
                addresses.push(addr);
            }
            assert_eq!(addresses.len(), 3);
            for index in [1, 2, 0] {
                pool.complete(addresses[index]).unwrap();
            }
            assert_eq!(pool.inflight, 0);
            assert_eq!(pool.states, [TxFrameState::Free; 3]);
        }
    }

    #[cfg(devcli_testenv)]
    #[test]
    fn wake_retry_window_survives_empty_refill_and_expires() {
        // Exercise scheduling with a copy socket; this does not validate a
        // real zero-copy driver's wakeup behavior.
        let mut xsk = Xsk::new(
            iface_index("xdp-test0").unwrap(),
            0,
            XdpSocketConfig::default(),
        )
        .unwrap();
        assert!(!xsk.has_pending_refill());
        xsk.zerocopy = true;
        xsk.retry_rx_wakeup();
        let deadline = xsk.rx_wake_deadline;
        assert!(xsk.has_pending_refill());
        xsk.refill().unwrap();
        assert_eq!(xsk.rx_wake_deadline, deadline);
        xsk.rx_wake_deadline = Some(Instant::now() - Duration::from_secs(1));
        xsk.refill().unwrap();
        assert!(!xsk.has_pending_refill());
        xsk.retry_rx_wakeup();
        assert!(xsk.has_pending_refill());
    }

    #[test]
    fn rx_frame_identity_follows_descriptor_not_fill_order() {
        let mut published = [true; 3];
        for index in [2, 0, 1] {
            assert_eq!(
                rx_frame_index(index * 4096, 4096, &mut published).unwrap(),
                index as u32,
            );
        }
        rx_frame_index(2 * 4096, 4096, &mut published).unwrap_err();
        published.fill(true);
        rx_frame_index(3 * 4096, 4096, &mut published).unwrap_err();
        rx_frame_index(u64::MAX, 4096, &mut published).unwrap_err();
        assert_eq!(published, [true; 3]);
    }
}
