// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Copy-mode AF_XDP datapath for virtio-net.
//!
//! This is the AF_XDP analogue of [`crate::NetQueuePair`]. The TAP datapath
//! builds `iovec`s pointing into guest RAM and does a single `readv`/`writev`
//! on the tap fd; AF_XDP has no such fd semantics, so this copies between guest
//! descriptors and UMEM frames:
//!
//! - **TX (guest → host):** gather the descriptor chain, strip the
//!   `virtio_net_hdr`, copy the raw L2 frame into a UMEM frame, enqueue it on
//!   the TX ring, and kick the kernel.
//! - **RX (host → guest):** read a raw L2 frame from the RX ring, prepend a
//!   zeroed `virtio_net_hdr` (`num_buffers = 1`), and scatter it across the
//!   guest's writable descriptors.
//!
//! AF_XDP delivers raw L2 frames with no checksum/segmentation offload, so the
//! device must not advertise those features (handled in `virtio-devices`).

use std::io;
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use log::error;
use rate_limiter::{RateLimiter, TokenType};
use thiserror::Error;
use virtio_bindings::virtio_net::virtio_net_hdr_v1;
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_memory::bitmap::Bitmap;
use vm_memory::{GuestAddress, GuestMemory};
use vm_virtio::{AccessPlatform, Translatable};

use super::{NetCounters, register_listener, unregister_listener, vnet_hdr_len};
use crate::xsk::{XdpError, Xsk};

#[derive(Error, Debug)]
pub enum XdpQueuePairError {
    #[error("Error registering listener")]
    RegisterListener(#[source] io::Error),
    #[error("Error unregistering listener")]
    UnregisterListener(#[source] io::Error),
    #[error("Error related to guest memory")]
    GuestMemory(#[source] vm_memory::GuestMemoryError),
    #[error("Descriptor chain does not contain valid descriptors")]
    DescriptorChainInvalid,
    #[error("Failed to add used index to the queue")]
    QueueAddUsed(#[source] virtio_queue::Error),
    #[error("Failed to enable notification on the queue")]
    QueueEnableNotification(#[source] virtio_queue::Error),
    #[error("Failed to determine if queue needed notification")]
    QueueNeedsNotification(#[source] virtio_queue::Error),
    #[error("AF_XDP datapath error")]
    Xdp(#[from] XdpError),
}

/// Builds the synthetic `virtio_net_hdr` prepended to received frames.
///
/// AF_XDP hands us a bare L2 frame, but the guest expects every RX buffer to
/// start with a `virtio_net_hdr`. We have disabled all offloads, so a zeroed
/// header is correct; `num_buffers` is the trailing `u16` and must be 1 because
/// a frame never spans more than one descriptor chain here.
fn rx_vnet_header() -> [u8; size_of::<virtio_net_hdr_v1>()] {
    let mut hdr = [0u8; size_of::<virtio_net_hdr_v1>()];
    let n = hdr.len();
    hdr[n - 2..].copy_from_slice(&1u16.to_le_bytes());
    hdr
}

/// One virtio-net RX/TX queue pair backed by a single AF_XDP socket.
pub struct XdpQueuePair {
    pub xsk: Xsk,
    pub counters: NetCounters,
    tx_counter_bytes: Wrapping<u64>,
    tx_counter_frames: Wrapping<u64>,
    rx_counter_bytes: Wrapping<u64>,
    rx_counter_frames: Wrapping<u64>,
    pub epoll_fd: Option<RawFd>,
    pub xsk_rx_listening: bool,
    pub xsk_rx_event_id: u16,
    pub rx_desc_avail: bool,
    pub rx_rate_limiter: Option<RateLimiter>,
    pub tx_rate_limiter: Option<RateLimiter>,
    pub access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl XdpQueuePair {
    pub fn new(
        xsk: Xsk,
        counters: NetCounters,
        xsk_rx_event_id: u16,
        rx_rate_limiter: Option<RateLimiter>,
        tx_rate_limiter: Option<RateLimiter>,
        access_platform: Option<Arc<dyn AccessPlatform>>,
    ) -> Self {
        XdpQueuePair {
            xsk,
            counters,
            tx_counter_bytes: Wrapping(0),
            tx_counter_frames: Wrapping(0),
            rx_counter_bytes: Wrapping(0),
            rx_counter_frames: Wrapping(0),
            epoll_fd: None,
            xsk_rx_listening: false,
            xsk_rx_event_id,
            rx_desc_avail: false,
            rx_rate_limiter,
            tx_rate_limiter,
            access_platform,
        }
    }

    /// Walks a device-readable (TX) descriptor chain into `(addr, len)` guest
    /// segments. Mirrors the validity checks the TAP path applies.
    fn collect_readable<B: Bitmap + 'static>(
        &self,
        desc_chain: &mut virtio_queue::DescriptorChain<&vm_memory::GuestMemoryMmap<B>>,
        segments: &mut Vec<(GuestAddress, usize)>,
    ) -> Result<(), XdpQueuePairError> {
        for desc in desc_chain.by_ref() {
            let desc_addr = desc
                .addr()
                .translate_gva(self.access_platform.as_deref(), desc.len() as usize)
                .map_err(|e| {
                    XdpQueuePairError::GuestMemory(vm_memory::GuestMemoryError::IOError(e))
                })?;
            if !desc.is_write_only() && desc.len() > 0 {
                segments.push((desc_addr, desc.len() as usize));
            } else {
                error!(
                    "xdp: tx: invalid descriptor: addr=0x{:x} len={} write_only={}",
                    desc_addr.0,
                    desc.len(),
                    desc.is_write_only()
                );
                return Err(XdpQueuePairError::DescriptorChainInvalid);
            }
        }
        Ok(())
    }

    /// Walks a device-writable (RX) descriptor chain into `(addr, len)` guest
    /// segments and returns their total capacity.
    fn collect_writable<B: Bitmap + 'static>(
        &self,
        desc_chain: &mut virtio_queue::DescriptorChain<&vm_memory::GuestMemoryMmap<B>>,
        segments: &mut Vec<(GuestAddress, usize)>,
    ) -> Result<usize, XdpQueuePairError> {
        let mut capacity = 0;
        for desc in desc_chain.by_ref() {
            let desc_addr = desc
                .addr()
                .translate_gva(self.access_platform.as_deref(), desc.len() as usize)
                .map_err(|e| {
                    XdpQueuePairError::GuestMemory(vm_memory::GuestMemoryError::IOError(e))
                })?;
            if desc.is_write_only() && desc.len() > 0 {
                segments.push((desc_addr, desc.len() as usize));
                capacity += desc.len() as usize;
            } else {
                error!(
                    "xdp: rx: invalid descriptor: addr=0x{:x} len={} write_only={}",
                    desc_addr.0,
                    desc.len(),
                    desc.is_write_only()
                );
                return Err(XdpQueuePairError::DescriptorChainInvalid);
            }
        }
        Ok(capacity)
    }

    pub fn process_tx<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        queue: &mut Queue,
    ) -> Result<bool, XdpQueuePairError> {
        let hdr_len = vnet_hdr_len();
        let mut rate_limit_reached = false;
        let mut transmitted_any = false;

        // Reclaim TX frames the kernel has finished with before sending more.
        self.xsk.complete();

        while let Some(mut desc_chain) = queue.pop_descriptor_chain(mem) {
            if rate_limit_reached {
                queue.go_to_previous_position();
                break;
            }

            let mut segments = Vec::new();
            let head_index = desc_chain.head_index();
            if let Err(e) = self.collect_readable(&mut desc_chain, &mut segments) {
                queue
                    .add_used(mem, head_index, 0)
                    .map_err(XdpQueuePairError::QueueAddUsed)?;
                return Err(e);
            }

            let total: usize = segments.iter().map(|(_, len)| len).sum();
            let bytes_sent = if total <= hdr_len {
                0
            } else {
                let payload_len = total - hdr_len;

                // Reclaim completions and obtain a free TX frame. If none is
                // available the TX ring is saturated; rewind and retry later.
                if self.xsk.tx_alloc().is_none() {
                    self.xsk.complete();
                }
                let Some((frame_index, addr)) = self.xsk.tx_alloc() else {
                    queue.go_to_previous_position();
                    break;
                };

                let mut packet = vec![0u8; total];
                if let Err(e) = read_segments(mem, &segments, &mut packet) {
                    self.xsk.tx_recycle(frame_index);
                    queue
                        .add_used(mem, head_index, 0)
                        .map_err(XdpQueuePairError::QueueAddUsed)?;
                    return Err(XdpQueuePairError::GuestMemory(e));
                }

                // Strip the virtio_net_hdr; AF_XDP transmits raw L2 frames.
                let payload = &packet[hdr_len..];
                if payload_len > crate::XDP_FRAME_SIZE as usize {
                    error!("xdp: tx: dropping oversized frame ({payload_len} bytes)");
                    self.xsk.tx_recycle(frame_index);
                    0
                } else {
                    let frame = self
                        .xsk
                        .tx_frame_mut(addr, payload_len as u32)
                        .expect("UMEM frame within bounds");
                    frame.copy_from_slice(payload);

                    if !self.xsk.transmit(addr, payload_len as u32)? {
                        // TX ring filled between the alloc and the submit.
                        self.xsk.tx_recycle(frame_index);
                        queue.go_to_previous_position();
                        break;
                    }
                    transmitted_any = true;
                    payload_len as u64
                }
            };

            if let Some(rate_limiter) = &mut self.tx_rate_limiter {
                rate_limit_reached = !rate_limiter.consume(1, TokenType::Ops)
                    || !rate_limiter.consume(bytes_sent, TokenType::Bytes);
            }

            self.tx_counter_bytes += Wrapping(bytes_sent);
            if bytes_sent > 0 {
                self.tx_counter_frames += Wrapping(1);
            }

            // TX descriptors are device-readable only; used length is 0.
            queue
                .add_used(mem, head_index, 0)
                .map_err(XdpQueuePairError::QueueAddUsed)?;

            if !queue
                .enable_notification(mem)
                .map_err(XdpQueuePairError::QueueEnableNotification)?
            {
                break;
            }
        }

        if transmitted_any {
            self.xsk.kick()?;
        }

        self.counters
            .tx_bytes
            .fetch_add(self.tx_counter_bytes.0, Ordering::AcqRel);
        self.counters
            .tx_frames
            .fetch_add(self.tx_counter_frames.0, Ordering::AcqRel);
        self.tx_counter_bytes = Wrapping(0);
        self.tx_counter_frames = Wrapping(0);

        queue
            .needs_notification(mem)
            .map_err(XdpQueuePairError::QueueNeedsNotification)
    }

    pub fn process_rx<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        queue: &mut Queue,
    ) -> Result<bool, XdpQueuePairError> {
        let header = rx_vnet_header();
        let mut processed = 0u32;
        let mut rate_limit_reached = false;

        loop {
            if rate_limit_reached {
                self.rx_desc_avail = true;
                break;
            }
            if processed >= self.xsk.rx_available() {
                // Drained every received packet the kernel handed us.
                self.rx_desc_avail = true;
                break;
            }
            let Some(mut desc_chain) = queue.pop_descriptor_chain(mem) else {
                // No guest RX buffers available right now.
                self.rx_desc_avail = false;
                break;
            };

            let mut segments = Vec::new();
            let head_index = desc_chain.head_index();
            let capacity = match self.collect_writable(&mut desc_chain, &mut segments) {
                Ok(capacity) => capacity,
                Err(e) => {
                    queue
                        .add_used(mem, head_index, 0)
                        .map_err(XdpQueuePairError::QueueAddUsed)?;
                    return Err(e);
                }
            };

            let payload_len = self
                .xsk
                .rx_peek(processed)
                .map(|p| p.len())
                .unwrap_or_default();
            let frame_len = header.len() + payload_len;

            let written = if payload_len == 0 || capacity < frame_len {
                if capacity < frame_len {
                    error!(
                        "xdp: rx: dropping frame, guest buffer too small ({capacity} < {frame_len})"
                    );
                }
                0
            } else {
                // Re-peek to obtain the borrow for the copy; the immutable XSK
                // borrow ends before any mutable XSK call below.
                let payload = self.xsk.rx_peek(processed).expect("peeked above");
                write_rx_frame(mem, &segments, &header, payload)?
            };

            processed += 1;

            if let Some(rate_limiter) = &mut self.rx_rate_limiter {
                rate_limit_reached = !rate_limiter.consume(1, TokenType::Ops)
                    || !rate_limiter.consume(written as u64, TokenType::Bytes);
            }

            if written > 0 {
                self.rx_counter_bytes += Wrapping(payload_len as u64);
                self.rx_counter_frames += Wrapping(1);
            }

            queue
                .add_used(mem, head_index, written)
                .map_err(XdpQueuePairError::QueueAddUsed)?;

            if !queue
                .enable_notification(mem)
                .map_err(XdpQueuePairError::QueueEnableNotification)?
            {
                break;
            }
        }

        // Return the consumed frames to the kernel.
        if processed > 0 {
            self.xsk.rx_release(processed);
            self.xsk.refill()?;
        }

        let rate_limit_blocked = self
            .rx_rate_limiter
            .as_ref()
            .is_some_and(|r| r.is_blocked());

        // Stop listening on the XSK fd when the guest has no RX buffers left or
        // the RX rate limit is reached, mirroring the TAP datapath.
        if self.xsk_rx_listening && (!self.rx_desc_avail || rate_limit_blocked) {
            unregister_listener(
                self.epoll_fd.unwrap(),
                self.xsk.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(self.xsk_rx_event_id),
            )
            .map_err(XdpQueuePairError::UnregisterListener)?;
            self.xsk_rx_listening = false;
        }

        self.counters
            .rx_bytes
            .fetch_add(self.rx_counter_bytes.0, Ordering::AcqRel);
        self.counters
            .rx_frames
            .fetch_add(self.rx_counter_frames.0, Ordering::AcqRel);
        self.rx_counter_bytes = Wrapping(0);
        self.rx_counter_frames = Wrapping(0);

        queue
            .needs_notification(mem)
            .map_err(XdpQueuePairError::QueueNeedsNotification)
    }

    /// Registers the XSK fd for readability if not already listening.
    pub fn register_rx_listener(&mut self) -> Result<(), XdpQueuePairError> {
        if !self.xsk_rx_listening {
            register_listener(
                self.epoll_fd.unwrap(),
                self.xsk.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(self.xsk_rx_event_id),
            )
            .map_err(XdpQueuePairError::RegisterListener)?;
            self.xsk_rx_listening = true;
        }
        Ok(())
    }
}

/// Copies guest segments into `dest`, which must be exactly their total length.
fn read_segments<B: Bitmap + 'static>(
    mem: &vm_memory::GuestMemoryMmap<B>,
    segments: &[(GuestAddress, usize)],
    dest: &mut [u8],
) -> Result<(), vm_memory::GuestMemoryError> {
    let mut off = 0;
    for &(addr, len) in segments {
        let slice = mem.get_slice(addr, len)?;
        slice.copy_to(&mut dest[off..off + len]);
        off += len;
    }
    Ok(())
}

/// Scatters `header ++ payload` across the writable guest segments, returning
/// the number of bytes written.
fn write_rx_frame<B: Bitmap + 'static>(
    mem: &vm_memory::GuestMemoryMmap<B>,
    segments: &[(GuestAddress, usize)],
    header: &[u8],
    payload: &[u8],
) -> Result<u32, XdpQueuePairError> {
    let mut packet = Vec::with_capacity(header.len() + payload.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(payload);

    let mut off = 0;
    for &(addr, seg_len) in segments {
        if off >= packet.len() {
            break;
        }
        let n = seg_len.min(packet.len() - off);
        let slice = mem
            .get_slice(addr, n)
            .map_err(XdpQueuePairError::GuestMemory)?;
        slice.copy_from(&packet[off..off + n]);
        off += n;
    }
    Ok(off as u32)
}

#[cfg(test)]
mod tests {
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;

    fn test_mem() -> GuestMemoryMmap<()> {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1_0000)]).unwrap()
    }

    #[test]
    fn vnet_header_marks_single_buffer() {
        let hdr = rx_vnet_header();
        assert_eq!(hdr.len(), vnet_hdr_len());
        // Everything zero except num_buffers (last u16) == 1.
        let (rest, num_buffers_bytes) = hdr.split_last_chunk::<2>().unwrap();
        assert!(rest.iter().all(|&b| b == 0));
        assert_eq!(u16::from_le_bytes(*num_buffers_bytes), 1);
    }

    #[test]
    fn read_segments_concatenates() {
        let mem = test_mem();
        mem.write_slice(&[0xaa; 4], GuestAddress(0x100)).unwrap();
        mem.write_slice(&[0xbb; 6], GuestAddress(0x200)).unwrap();

        let segments = [(GuestAddress(0x100), 4), (GuestAddress(0x200), 6)];
        let mut dest = vec![0u8; 10];
        read_segments(&mem, &segments, &mut dest).unwrap();

        assert_eq!(&dest[..4], &[0xaa; 4]);
        assert_eq!(&dest[4..], &[0xbb; 6]);
    }

    #[test]
    fn write_rx_frame_prepends_header_across_segments() {
        let mem = test_mem();
        let header = rx_vnet_header();
        let payload: Vec<u8> = (0..40u8).collect();

        // Two segments: the header straddles the boundary into the payload.
        let segments = [(GuestAddress(0x100), 8), (GuestAddress(0x300), 100)];
        let written = write_rx_frame(&mem, &segments, &header, &payload).unwrap();
        assert_eq!(written as usize, header.len() + payload.len());

        let mut reassembled = vec![0u8; written as usize];
        reassembled[..8].copy_from_slice(&{
            let mut b = [0u8; 8];
            mem.read_slice(&mut b, GuestAddress(0x100)).unwrap();
            b
        });
        mem.read_slice(&mut reassembled[8..], GuestAddress(0x300))
            .unwrap();

        assert_eq!(&reassembled[..header.len()], &header);
        assert_eq!(&reassembled[header.len()..], &payload[..]);
    }

    #[test]
    fn write_rx_frame_truncates_to_capacity() {
        let mem = test_mem();
        let header = rx_vnet_header();
        let payload = vec![0x5au8; 100];

        // Capacity (20) is smaller than header + payload; only 20 bytes land.
        let segments = [(GuestAddress(0x100), 20)];
        let written = write_rx_frame(&mem, &segments, &header, &payload).unwrap();
        assert_eq!(written, 20);
    }
}
