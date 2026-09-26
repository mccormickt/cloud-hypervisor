// Copyright © 2026 Cloud Hypervisor Authors
// SPDX-License-Identifier: Apache-2.0

// Run with --cfg devcli_testenv in a network namespace containing an active
// xdp-test0 veth interface. These tests need CAP_NET_RAW and sufficient memlock.
#![cfg(all(devcli_testenv, feature = "net_backend_af_xdp"))]

use net_util::{
    NetCounters, XdpAttachMode, XdpProgram, XdpQueuePair, XdpSocketConfig, Xsk, iface_index,
    vnet_hdr_len,
};
use virtio_queue::QueueT;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vm_virtio::queue::testing::VirtQueue;

fn socket() -> Xsk {
    Xsk::new(
        iface_index("xdp-test0").unwrap(),
        0,
        XdpSocketConfig {
            rx_size: 64,
            tx_size: 64,
            fill_size: 64,
            completion_size: 64,
            ..Default::default()
        },
    )
    .unwrap()
}

fn free_tx_frames(xsk: &mut Xsk) -> usize {
    xsk.complete();
    let mut frames = Vec::new();
    while let Some((index, _)) = xsk.tx_alloc() {
        frames.push(index);
    }
    let count = frames.len();
    for index in frames {
        xsk.tx_recycle(index);
    }
    count
}

#[test]
fn tx_reclaims_every_frame() {
    let mem =
        GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap();
    let guest_q = VirtQueue::new(GuestAddress(0x10_0000), &mem, 256);
    let mut queue = guest_q.create_queue();
    let mut xsk = socket();
    let mut net = XdpQueuePair::new(&mut xsk, NetCounters::default(), 0, None, None, None);
    let mut packet = vec![0u8; vnet_hdr_len() + 60];
    packet[vnet_hdr_len()..vnet_hdr_len() + 6].fill(0xff);
    packet[vnet_hdr_len() + 12..vnet_hdr_len() + 14].copy_from_slice(&[0x88, 0xb5]);
    mem.write_slice(&packet, GuestAddress(0x1000)).unwrap();

    for i in 0..256u16 {
        guest_q.dtable[i as usize].set(0x1000, packet.len() as u32, 0, 0);
        guest_q.avail.ring[i as usize].set(i);
        guest_q.avail.idx.set(i + 1);
        net.process_tx(&mem, &mut queue).unwrap();
        assert_eq!(queue.next_used(), i + 1);
        for _ in 0..100 {
            net.xsk.kick().unwrap();
            if free_tx_frames(&mut net.xsk) == 64 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(free_tx_frames(&mut net.xsk), 64);
    }
}

#[test]
fn tx_rejects_oversized_descriptor_before_reading_memory() {
    let mem =
        GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap();
    let guest_q = VirtQueue::new(GuestAddress(0x10_0000), &mem, 2);
    let mut queue = guest_q.create_queue();
    let mut xsk = socket();
    let mut net = XdpQueuePair::new(&mut xsk, NetCounters::default(), 0, None, None, None);
    guest_q.dtable[0].set(0x1000, u32::MAX, 0, 0);
    guest_q.avail.ring[0].set(0);
    guest_q.avail.idx.set(1);

    net.process_tx(&mem, &mut queue).unwrap();
    assert_eq!(queue.next_used(), 1);
    assert_eq!(free_tx_frames(&mut net.xsk), 64);
}

#[test]
fn tx_burst_progresses_without_new_guest_descriptors() {
    let mem =
        GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap();
    let guest_q = VirtQueue::new(GuestAddress(0x10_0000), &mem, 256);
    let mut queue = guest_q.create_queue();
    let mut xsk = socket();
    let mut net = XdpQueuePair::new(&mut xsk, NetCounters::default(), 0, None, None, None);
    let mut packet = vec![0u8; vnet_hdr_len() + 60];
    packet[vnet_hdr_len()..vnet_hdr_len() + 6].fill(0xff);
    packet[vnet_hdr_len() + 12..vnet_hdr_len() + 14].copy_from_slice(&[0x88, 0xb5]);
    mem.write_slice(&packet, GuestAddress(0x1000)).unwrap();
    for i in 0..256u16 {
        guest_q.dtable[i as usize].set(0x1000, packet.len() as u32, 0, 0);
        guest_q.avail.ring[i as usize].set(i);
    }
    guest_q.avail.idx.set(256);
    net.process_tx(&mem, &mut queue).unwrap();

    for _ in 0..100 {
        if !net.needs_tx_retry() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
        net.process_tx(&mem, &mut queue).unwrap();
    }
    assert_eq!(queue.next_used(), 256);
    assert!(!net.needs_tx_retry());
    assert_eq!(free_tx_frames(&mut net.xsk), 64);
}

#[test]
fn rx_recycles_frames_and_fd_links_detach() {
    let mut program =
        XdpProgram::load_and_attach("xdp-test0", Some("xdp-test1"), XdpAttachMode::Auto).unwrap();
    let mut xsk = socket();
    program.insert_xsk(0, &xsk).unwrap();
    let peer = pnet_datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == "xdp-test1")
        .unwrap();
    let pnet_datalink::Channel::Ethernet(mut tx, _) =
        pnet_datalink::channel(&peer, Default::default()).unwrap()
    else {
        panic!("expected Ethernet channel");
    };
    let mut packet = [0u8; 60];
    packet[..6].fill(0xff);
    packet[12..14].copy_from_slice(&[0x88, 0xb5]);

    for sequence in 0..512u32 {
        packet[14..18].copy_from_slice(&sequence.to_le_bytes());
        tx.send_to(&packet, None).unwrap().unwrap();
        let mut received = false;
        for _ in 0..100 {
            xsk.refill().unwrap();
            while xsk.rx_available() != 0 {
                received |= xsk.rx_peek(0).unwrap() == packet;
                xsk.rx_release(1).unwrap();
            }
            if received {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(received, "missing RX packet {sequence}");
    }

    drop(program);
    XdpProgram::load_and_attach("xdp-test0", Some("xdp-test1"), XdpAttachMode::Auto).unwrap();
}

#[test]
fn attachment_failure_rolls_back_links() {
    assert!(
        XdpProgram::load_and_attach("xdp-test0", Some("missing-peer"), XdpAttachMode::Auto)
            .is_err()
    );
    drop(XdpProgram::load_and_attach(
        "xdp-test0",
        None,
        XdpAttachMode::Skb,
    ));
    XdpProgram::load_and_attach("xdp-test0", Some("xdp-test1"), XdpAttachMode::Auto).unwrap();
}

#[test]
fn header_only_tx_yields_and_continues() {
    let mem =
        GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap();
    let guest_q = VirtQueue::new(GuestAddress(0x10_0000), &mem, 512);
    let mut queue = guest_q.create_queue();
    let mut xsk = socket();
    let mut net = XdpQueuePair::new(&mut xsk, NetCounters::default(), 0, None, None, None);
    for index in 0..512u16 {
        guest_q.dtable[index as usize].set(0x1000, vnet_hdr_len() as u32, 0, 0);
        guest_q.avail.ring[index as usize].set(index);
    }
    guest_q.avail.idx.set(512);
    net.process_tx(&mem, &mut queue).unwrap();
    assert_eq!(queue.next_used(), 256);
    assert!(net.needs_tx_retry());
    net.process_tx(&mem, &mut queue).unwrap();
    assert_eq!(queue.next_used(), 512);
    assert!(!net.needs_tx_retry());
    assert_eq!(free_tx_frames(&mut net.xsk), 64);
}
