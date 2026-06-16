# AF_XDP network backend

Cloud Hypervisor can drive a virtio-net device with an in-process
[AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html) (XSK)
datapath instead of a kernel TAP. AF_XDP moves raw L2 frames between userspace
and a NIC queue through a shared memory region (UMEM) and a set of rings,
bypassing the kernel network stack for higher packet rates.

This backend is built behind the `net_backend_af_xdp` cargo feature, which is
**off by default**. Building it compiles a small embedded eBPF redirect program,
which needs a **nightly** toolchain (with `rust-src`) and
[`bpf-linker`](https://github.com/aya-rs/bpf-linker):

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo +nightly build --release --features net_backend_af_xdp
```

Default builds and CI are unaffected: no CI job enables the feature, and
`net_util`'s `build.rs` only compiles the eBPF program when the feature is on.

## Privilege model (load-then-drop)

Cloud Hypervisor loads the XDP redirect program **itself** and drops the
root-equivalent capabilities before the guest runs. There is no second process,
no `SCM_RIGHTS` handoff, and no control socket.

| Phase | Operation | Capability |
|---|---|---|
| Device creation (`Vm::new`) | Load + attach the XDP redirect program, create `xsks_map` | `CAP_BPF` + `CAP_NET_ADMIN` |
| Device creation (`Vm::new`) | Create/bind one XSK per queue, insert each into `xsks_map` | `CAP_NET_RAW` |
| Boot (`Vm::boot`, before vCPUs) | Drop `CAP_BPF` + `CAP_NET_ADMIN`, retain `CAP_NET_RAW` | — |
| Running guest | Drive the rings (copy datapath) | `CAP_NET_RAW` |

The XDP/BPF program is built from source ([`net_util/xdp-ebpf`](../net_util/xdp-ebpf))
and embedded in the binary. It is loaded with [`aya`](https://github.com/aya-rs/aya).
Every `bpf()` operation — program load, map creation, and `xsks_map` population —
finishes during device creation, while the capabilities are still held. The XSK
fds are inserted into `xsks_map` **before** the capability drop, so the running
datapath never depends on `bpf()`.

Cloud Hypervisor must therefore **start** with `CAP_BPF`, `CAP_NET_ADMIN`, and
`CAP_NET_RAW` — run it as root, or grant the binary the capabilities directly:

```bash
sudo setcap cap_bpf,cap_net_admin,cap_net_raw+ep ./cloud-hypervisor
```

The drop happens on the vmm thread before any vCPU or virtio-worker thread is
spawned. Linux capabilities are per-thread and inherited at thread creation, so
those guest-facing threads start with the reduced set, and `CAP_BPF`/
`CAP_NET_ADMIN` are also removed from the bounding set.

> **Residual limitation.** The drop is per-thread on the vmm thread. Long-lived
> helper threads already running at that point — the event monitor, the signal
> handler, and the HTTP/D-Bus API threads — keep their capabilities. They are
> not guest-controlled. A full process-wide drop (signalling every thread to
> `capset`) is a follow-up.

## Usage

```
--net backend=xdp,xdp_iface=<host_if>,mac=<mac>[,num_queues=<2N>][,xdp_skb=on][,xdp_zerocopy=on]
```

Key parameters:

- `backend=xdp` — select the AF_XDP backend (`af_xdp` is also accepted).
- `xdp_iface=<host_if>` — the host interface whose queues the XSKs bind to and
  onto which the redirect program is attached (required).
- `xdp_peer=<veth_peer>` — peer interface of a `veth` pair. AF_XDP redirect on
  `veth` only works when **both** ends have an XDP program, so CH attaches a
  pass-through program to the peer. Leave unset for a real NIC.
- `xdp_skb=on` — force the redirect program to attach in generic (SKB) mode
  instead of native driver mode. Required on `veth` and other interfaces without
  native XDP support. Default (`off`) tries native mode and falls back to SKB.
- `xdp_zerocopy=on` — request zero-copy mode; falls back to copy mode at bind
  time on drivers without zero-copy support.
- `num_queues=<2N>` — one XSK is bound per NIC hardware queue using queue ids
  `0..N`. The interface must expose that many combined queues
  (`ethtool -L <iface> combined N`); otherwise frames land on queues with no XSK
  and are passed up the normal stack (`XDP_PASS`).

`backend=xdp` cannot be combined with `tap`, `fd`, `vhost_user`, or a virtual
IOMMU.

## Limitations

- **Boot-only.** AF_XDP devices load their program while `CAP_BPF` is held, which
  happens only at device creation. Hot-plug (`vm.add-net backend=xdp`) is
  rejected. Cold snapshot/restore works because the destination rebuilds the
  program and XSKs at `Vm::new` (capabilities still held); **live migration is
  refused** (in-flight ring state and the kernel-attached program cannot be
  transferred).
- **No offloads.** AF_XDP delivers raw L2 frames, so no checksum/TSO/UFO
  features are advertised. Bulk TCP throughput is typically below TAP-with-TSO,
  while small-packet (PPS) rates are competitive or better.
- **MTU.** The aligned-chunk UMEM frame size (4096 bytes) bounds the MTU at
  4082; jumbo frames are unsupported.
- **Memory.** Each queue pair allocates a UMEM of roughly 16 MiB
  (4096 × 4096-byte frames).
