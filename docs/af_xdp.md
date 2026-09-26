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
rustup toolchain install nightly-2026-09-25 --component rust-src
cargo install bpf-linker --version 0.11.1 --locked
cargo +nightly-2026-09-25 build --release --features net_backend_af_xdp
```

Default builds and CI are unaffected: no CI job enables the feature, and
`net_util`'s `build.rs` only compiles the eBPF program when the feature is on.

## Privilege model (load-then-drop)

Cloud Hypervisor loads the XDP redirect program **itself** and removes setup
capabilities from the VMM thread before the guest runs. There is no second process,
no `SCM_RIGHTS` handoff, and no control socket.

| Phase | Operation | Capability |
|---|---|---|
| Device creation (`Vm::new`) | Load + attach the XDP redirect program, create `xsks_map` | `CAP_BPF` + `CAP_NET_ADMIN` |
| Device creation (`Vm::new`) | Create/bind one XSK per queue, insert each into `xsks_map` | `CAP_NET_RAW` |
| End of device creation, including restore | Drop `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_ADMIN`, and `CAP_SETPCAP`; deny `bpf()` | — |
| Running guest | Drive the existing rings (copy datapath) | None |

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
those guest-facing threads start with the reduced set. Bounding-set removal is
also done when `CAP_SETPCAP` is available. Otherwise, clearing the permitted and
inheritable sets and setting `no_new_privs` prevents privilege gain through exec.
A second seccomp filter denies all `bpf()` operations, including map updates
through existing FDs, even when the normal seccomp mode is disabled.
Restore defers virtio activation until this restriction is in place.

> **Residual limitation.** The drop is per-thread on the vmm thread. Long-lived
> helper threads already running at that point retain their capabilities and
> open FDs. This includes API, event, signal, and some constructor-created
> helper threads. This is not process-wide privilege separation.

## Usage

```
--net backend=xdp,xdp_iface=<host_if>,mac=<mac>[,xdp_zerocopy=on]
```

Key parameters:

- `backend=xdp` — select the AF_XDP backend (`af_xdp` is also accepted).
- `xdp_iface=<host_if>` — the host interface whose queues the XSKs bind to and
  onto which the redirect program is attached (required).
- `xdp_peer=<veth_peer>` — peer interface of a `veth` pair. AF_XDP redirect on
  `veth` only works when **both** ends have an XDP program, so CH attaches a
  pass-through program to the peer. Leave unset for a real NIC.
- `xdp_skb=on` — request generic (SKB) mode. Only FD-owned XDP links are
  supported; kernels that require legacy netlink attachment reject setup.
  Use the default native mode for veth.
- `xdp_zerocopy=on` — require zero-copy support at bind time. Unsupported
  drivers fail setup; there is no copy-mode fallback. Guest data is still copied.
- `num_queues=2` — exactly one RX/TX queue pair is supported. Configure the
  interface to receive on queue 0 (`ethtool -L <iface> combined 1`).

Use a **dedicated interface**. Every packet on queue 0 is redirected to the
guest, with no MAC/IP classification. The guest can also transmit arbitrary L2
frames. Packets on other queues pass to the host; they do not reach the guest.

`backend=xdp` cannot be combined with `tap`, `fd`, `vhost_user`, or a virtual
IOMMU.

## Limitations

- **Boot-only.** AF_XDP devices load their program while `CAP_BPF` is held, which
  happens only at device creation. Hot-plug (`vm.add-net backend=xdp`) is
  rejected. Cold snapshot/restore works because the destination rebuilds the
  program and XSKs at `Vm::new` (capabilities still held); **live migration is
  refused** (in-flight ring state and the kernel-attached program cannot be
  transferred).
- **Process lifecycle.** Guest virtio reset reuses the existing sockets. Full
  VM reboot or another AF_XDP VM requires a fresh VMM process. Capability
  removal is permanent and can also prevent later TAP/network hotplug.
- **Attachment.** FD-owned links are required, so closing them detaches without
  setup privileges. Legacy netlink-only attachment is unsupported.
- **No offloads.** AF_XDP delivers raw L2 frames, so no checksum/TSO/UFO
  features are advertised. Performance gains have not been established by the
  included tests; compare against TAP with representative workloads.
- **MTU.** The aligned-chunk UMEM frame size (4096 bytes) bounds the MTU at
  3826 after kernel RX headroom and the Ethernet header. Both host and guest
  MTUs must fit; jumbo frames are unsupported. This ceiling is for untagged
  Ethernet. For in-band VLAN tags, reduce the MTU by four bytes per tag.
- **Memory.** Each queue pair allocates a UMEM of roughly 16 MiB
  (4096 × 4096-byte frames).
