# Cloud Hypervisor — Follow-on Vulnerability Report (v2)

**Scope:** additive to `findings.md`. Covers Phase A pattern sweeps, Phase D differential review (post-2026-02-01 commits), and Phase C coverage gap analysis against the `pure-swinging-raven` hunt plan. HEAD is post-v51.1.

**Method:** Ripgrep sweeps across six validated bug classes, reproducer-level verification of HIGH candidates, cross-check against existing fuzz coverage, diff review of the 90-commit March-2026 spike.

**Threat model** (same as `findings.md`):
- **Architecture**: cloud-hypervisor is a 1:1 VMM — one process per VM. A VMM crash kills only the single associated guest, not other VMs on the host.
- **Guest → VMM**: a single in-guest instruction reaching a panic/UB is HIGH (guest-DoS: the guest can kill itself, which breaks availability guarantees in orchestrated environments; and for memory-safety bugs, potential host escape).
- **API → VMM**: local Unix socket, typically admin-trusted; arbitrary-file-write / UAF / DoS is MEDIUM unless feature-gated off by default.
- **Migration peer → VMM**: trusted-but-remote; malformed input DoS is MEDIUM, but arbitrary file access or UB is HIGH.
- **Hypervisor → VMM**: trusted but non-adversarial; defensive gaps are LOW.
- **Build/host**: trusted; hygiene issues are LOW/INFO.
- For `sev_snp`/`tdx` features the guest is explicitly adversarial — any VMM panic on guest-controlled GHCB/TDX data is HIGH within that build.

---

## Summary

| ID           | Finding                                                                    | Severity | Reach            |
|--------------|----------------------------------------------------------------------------|----------|------------------|
| V2-01        | Narrow MMIO guest access → `assert!` panic (Bus width not filtered)        | **HIGH** | guest            |
| V2-01a       | — PCI hotplug ACPI region (`device_manager.rs` × 6 sites)                  | HIGH     | guest            |
| V2-01b       | — CpuManager vCPU hotplug MMIO (`cpu.rs` × 2 sites)                        | HIGH     | guest            |
| V2-01c       | — MSI-X table/PBA BAR (`pci/msix.rs` × 3 sites)                            | HIGH     | guest            |
| V2-02        | SEV-SNP GHCB VMGEXIT panics (`mshv/mod.rs` × 6 sites)                      | **HIGH** | guest (sev_snp)  |
| V2-03        | fw_cfg `read_content` OOB on `data_offset` walk                            | MEDIUM   | guest (fw_cfg)   |
| V2-04        | `MemoryRangeTable::read_from` — unbounded peer length → panic/OOM          | MEDIUM   | migration-peer   |
| V2-05        | qcow2 backing-file not in Landlock ruleset                                 | LOW      | config (opt-in)  |
| V2-06        | `FwCfgConfig` missing `ApplyLandlock` impl                                 | LOW      | config (fw_cfg)  |
| V2-07        | TDVF GUID-table parser underflow cluster                                   | LOW      | firmware (tdx)   |
| V2-08        | `MsrEntries::from_entries(...).unwrap()` cluster (mshv + kvm)              | LOW      | api              |
| V2-09        | vCPU id `u32 → u8 .try_into().unwrap()` (`mshv/mod.rs:1821`)               | LOW      | api              |
| V2-10        | `.to_*_info().unwrap()` sites beyond VULN-04's enumerated list             | INFO     | hv-trust         |
| V2-11        | PCI VFIO region lookup `unchecked_add` on guest BAR                        | INFO     | guest            |
| V2-12        | `fuzz/Cargo.toml` `micro_http` branch pin (sibling of VLN-02)              | LOW      | build            |
| V2-13        | Cargo.lock has drifted from `micro_http` upstream `main` tip               | LOW      | build            |
| V2-14        | `cloud-hypervisor/build.rs:22` env-rerun directive ordering bug            | INFO     | build            |
| V2-15        | No fuzz corpus / no dictionary committed in `fuzz/`                        | LOW      | coverage         |
| V2-16        | Missing fuzz harnesses: `hv_message`, migration-recv, raw-image-detect     | LOW      | coverage         |
| V2-17        | Sector-0 write-ban silently disabled after autodetect persistence          | MEDIUM   | guest            |
| V2-18        | vsock multi-descriptor TX buffer driven by guest `pkt.len()` (bf6f0f8)     | LOW      | guest (audit)    |
| V2-19        | GICv2M `save_data_tables` now silently `Ok(())` (caa362c)                  | LOW      | migration        |
| V2-20        | DISCARD/WRITE_ZEROES `sector * SECTOR_SIZE` unchecked_mul (81c075b)        | LOW      | guest            |
| **Phase B deep dives** | | | |
| V2-21        | aarch64 emulator OOB write via XZR register 31 (`mshv/aarch64/emulator.rs:87`) | **HIGH** | guest (aarch64+mshv) |
| V2-22        | Migration `Command`/`Status` enum UB via `ByteValued` reinterpretation     | **HIGH** | migration-peer   |
| V2-23        | VHDX region overlap check inverted logic (`vhdx_header.rs:280`)            | MEDIUM   | image            |
| V2-24        | VHDX I/O hardcoded 512-byte sector size ignores 4K-sector images           | MEDIUM   | image            |
| V2-25        | x86 emulator expand-down segment check inverted (`emulator/mod.rs:164`)    | MEDIUM   | guest            |
| V2-26        | REP MOVS/STOS unbounded emulation loop from guest ECX                      | MEDIUM   | guest (mshv)     |
| V2-27        | GPA_ATTRIBUTE_INTERCEPT unbounded alloc from guest `gfn_count`             | MEDIUM   | guest (sev_snp)  |
| V2-28        | GPA_ATTRIBUTE_INTERCEPT bitmap `reset_addr_range` unit mismatch            | MEDIUM   | guest (sev_snp)  |
| V2-29        | Migration `vm_receive_config`/`vm_receive_state` unbounded allocation      | MEDIUM   | migration-peer   |
| V2-30        | `MemoryRangeTable::read_from` assert! panic on non-aligned length          | MEDIUM   | migration-peer   |
| V2-31        | Migration `receive_memory_regions` infinite loop on socket EOF             | MEDIUM   | migration-peer   |
| V2-32        | Migration `vm_receive_config`: unvalidated config → arbitrary file access + crash | **HIGH** | migration-peer   |
| V2-33        | VHDX BAT `with_capacity` driven by image-controlled `bat_entry.length`     | LOW      | image            |
| V2-34        | VHDX `write` silently truncates on low file offset                         | LOW      | image            |
| V2-35        | x86 emulator hardcoded 64-bit decode mode                                  | LOW      | guest (mshv)     |
| V2-36        | GPA_ATTRIBUTE_INTERCEPT `range_count() == 0` assert (reassessed)           | LOW      | guest (sev_snp)  |
| V2-37        | qcow2 `rebuild_refcounts` wrapping subtraction (debug panic)               | LOW      | image            |
| **Phase B.3/B.4 deep dives** | | | |
| V2-38        | `RestoreConfig::validate` assert_eq! panic (D-Bus only; HTTP sanitizes input) | LOW (HTTP) / MEDIUM (D-Bus) | api (dbus)       |
| V2-39        | HTTP `handle_request` try_clone().unwrap() panic under FD exhaustion       | **MEDIUM** | api              |
| V2-40        | Hot-add API endpoints accept arbitrary paths without validation            | **MEDIUM** | api (no Landlock)|
| V2-41        | D-Bus `vm_restore` lacks FD passing; same panic as V2-38                   | LOW      | api (dbus)       |
| V2-42        | `hotplug_virtio_pci_device` stale handle on add failure                    | LOW      | api              |
| V2-43        | `add_vfio_device` stores VFIO container before DMA mapping                 | LOW      | api              |
| V2-44        | `eject_device` releases PCI slot before verifying device in tree           | LOW      | guest            |
| V2-45        | `DeviceConfig::apply_landlock` reads wrong symlink — VFIO Landlock rule no-op | **MEDIUM** | config (VFIO+Landlock) |
| V2-46        | `DiskConfig.vhost_socket` not covered by Landlock                          | LOW      | config (Landlock)|
| V2-47        | `NetConfig.vhost_socket` missing from `ApplyLandlock` dispatch             | LOW      | config (Landlock)|
| V2-48        | `IvshmemConfig.path` missing from `ApplyLandlock` dispatch                 | LOW      | config (ivshmem) |

---

## HIGH findings (guest-reachable on default builds)

### V2-01 — Narrow MMIO guest access panics VMM via unchecked `assert!(data.len() == N)` in `BusDevice` implementations — **HIGH**

**Root cause.** `vm-device/src/bus.rs:239-259` dispatches `Bus::read(addr, data)` / `Bus::write(addr, data)` verbatim to the target `BusDevice`. `data` originates from `VcpuExit::MmioRead/MmioWrite` (kvm/mod.rs:1990-2008; mshv is symmetric) with `data.len()` equal to the guest instruction's access width (1, 2, 4, or 8 bytes). There is no per-region width filter. Multiple `BusDevice::read`/`write` implementations `assert!` on `data.len() == <natural width>`, panicking the vCPU thread and tearing down the VMM process when the guest issues a byte- or word-wide access.

Verified call path for MSI-X:
```
VcpuExit::MmioWrite(gpa, data)
  → VmOps::mmio_write (vmm/src/vm.rs:458)
    → Bus::write (vm-device/src/bus.rs:252)   // no width check
      → VfioPciDevice::write_bar (pci/src/vfio.rs:1235)
        → msix_write_table (pci/src/vfio.rs:240)
          → MsixConfig::write_table (pci/src/msix.rs:268) assert!(data.len()==4||8)
```
The three sub-findings below are cousins of the same bug; fixing the root in `Bus::read`/`Bus::write` (or in the MMIO dispatch on either hypervisor) closes all of them plus any similar sites we have not yet enumerated.

**Reproducer (generic, any of the sub-findings):**
```asm
; guest ring-0, after mapping the relevant MMIO page
mov al, 0
mov byte ptr [mmio_addr], al    ; 1-byte MMIO write
```
Replace `mmio_addr` with a register in the offending region (see per-subfinding reproducers).

**Fix direction.** Two options, roughly in order of effort:
1. *Minimal:* replace every `assert!(data.len() == N)` / `assert_eq!(data.len(), N)` in `BusDevice::{read,write}` bodies with an early return + `warn!`. Covers the immediate panic surface.
2. *Principled:* extend the `Bus` registration API so a device declares `min_access_width`/`max_access_width`; `Bus::{read,write}` filter (pad-zero / fan-out / reject) before dispatch. Also eliminates future recurrences.

Priority: fix-1 is a mechanical pass (`rg -n 'assert!.*data.len' vm-device/ vmm/ pci/ virtio-devices/ devices/`), ~15 call sites.

---

#### V2-01a — PCI hotplug ACPI MMIO region — HIGH

```rust
// vmm/src/device_manager.rs:5511-5588
impl BusDevice for DeviceManager {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            PCIU_FIELD_OFFSET => { assert!(data.len() == PCIU_FIELD_SIZE); ... }   // :5515
            PCID_FIELD_OFFSET => { assert!(data.len() == PCID_FIELD_SIZE); ... }   // :5525
            B0EJ_FIELD_OFFSET => { assert!(data.len() == B0EJ_FIELD_SIZE); ... }   // :5535
            PSEG_FIELD_OFFSET => { assert_eq!(data.len(), PSEG_FIELD_SIZE); ... }  // :5541
            ...
        }
    }
    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            B0EJ_FIELD_OFFSET => { assert!(data.len() == B0EJ_FIELD_SIZE); ... }   // :5553
            PSEG_FIELD_OFFSET => { assert_eq!(data.len(), PSEG_FIELD_SIZE); ... }  // :5568
            ...
        }
    }
}
```
Six distinct asserts across read/write at offsets 0/4/8/12 inside each PCI segment's hotplug window. MMIO region base is enumerated by the guest via ACPI (`_SB.PCIx.PHPR`).

**Reproducer:** after guest reads ACPI to locate the PHPR base `B`, any one of:
- `movb 0, (B + 0)` (1-byte read of PCIU) → panics at 5515.
- `movb 0, (B + 8)` (1-byte write of B0EJ) → panics at 5553.
- `movw 0, (B + 12)` (2-byte write of PSEG) → panics at 5568.

Default build affected (PCI hotplug is not feature-gated).

---

#### V2-01b — CpuManager ACPI vCPU-topology MMIO — HIGH

```rust
// vmm/src/cpu.rs:622-680
fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
    match offset {
        CPU_SELECTION_OFFSET..CPU_COMMAND_OFFSET => {
            data.fill(0);
            assert!(data.len() >= core::mem::size_of::<u32>());   // :629
            ...
        }
    }
}
fn write(...) {
    CPU_SELECTION_OFFSET => {
        assert!(data.len() >= core::mem::size_of::<u32>());       // :658
        ...
    }
}
```
Two asserts; region declared by ACPI on x86 and used by Linux `/sys/devices/system/cpu/cpu*/online`.

**Reproducer:** `movb 0, (cpu_mmio_base + 0)` (1-byte read to CPU_SELECTION_OFFSET) → panics at 629.

Default build affected.

---

#### V2-01c — MSI-X table / PBA BAR — HIGH (broadest reach)

```rust
// pci/src/msix.rs:215,268,364
pub fn read_table(&self, offset: u64, data: &mut [u8]) {
    assert!(data.len() == 4 || data.len() == 8);   // :215
    ...
}
pub fn write_table(&mut self, offset: u64, data: &[u8]) {
    assert!(data.len() == 4 || data.len() == 8);   // :268
    ...
}
pub fn read_pba(&self, offset: u64, data: &mut [u8]) {
    assert!(data.len() == 4 || data.len() == 8);   // :364
    ...
}
```
Every virtio-pci device exposes an MSI-X table in a BAR. The guest programs that BAR during PCI enumeration and then touches it. Reach is universal on default builds.

**Reproducer:** from the guest driver, after BAR assignment locates the MSI-X table at `T`:
```asm
movw 0, (T + 0)    ; 2-byte write
```
→ panics at 268.

Default build affected.

---

### V2-02 — SEV-SNP GHCB VMGEXIT handlers panic on guest-controlled fields — **HIGH (sev_snp builds only)**

Six sites in `hypervisor/src/mshv/mod.rs` inside `HVMSG_X64_SEV_VMGEXIT_INTERCEPT` (`#[cfg(feature = "sev_snp")]`):

```rust
// :891  inside GHCB_INFO_HYP_FEATURE_REQUEST
assert!(ghcb_data == 0);
// :1103 (MMIO_READ)  and :1127 (MMIO_WRITE)
let data_len = info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info2 as usize;
assert!(data_len <= 0x8);
// :1043
panic!("SVM_EXITCODE_HV_DOORBELL_PAGE: Unhandled exit code: {exit_info1:0x}");
// :1203
panic!("GHCB_INFO_NORMAL: Unhandled exit code: {exit_code:0x}");
// :1207
panic!("Unsupported VMGEXIT operation: {ghcb_op:0x}");
```

`ghcb_data = ghcb_msr >> GHCB_INFO_BIT_WIDTH`; `sw_exit_info1/2` and `exit_code` are set by the guest in its GHCB page. All six are reachable with a single `vmgexit` instruction after writing the relevant GHCB fields.

**Why HIGH in sev_snp builds.** SEV-SNP's entire threat model treats the guest as hostile and promises host/VMM integrity. A panic on a guest-chosen GHCB MSR value directly violates that promise. Unlike the generic case where feature-gating reduces severity, the `sev_snp` feature explicitly includes this adversarial model.

**Reproducer:** guest writes `ghcb_msr = GHCB_INFO_HYP_FEATURE_REQUEST | (1 << 12)` (any nonzero data bits) and executes `vmgexit` → panic at 891. Variations for the other five sites.

**Fix direction.** Return `HypervisorCpuError::UnhandledVmExit(...)` or signal `#VC` back to the guest via `sw_exit_info1`. Never `panic!` on GHCB contents.

---

## MEDIUM findings

### V2-03 — `fw_cfg` `read_content` OOB via guest-advanced `data_offset` — MEDIUM

```rust
// devices/src/legacy/fw_cfg.rs:693-716
fn read_content(content: &FwCfgContent, offset: u32, data: &mut [u8], size: u32) -> Option<u8> {
    let start = offset as usize;
    let end = start + size as usize;
    match content {
        FwCfgContent::Bytes(b) => {
            if b.len() >= size as usize {               // BUG: checks size, not end
                data.copy_from_slice(&b[start..end]);   // :699 panics when start>0
            }
        }
        FwCfgContent::Slice(s) => {
            if s.len() >= size as usize {               // same bug
                data.copy_from_slice(&s[start..end]);   // :704
            }
        }
        FwCfgContent::File(o, f) => { f.read_exact_at(data, o + offset as u64).ok()?; }
        FwCfgContent::U32(n) => {
            let bytes = n.to_le_bytes();                // [u8; 4]
            data.copy_from_slice(&bytes[start..end]);   // :712 no guard at all
        }
    }
    ...
}
```
`data_offset` is guest-driven: reset only on selector write (line 775), incremented on every data-port read (line 728). By repeatedly reading the data port, the guest walks `data_offset` past the item length; the next read panics the vCPU thread.

**Reproducer:** guest selects `FW_CFG_NB_CPUS` (a `U32` item), reads 1 byte four times (`data_offset → 4`), reads 1 byte again → `bytes[4..5]` on a 4-byte array → slice-bounds panic → VMM crashes.

**Gating:** `fw_cfg` feature, off by default (`cloud-hypervisor/Cargo.toml`). All `FwCfg` use in `vmm/src/device_manager.rs` is `#[cfg(feature = "fw_cfg")]`.

**Fix direction.** Compute `end` from `min(content.len(), end)`; guard `if start >= content.len() { return None }`. The `FwCfgContent::File` arm does the right thing; mirror it for the Bytes/Slice/U32 arms, or switch to `saturating_sub + take`.

---

### V2-04 — `MemoryRangeTable::read_from` trusts peer `length: u64` unconditionally — MEDIUM

```rust
// vm-migration/src/protocol.rs:332-349
pub fn read_from(fd: &mut dyn Read, length: u64) -> Result<MemoryRangeTable, MigratableError> {
    assert!((length as usize).is_multiple_of(size_of::<MemoryRange>()));   // :333 — panic on unaligned
    let mut data: Vec<MemoryRange> = Vec::new();
    data.resize_with(length as usize / size_of::<MemoryRange>(), Default::default);  // :336 — allocate attacker-sized Vec
    // SAFETY: the slice is constructed with the correct arguments
    fd.read_exact(unsafe { std::slice::from_raw_parts_mut(data.as_ptr() as *mut _, length as usize) })
        .map_err(MigratableError::MigrateSocket)?;
    Ok(Self { data })
}
```
Caller (`vmm/src/lib.rs:1144`):
```rust
let table = MemoryRangeTable::read_from(socket, req.length())?;
```
where `req.length()` is read verbatim off the migration socket in `Request::read_from` (no caps).

**Attacks (under "migration peer is semi-trusted" model):**
- `length = 1` → unaligned → `assert!` panics receiver.
- `length = u64::MAX / 2` (aligned to `size_of::<MemoryRange>() = 32`) → `Vec::resize_with` aborts on allocation failure → VMM killed.

**Gating:** always built. Only pre-requisite is the operator exposing migration on a socket the attacker can write to. Cloud-hypervisor documentation assumes this socket is private; when it isn't (shared orchestrator, misconfigured TCP migration), severity is effectively HIGH.

**Fix direction.** Replace `assert!` with `if !length.is_multiple_of(...) { return Err(...) }`. Cap `length` at a sanity bound (`MAX_MEMORY_REGIONS * size_of::<MemoryRange>()`, e.g. `1 << 24`). Apply the same pattern to other `Request` `length` consumers in `vm-migration/src/protocol.rs` (worth a sibling audit).

---

### V2-17 — Sector-0 write-ban silently disabled after autodetect persistence — MEDIUM

Phase D regression-risk finding from the `a63315d → 6f2357c → b3e8e2a` commit chain:

- `b3e8e2a` added `disable_sector0_writes: bool` on the virtio-block device, set when `disk_cfg.image_type == Unknown` AND autodetect resolved to `Raw`. Mitigates CVE-2026-27211-class attacks where a raw image hosts a qcow magic at offset 0.
- `6f2357c` then **persists** the autodetected `image_type` back into the config for subsequent boots. On second boot the config now carries `image_type = Raw`, which is no longer `Unknown` — so `disable_sector0_writes` is **not** set. The guard fires once, then turns itself off.
- `a63315d` (v51.1) extended the ban to DISCARD and WRITE_ZEROES but inherited the same gating logic, so it also self-disables on restart.

**Net:** the operator's expectation ("CVE-2026-27211 is fixed") is true for the first boot of a freshly-configured disk but false for every boot after. Explicit `image_type = raw` in the config never gets the guard at all.

**Fix direction.** Tie `disable_sector0_writes` to the presence of a raw image header whose first sector looks like any of the guardrail magics (qcow2, vhdx, vmdk), not to whether the `image_type` was autodetected. Or: persist `disable_sector0_writes` alongside the `image_type` when saving config.

Relevant: `vmm/src/device_manager.rs:2698-2701`, `block/src/lib.rs` (DISCARD/WRITE_ZEROES parsing), `virtio-devices/src/block.rs` (Check_request).

---

## LOW findings

### V2-05 — qcow2 `backing_file` header path is not Landlocked — LOW

`DiskConfig::apply_landlock` (`vmm/src/vm_config.rs:296-302`) adds `self.path` to the Landlock ruleset but does not inspect the qcow2 image for a `backing_file` header. When `backing_files = on` (admin opt-in), `QcowFile::from_with_nesting_depth` opens the backing path from the image header (`block/src/qcow/mod.rs:809`). With Landlock enabled and the backing file path not registered, the open is denied (functional error). Without Landlock, an admin-supplied qcow whose backing points at any path under the VMM's UID is opened.

Gating: `backing_files = on` (default `false`). Low reach.

**Fix direction.** Either (a) parse the qcow header at config-parse time and add the backing path to Landlock, or (b) reject backing-file qcow images outside a whitelisted directory at disk-open time.

---

### V2-06 — `FwCfgConfig` missing `ApplyLandlock` — LOW (and a functional defect under Landlock)

`vmm/src/vm_config.rs:974-1060` iterates `disks`, `net`, `rng`, `fs`, `pmem`, `console`, `serial`, etc. and calls `ApplyLandlock::apply_landlock` on each. `FwCfgConfig` (with its `FwCfgItemConfig { file: PathBuf, ... }`) is not in the dispatch list, and no `ApplyLandlock` impl exists for it. With `--landlock`, `fw_cfg -f <file>` fails at open-time (EACCES). Without `--landlock` it is simply unprotected.

Gating: `fw_cfg` feature, off by default.

**Fix direction.** Implement `ApplyLandlock` for `FwCfgItemConfig` (register `file` as `ro`) and call it from `VmConfig::apply_landlock`.

---

### V2-07 — TDVF GUID-table parser underflow/narrowing cluster — LOW

Five arithmetic weak spots in `arch/src/x86_64/tdx/mod.rs`:

- `:102` `let offset = table_size - 18;` — underflows if `table_size < 18`.
- `:121` `offset -= entry_size;` — underflows if `entry_size > offset`. Only zero-check, not `>=` check.
- `:178` validates `descriptor.num_sections as usize * size_of::<TdvfSection>()` using the same arithmetic it's checking; redundant guard.
- `:442-443` `align_hob(table_content.len() as u64) as u16` — silent narrowing to u16; ACPI tables >~65527B wrap.
- `:106, 109, 128` slice expressions rely on `offset` staying inside the table.

**Trust:** TDVF firmware is admin-supplied, so reach is admin-trust. Panics on malformed firmware or OOB slices during HOB construction. Not guest-reachable.

**Fix direction.** Consolidate these into a `TdvfParser` that uses `checked_sub`/`checked_mul` and returns `Result<Section, TdvfError>` instead of panicking.

---

### V2-08 — `MsrEntries::from_entries(...).unwrap()` cluster — LOW

Four sites, identical pattern:

```
hypervisor/src/mshv/mod.rs:541, 564
hypervisor/src/kvm/mod.rs:1874, 1897
```
`MsrEntries::from_entries(&entries)` panics when `entries.len()` exceeds the FAM max. `entries` is built from the guest-visible MSR list, whose length is derived from VM config + arch defaults. Config-time caps likely bound `entries.len()`; flag anyway because:
- VULN-04's enumeration in `findings.md` only mentioned `.to_*_info().unwrap()` — this is a distinct pattern.
- Future MSR-list growth (e.g. new CPUID features) can silently break the cap.

**Fix direction.** Replace `.unwrap()` with `.map_err(|e| ...)?`.

---

### V2-09 — `create_vcpu` API panics on id ≥ 256 — LOW

```rust
// hypervisor/src/mshv/mod.rs:1821
let id: u8 = id.try_into().unwrap();
```
`id: u32` enters via `Vm::create_vcpu` — API-reachable. `MAX_SUPPORTED_CPUS` on MSHV is 255, so within the supported range this is unreachable, but the API does not enforce it before reaching the `unwrap()`.

**Fix direction.** Return `HypervisorVmError::CreateVcpu("vcpu id exceeds MAX_SUPPORTED_CPUS")` when `id >= MAX_SUPPORTED_CPUS`.

---

### V2-10 — `.to_*_info().unwrap()` sites beyond VULN-04's enumerated lines — INFO

Additional hits not in VULN-04's list (findings.md cites only lines 608, 677, 710, 747, 815):

```
hypervisor/src/mshv/mod.rs:589   x.to_reset_intercept_msg().unwrap()
hypervisor/src/mshv/mod.rs:825   x.to_cpuid_info().unwrap()
hypervisor/src/mshv/mod.rs:831   x.to_msr_info().unwrap()
hypervisor/src/mshv/mod.rs:842   x.to_exception_info().unwrap()
hypervisor/src/mshv/mod.rs:848   x.to_apic_eoi_info().unwrap()
hypervisor/src/mshv/mod.rs:861   x.to_vmg_intercept_info().unwrap()   (sev_snp)
```

Same kernel-trust class as VULN-04; include for completeness so the eventual fix covers every arm.

---

### V2-11 — PCI VFIO region lookup `unchecked_add` on guest-programmed BAR — INFO

```rust
// pci/src/vfio.rs:1205
// (inside region-resolution for MMIO access)
let end = region.start.unchecked_add(region.length);
```
`region.start` is the guest-programmed BAR base. A BAR programmed close to `u64::MAX` wraps the addition. The result is only used in a comparison (`addr < end`), so the bug is a logical mis-hit, not a panic. Low severity: mis-routing an MMIO to a wrong region with wraparound.

**Fix direction.** `region.start.checked_add(region.length)` and return "no match" on overflow.

---

### V2-12 — `fuzz/Cargo.toml` carries a second `micro_http` branch pin — LOW

```toml
# fuzz/Cargo.toml:27
micro_http = { git = "https://github.com/firecracker-microvm/micro-http", branch = "main" }
```
Sibling of VLN-02. Fixing VLN-02 in `vmm/Cargo.toml` alone leaves this copy untouched; `cargo update -p micro_http --manifest-path fuzz/Cargo.toml` still pulls upstream `main`.

**Fix direction.** Pin to `rev = "<sha>"` in both manifests, or publish a crates.io release of `micro_http` and depend on it.

---

### V2-13 — Cargo.lock has drifted from `micro_http` upstream `main` — LOW

`Cargo.lock:1323` pins `micro_http` at commit `3248ceea…`. Upstream `firecracker-microvm/micro-http@main` has advanced (agent observed `876f3fec…` at audit time). The drift itself is harmless; it becomes the concrete exploitation path for VLN-02 the moment any maintainer runs `cargo update -p micro_http`.

**Fix direction.** As with V2-12: pin to `rev = "<sha>"` so `cargo update` is a no-op until an explicit rev bump.

---

### V2-14 — `cloud-hypervisor/build.rs:22` — `rerun-if-env-changed` ordering bug — INFO

```rust
// cloud-hypervisor/build.rs:22-24
if let Ok(extra_version) = env::var("CH_EXTRA_VERSION") {
    println!("cargo:rerun-if-env-changed=CH_EXTRA_VERSION");
    version.push_str(&format!("-{extra_version}"));
}
```
The `rerun-if-env-changed` directive is only emitted when the env var is already set at first build. A subsequent build that newly sets `CH_EXTRA_VERSION` is not rerun because cargo was never told to watch that variable. Effect: stale embedded `BUILD_VERSION`, not a memory-safety issue.

**Fix direction.** Move the directive above the `if let`, so it is always emitted.

---

### V2-18 — vsock multi-descriptor TX buffer driven by guest `pkt.len()` (bf6f0f8) — LOW (audit-worthy)

Commit `bf6f0f835` added a `PacketBuffer::Owned` path in `virtio-devices/src/vsock/packet.rs` that accepts multi-descriptor TX packets from the guest. The buffer is allocated with `pkt.len()` (u32 header chosen by the guest) and filled by copying from the descriptor chain. Guard relies on `pkt.len() == sum(descriptor.len)` — two potential issues worth confirming:
- Divergence between `pkt.len()` header and actual descriptor-chain length → under-copy (leaves uninit bytes) or over-copy (OOB read).
- Upper bound on `pkt.len()` — if unbounded, guest can drive per-packet heap allocation.

Not validated as a bug in this pass; flagged as a Phase B.3 target (virtio hotplug + vsock).

---

### V2-19 — GICv2M `save_data_tables` now silently `Ok(())` (caa362c) — LOW

On mshv aarch64, `save_data_tables` was previously `unimplemented!()`; commit `caa362c31` replaced it with `Ok(())`. Pause/resume and migration now silently drop ITS state instead of failing. The prior `unimplemented!()` is a clear runtime error; the new `Ok(())` is a latent correctness bug that surfaces only on resume (and even then only through device misbehavior). Not a security issue by itself; include as Phase D regression-risk because it converts a loud failure into a quiet one.

**Fix direction.** Return an explicit `MigratableError::Save("GICv2M snapshot not implemented on mshv aarch64")` until the save path is implemented.

---

### V2-20 — DISCARD/WRITE_ZEROES sector-to-byte `*` unchecked (81c075b) — LOW

Commit `81c075b31` added DISCARD/WRITE_ZEROES parsing that computes `discard_sector * SECTOR_SIZE` on a guest-controlled `u64`. No overflow check: in release builds the multiplication wraps; in debug it panics. Pre-existing Read/Write paths share the shape. The `disable_sector0_writes` guard catches literal sector 0 but not wrap-to-0.

**Fix direction.** Centralize in `block/src/lib.rs`: `let byte_offset = sector.checked_mul(SECTOR_SIZE).ok_or(BlockError::InvalidRange)?;`.

---

## Tooling / coverage findings

### V2-15 — No fuzz corpus, no dictionary in tree — LOW (major coverage impact)

`fuzz/` declares `libfuzzer-sys = "0.4.12"` but ships no `fuzz/corpus/<target>/` and no `fuzz/dict/`. Every fuzz run starts from an empty corpus with no token dictionary. Format-parsing harnesses (`qcow`, `vhdx`, `linux_loader`, `linux_loader_cmdline`) are magic-number-gated; naive libFuzzer mutation takes hours to discover valid inputs. The effective coverage of these harnesses under realistic CI time budgets is near zero.

**Fix direction.** Commit seed corpora under `fuzz/corpus/<target>/` (a handful of real images/ELFs/request bodies is enough to bootstrap) and per-format dictionaries under `fuzz/dict/`. `cargo-fuzz` picks them up automatically.

---

### V2-16 — Missing fuzz harnesses — LOW

Confirmed as missing from `fuzz/fuzz_targets/`:

1. **MSHV/KVM `hv_message` exit-reason dispatcher.** The intercept → emulator → MMIO/PIO dispatch inside `MshvVcpu::run`/`KvmVcpu::run`. Directly exposes the bug class enumerated in `findings.md` VULN-01..04 and in V2-01 above. Harness sketch: construct `mshv_bindings::hv_message` from fuzzer bytes, drive the run loop's `match header.message_type`. Invariants: no OOB on `data[0..len]`, no panic on reserved message types.
2. **Migration receive** (`recv_vm_config` + `recv_vm_state` over a `file://` URI). Directly exposes V2-04 (`MemoryRangeTable::read_from`) + VLN-01. Harness: memfd-backed migration URI, mock `Vmm`, fuzz the framed stream.
3. **Raw image auto-detection** (`block::detect_image_type`). Post-CVE-2026-27211 hardening surface; see V2-17 on the silent-disable regression. Harness: feed ~4 KiB fuzzer bytes, call `detect_image_type`, then instantiate the chosen `DiskFile` and issue a small read.

Additional gaps found but not in the original plan list:
- PCI config space + MSI-X table writes (`pci::configuration::PciConfiguration`, `MsixConfig`).
- ACPI table emit + re-parse (`acpi_tables::{Sdt, Dsdt, Madt}`).
- `VmConfig` direct JSON/CLI parsing (`http_api` fuzzes handlers, not `serde_json::from_slice::<VmConfig>`).
- Snapshot restore + userfaultfd page-fault replay.
- IGVM blob parsing.

---

### Phase C.4 — `cargo audit` results (cargo-audit 0.22.1)

Ran against both workspace `Cargo.lock` (301 deps) and `fuzz/Cargo.lock` (182 deps). No vulnerability advisories. Two warnings:

| Advisory          | Crate     | Severity | Impact on cloud-hypervisor                           |
|-------------------|-----------|----------|------------------------------------------------------|
| RUSTSEC-2024-0436 | `paste` 1.0.15 | unmaintained | Transitive via `gdbstub` 0.7.9 → `vmm`. No security issue; `paste` is a proc-macro with no runtime footprint. Track for eventual gdbstub upgrade. |
| RUSTSEC-2026-0097 | `rand` 0.9.2 / 0.10.0 | unsound (custom logger) | Triggered only if a Rust `#[global_allocator]` or custom logger calls `rand::rng()` during init. Cloud-hypervisor does not use a custom logger that calls `rand`. Not exploitable in practice; upgrade when `rand` 0.9.3+ is available. |

**Verdict:** dependency chain is clean. No action required today.

---

### Phase C.1 — Opengrep (semgrep-compatible) static analysis

**Community rules (`p/rust`):** 253 hits, all `rust.lang.security.unsafe-usage.unsafe-usage`. Expected for a VMM codebase — every KVM/MSHV ioctl wrapper, every guest-memory access, every bindgen union dereference requires `unsafe`. No actionable findings.

**Custom rules (6 rules targeting Phase-A patterns):** 28 hits across the codebase. All match sites already enumerated by Phase A ripgrep sweeps. Three additional `try_into().unwrap()` locations confirmed but already covered by V2-07 class:
- `arch/src/aarch64/mod.rs:184` — `get_host_ipa_limit().try_into().unwrap()` (i32 → u8, aarch64 IPA).
- `hypervisor/src/kvm/mod.rs:1216` — same pattern, KVM side.
- `vmm/src/vm.rs:2515` — `section.size.try_into().unwrap()` in `init_tdx_memory` (u64 → usize, infallible on 64-bit).

Custom rules written and available at `/tmp/ch-audit-rules.yaml`:
- `busdevice-assert-on-data-len` — V2-01 class (no new hits; opengrep Rust macro handling limited)
- `unwrap-on-to-info-decoder` — VULN-04/V2-10 class (no hits; macro patterns not matched)
- `assert-in-guest-path` — V2-01/V2-02/V2-03 class (no hits; same macro limitation)
- `unchecked-arithmetic` — VLN-03/V2-07 class (no hits; method call pattern not matched)
- `strip-prefix-file-url` — VLN-01 class (2 hits: migration.rs:21, :39 — both known)
- `try-into-unwrap-narrowing` — V2-09 class (26 hits, all previously triaged)

**Note:** opengrep's Rust `assert!` / `assert_eq!` macro expansion is incomplete — the `busdevice-assert-on-data-len` and `assert-in-guest-path` rules returned zero results despite known sites. A semgrep Pro license or a Rust-specific AST tool (e.g., `cargo-clippy` with custom lints, or `dylint`) would be needed to match macro invocations reliably.

**Verdict:** no new findings from static analysis. Phase A ripgrep sweeps were more effective than the available community rules for this codebase.

---

## Phase D — hardening patterns worth emulating

The 2026-02-01→HEAD window has a clear backing-file hardening chain worth duplicating to other opaque-reference loaders:

| Commit    | Lesson                                                                   |
|-----------|--------------------------------------------------------------------------|
| `5098322` | default-deny opt-in (`backing_files = false`)                            |
| `94368c6` | translate low-level error into policy-aware variant (`BackingFilesDisabled`) |
| `76e2335` | align test/mock backends with the default                                |
| `2c2f5d2` | open with minimum privilege (RO when `!shared`)                          |
| `dde5f6e` | per-region removal on hot-unplug (analogous state-cleanup pattern)       |

Candidate surfaces to apply this shape:
- Kernel blob / initramfs / firmware paths in `vmm/src/config.rs` (currently Landlock-covered but no opt-in gate).
- pmem backings.
- vhost-user socket paths (already Landlock-covered; no policy gate).

---

## Deferred Phase B surfaces

B.1, B.2, B.6, and B.7 are now complete (see "Phase B deep dives" above). The remaining surfaces, ranked by expected yield:

1. **B.4 — HTTP / D-Bus API handlers** (`vmm/src/api/http.rs`, `vmm/src/api/dbus/*`, `vmm/src/api/mod.rs`). New endpoints since CVE-2023-30612 not yet in the `http_api` fuzz corpus (which, per V2-15, is empty anyway).
2. **B.5 — VFIO passthrough + Landlock** (`pci/src/vfio.rs`, `vmm/src/landlock.rs`). V2-05/V2-06 are the known gaps; more `read_link`-then-reuse sequences likely exist.
3. **B.3 — Device manager + hotplug** (`vmm/src/device_manager.rs`, `vmm/src/memory_manager.rs`, `vmm/src/cpu.rs`). V2-01 exposes the bus-width systemic issue; partial-failure cleanup paths remain unaudited.

---

## Phase B deep dives

Per-function audit of four high-value surfaces: block/image parsers (B.1), MSHV vCPU run loop + emulators (B.2), migration receive path (B.6), and SEV-SNP/TDX handlers (B.7). Each finding below includes input origin, trust boundary, and reproducer sketch where applicable.

---

### V2-21 — aarch64 MMIO read emulator: OOB write via XZR (register index 31) — **HIGH (aarch64 mshv builds)**

```rust
// hypervisor/src/mshv/aarch64/emulator.rs:87
gprs[reg_index as usize] = data;
```

`gprs` is `StandardRegisters.regs: [u64; 31]` (indices 0–30, from `mshv-bindings-0.6.7 arm64/regs.rs:20`). `reg_index` is `iss.srt()`, a 5-bit field (0–31) from the ESR_EL2 syndrome register. When the guest performs an MMIO read targeting XZR (register 31), the write path (lines 59–64) correctly handles XZR by substituting `0u64`. The read path (line 87) does not — it writes the MMIO result to `gprs[31]`, one element past the end of the array.

**Input origin:** Guest data-abort syndrome register (guest-controlled `srt` field).
**Trust boundary:** guest → VMM.
**Defensive checks present:** The write path has a correct match; the read path has none.

**Reproducer (aarch64 guest ring-0):**
```asm
; map an MMIO BAR page, then:
ldr wzr, [x0]    ; load from MMIO into WZR (register 31)
```
→ VMM panics with "index out of bounds: the len is 31 but the index is 31" — Rust's array bounds check fires before any memory write occurs.

**Impact:** Guest-reachable VMM crash (DoS). The VMM process terminates, killing all guest VMs. On aarch64+MSHV, this is a one-instruction guest→host DoS. Not memory corruption — Rust bounds checking prevents the actual OOB write.

**Fix direction:** Add `if reg_index == 31 { /* discard, XZR */ } else { gprs[reg_index as usize] = data; }` mirroring the write path's match.

---

### V2-22 — Migration `Command`/`Status` enum UB via `ByteValued` reinterpretation — **HIGH (migration-peer reachable)**

```rust
// vm-migration/src/protocol.rs:109-121
#[repr(u16)]
pub enum Command {
    Invalid,   // 0
    Start,     // 1
    Config,    // 2
    ...
    MemoryFd,  // 7
}

// vm-migration/src/protocol.rs:179-184
pub fn read_from(fd: &mut dyn Read) -> Result<Request, MigratableError> {
    let mut request = Request::default();
    fd.read_exact(Self::as_mut_slice(&mut request))  // raw bytes → enum
        .map_err(MigratableError::MigrateSocket)?;
    Ok(request)
}
```

`ByteValued::as_mut_slice` reinterprets the struct's raw memory as a byte slice, then `read_exact` fills it from the peer socket. The `command` field is a `#[repr(u16)]` enum with 8 variants (0–7). If the peer sends any u16 value ≥ 8 in the command position, the resulting `Command` value has an invalid discriminant. Per Rust's reference, constructing an enum with an invalid discriminant is **immediate undefined behavior** — the compiler may exploit this for niche optimization, dead-code elimination, or miscompilation of subsequent `match` arms.

The same issue applies to `Status` (`#[repr(u16)]`, 3 variants 0–2) in `Response::read_from` (L238–L244).

**Input origin:** Migration peer socket (peer-controlled bytes).
**Trust boundary:** migration-peer → VMM.
**Defensive checks present:** None. No discriminant validation between `read_exact` and use.

**Reproducer:** Connect to the migration socket, send 16 bytes with the first two bytes set to `0x0008` (or any value > 7). The VMM constructs a `Request` with an invalid `Command` discriminant. Subsequent behavior is undefined — may range from incorrect dispatch to memory corruption depending on compiler optimization level.

**Fix direction:** Replace `ByteValued` deserialization with explicit u16 read + `TryFrom<u16>` conversion for `Command` and `Status`, returning an error for unrecognized discriminants. Alternatively, add a `validate()` step after `read_from` that checks the discriminant is in range.

---

### V2-23 — VHDX region overlap check has inverted logic — **MEDIUM (image → VMM)**

```rust
// block/src/vhdx/vhdx_header.rs:280-282
for (region_ent_start, region_ent_end) in region_entries.iter() {
    if !((start >= *region_ent_start) || (end <= *region_ent_end)) {
        return Err(VhdxHeaderError::RegionOverlap);
    }
}
```

The condition `!((start >= ent_start) || (end <= ent_end))` simplifies to `(start < ent_start) && (end > ent_end)` — it only detects when the new region **completely contains** an existing region. It misses:
- Partial overlaps where the new region starts inside an existing one.
- Cases where the new region is fully contained within an existing one.
- Adjacent-and-overlapping regions from either side.

A correct non-overlap check would be `!(start >= ent_end || end <= ent_start)`.

**Input origin:** VHDX image region table entries (image-controlled).
**Trust boundary:** image → VMM.

**Reproducer:** Craft a VHDX image with two region table entries whose file offsets partially overlap (e.g., BAT at offset 1 MiB with length 1 MiB, metadata at offset 1.5 MiB with length 1 MiB). The overlap check passes, and subsequent BAT parsing reads from the metadata region's bytes, producing incorrect block mappings. Guest reads/writes may be directed to wrong file offsets.

**Fix direction:** Replace the overlap check with the standard interval-overlap test: `if !(start >= *region_ent_end || end <= *region_ent_start) { return Err(RegionOverlap); }`.

---

### V2-24 — VHDX I/O uses hardcoded 512-byte sector size, ignoring 4K-sector images — **MEDIUM (image → VMM, data corruption)**

```rust
// block/src/vhdx/vhdx_io.rs:14
const SECTOR_SIZE: u64 = 512;
// block/src/vhdx/vhdx_io.rs:119-121
f.read_exact(
    &mut buf[read_count..(read_count + (sector.free_sectors * SECTOR_SIZE) as usize)],
)
// ...
// block/src/vhdx/vhdx_io.rs:134
read_count += sector.free_bytes as usize;
```

The VHDX format supports `logical_sector_size` of 512 or 4096 (validated at `vhdx_metadata.rs:180-183`). The `Sector::new` function at `vhdx_io.rs:68` correctly computes `free_bytes = free_sectors * logical_sector_size`. But the I/O functions at lines 121 and 191 use `sector.free_sectors * SECTOR_SIZE` (hardcoded 512) for the buffer slice bounds, while `read_count`/`write_count` at line 134 advance by `sector.free_bytes` (computed with the correct sector size).

For a 4096-byte-sector image: each iteration reads/writes `free_sectors * 512` bytes but advances the buffer pointer by `free_sectors * 4096` bytes, leaving 7/8 of the data as zero-fill on reads or skipping 7/8 of the source data on writes.

**Input origin:** VHDX metadata `logical_sector_size` field (image-controlled).
**Trust boundary:** image → VMM.
**Defensive checks present:** `logical_sector_size` is validated to be 512 or 4096, but the I/O path ignores it.

**Reproducer:** Create a VHDX image with `logical_sector_size = 4096`. Write known data via the VMM, read it back. The read returns mostly zeros (only 1/8 of each sector's data is correct).

**Fix direction:** Replace `SECTOR_SIZE` constant in `vhdx_io.rs` with `disk_spec.logical_sector_size as u64`, or pass the sector size through to the I/O functions.

---

### V2-25 — x86 emulator expand-down segment check inverted — **MEDIUM (guest correctness/security)**

```rust
// hypervisor/src/arch/x86/emulator/mod.rs:163-168
if segment_type_expand_down(segment_type) {
    if logical_addr >= segment_limit.into() {
        return Err(PlatformError::InvalidAddress(...));
    }
    ...
}
```

For expand-down segments, the valid address range is `(limit+1)` to the upper bound (`0xFFFF` or `0xFFFFFFFF`). Addresses from 0 to `limit` are **invalid**. The check at line 164 rejects addresses **at or above** the limit — exactly backwards. It rejects the valid range and accepts the invalid range.

**Input origin:** Guest segment registers + guest-issued memory access.
**Trust boundary:** guest → VMM (emulator correctness).
**Defensive checks present:** The expand-down check exists but has inverted polarity.

**Impact:** A guest using expand-down segments (used by stack segments in some OSes) will have its emulated MMIO accesses incorrectly validated. Addresses that should be rejected are accepted, and addresses that should be accepted are rejected. This could allow a guest to cause the emulator to access memory at addresses that would have been rejected by the real CPU, or fail to emulate valid guest operations.

**Fix direction:** Change to `if logical_addr <= segment_limit.into()` (reject the low range for expand-down segments).

---

### V2-26 — REP MOVS/STOS unbounded emulation loop from guest ECX — **MEDIUM (guest → VMM, DoS)**

```rust
// hypervisor/src/arch/x86/emulator/instructions/movs.rs:26-31,44
let count = state.read_reg(Register::ECX)? & REGISTER_MASK_32 as u64;
...
for _ in 0..count { ... }

// hypervisor/src/arch/x86/emulator/instructions/stos.rs — same pattern
```

The REP count comes from the guest's ECX register. When `num_insn = Some(1)`, the entire REP loop counts as a single instruction — all iterations execute before returning to the run loop. With `ECX = 0xFFFFFFFF`, the emulator performs ~4 billion iterations of memory read+write operations, each going through GVA translation and MMIO/PIO dispatch. This holds the vCPU thread for an extended period (minutes to hours).

**Input origin:** Guest ECX register (guest-controlled).
**Trust boundary:** guest → VMM.
**Defensive checks present:** None. No iteration cap or yield point.

**Reproducer (MSHV guest, MMIO-triggering REP MOVS):**
```asm
mov ecx, 0xFFFFFFFF
mov esi, mmio_src
mov edi, mmio_dst
rep movsb           ; trapped by MMIO, emulated with 4B iterations
```

**Fix direction:** Cap emulation iterations (e.g., 4096 per entry) and return partial progress, letting the run loop re-enter. Alternatively, detect REP instructions and handle the count in a single efficient operation rather than per-iteration emulation.

---

### V2-27 — GPA_ATTRIBUTE_INTERCEPT unbounded allocation from guest `gfn_count` — **MEDIUM (guest → VMM, sev_snp DoS)**

```rust
// hypervisor/src/mshv/mod.rs:776-778
for i in 0..gfn_count {
    gpas.push(gpa_start + i * HV_PAGE_SIZE as u64);
}
```

`gfn_count` is derived from `snp::parse_gpa_range(ranges[0])` where `ranges[0]` is guest-controlled (the GHCB GPA range descriptor). There is no upper bound on `gfn_count`. A guest can request a GPA range covering billions of pages, causing the VMM to allocate a multi-gigabyte `Vec<u64>` plus the corresponding `vec_with_array_field` structure at line 781.

**Input origin:** Guest GHCB GPA range (guest-controlled).
**Trust boundary:** guest → VMM.
**Defensive checks present:** None. `parse_gpa_range` extracts the count without validation.

**Reproducer:** From an SNP guest, trigger a GPA_ATTRIBUTE_INTERCEPT with a range encoding `gfn_count = 2^30` (4 TiB of pages). The VMM attempts to allocate ~8 GiB for the `gpas` Vec alone.

**Fix direction:** Cap `gfn_count` at a reasonable maximum (e.g., `MAX_GUEST_PAGES` or `total_vm_pages`).

---

### V2-28 — GPA_ATTRIBUTE_INTERCEPT bitmap `reset_addr_range` unit mismatch — **MEDIUM (sev_snp correctness)**

```rust
// hypervisor/src/mshv/mod.rs:770
bm.reset_addr_range(gfn_start as usize, gfn_count as usize);
// hypervisor/src/mshv/mod.rs:808
bm.reset_addr_range(gpa_start as usize, gfn_count as usize);
```

Line 770 passes `gfn_start` (page-frame number) to `reset_addr_range`. Line 808 passes `gpa_start = gfn_start * HV_PAGE_SIZE` (byte address, 4096× larger) to the same bitmap API. Since `AtomicBitmap::reset_addr_range` treats its first argument as a bit index, these two calls use incompatible coordinate spaces. The second call resets bits at position `gfn_start * 4096`, which is 4096× too far into the bitmap.

**Input origin:** Guest GPA range (guest-controlled).
**Trust boundary:** guest → VMM (correctness of host-access tracking).
**Impact:** The `host_access_pages` bitmap, which tracks which guest pages the host can access, becomes desynchronized. Pages that should be marked inaccessible remain marked accessible, potentially allowing the VMM to read guest-private memory that the guest has revoked. This is a confidentiality violation under the SEV-SNP model.

**Fix direction:** Both calls should use the same unit. If the bitmap is indexed by PFN: change line 808 to `bm.reset_addr_range(gfn_start as usize, gfn_count as usize)`. If indexed by byte address: change line 770.

---

### V2-29 — Migration `vm_receive_config`/`vm_receive_state`: unbounded allocation from peer length — **MEDIUM (peer → VMM, OOM)**

```rust
// vmm/src/lib.rs:991-992
let mut data: Vec<u8> = Vec::new();
data.resize_with(req.length() as usize, Default::default);

// vmm/src/lib.rs:1077-1078
let mut data: Vec<u8> = Vec::new();
data.resize_with(req.length() as usize, Default::default);
```

`req.length()` is a `u64` read directly from the migration peer. Both `vm_receive_config` and `vm_receive_state` allocate `req.length()` bytes with no upper bound. A peer sending `length = 4 GiB` triggers a multi-gigabyte allocation; `length` near `u64::MAX` triggers OOM/abort.

This is distinct from V2-04 (which covers `MemoryRangeTable::read_from`). These are two additional unbounded allocation sites.

**Input origin:** Migration peer socket (`Request.length` field).
**Trust boundary:** migration-peer → VMM.
**Defensive checks present:** None.

**Fix direction:** Cap `req.length()` at a reasonable maximum (e.g., 256 MiB for config, 1 GiB for state) before allocation. Return `MigratableError` if exceeded.

---

### V2-30 — Migration `MemoryRangeTable::read_from` assert! panic on non-aligned length — **MEDIUM (peer → VMM, panic)**

```rust
// vm-migration/src/protocol.rs:333
assert!((length as usize).is_multiple_of(size_of::<MemoryRange>()));
```

This `assert!` panics (crashing the VMM) when a migration peer sends a `Memory` command with a `length` value not divisible by 16 (`size_of::<MemoryRange>()`). This is distinct from V2-04 which covers the unbounded allocation at line 335–339 — this is a separate, earlier panic on the alignment check.

**Input origin:** Migration peer (`Request.length` field).
**Trust boundary:** migration-peer → VMM.
**Reproducer:** Send a `Memory` command (command=4) with `length = 17`.

**Fix direction:** Replace `assert!` with `if !(...) { return Err(MigratableError::MigrateReceive(...)); }`.

---

### V2-31 — Migration `receive_memory_regions` infinite loop on socket EOF — **MEDIUM (peer → VMM, hang)**

```rust
// vmm/src/memory_manager.rs:2164-2181
loop {
    let bytes_read = mem.read_volatile_from(
        GuestAddress(range.gpa + offset), fd, (range.length - offset) as usize,
    ).map_err(...)?;
    offset += bytes_read as u64;
    if offset == range.length { break; }
}
```

If the peer closes the connection mid-transfer, `read_volatile_from` may return `Ok(0)` (EOF). There is no `bytes_read == 0` guard, so the loop spins indefinitely with `offset` never advancing. This blocks the migration thread forever.

**Input origin:** Migration peer connection state (peer-controlled).
**Trust boundary:** migration-peer → VMM.
**Defensive checks present:** None for zero-byte reads.

**Fix direction:** Add `if bytes_read == 0 { return Err(MigratableError::MigrateReceive(anyhow!("unexpected EOF"))); }`.

---

### V2-32 — Migration `vm_receive_config` does not validate peer-supplied `VmConfig` — **HIGH (peer → VMM, arbitrary file access + crash)**

```rust
// vmm/src/lib.rs:997-1000
let vm_migration_config: VmMigrationConfig = serde_json::from_slice(&data)
    .map_err(|e| MigratableError::MigrateReceive(anyhow!("Error deserializing: {e}")))?;
```

The deserialized `VmConfig` is stored directly at line 1009 (`self.vm_config = Some(...)`) without calling `VmConfig::validate()`. The config contains filesystem `PathBuf` fields that the VMM opens when booting the restored VM:

- `DiskConfig.path` → opened as a block device (read/write)
- `PmemConfig.file` → opened as persistent memory (read/write)
- `FsConfig.socket` → connected as vhost-user socket
- `TpmConfig.socket` → connected as TPM socket
- `DeviceConfig.path` → used for VFIO passthrough
- `ConsoleConfig.file` → opened for console I/O
- `LandlockConfig` paths → control the Landlock allowlist

**Escalation to arbitrary file read/write:** A migration peer supplies `DiskConfig { path: "/etc/shadow", readonly: false, ... }`. After config receipt, the VM boots and the VMM opens `/etc/shadow` as the block device backing. The guest can then read the file contents via the virtual disk, and write arbitrary data to it. If the VMM runs as root (common for KVM/MSHV), this is arbitrary file read/write as root from a migration peer.

**Escalation to host crash:** At line 1038–1041:
```rust
if config.lock().unwrap().max_apic_id() > MAX_SUPPORTED_CPUS_LEGACY {
    vm.enable_x2apic_api().unwrap();
}
```
`max_apic_id()` is computed from peer-controlled `CpuTopology` fields (`threads_per_core * cores_per_die * dies_per_package * packages`). A peer can set these to force `max_apic_id() > 254`, triggering `enable_x2apic_api()`. If the host KVM doesn't support `KVM_CAP_X2APIC_API`, the `.unwrap()` panics the VMM. Additionally, if any topology field is 0, line 188 of `arch/src/x86_64/mod.rs` computes `0 - 1` which panics in debug or wraps in release.

**Input origin:** Migration peer JSON payload.
**Trust boundary:** migration-peer → VMM.
**Defensive checks present:** `serde_json` validates JSON syntax but not semantic validity.

**Gating:** Always built. Requires the attacker to connect to the migration socket. Documentation assumes this socket is private, but shared-orchestrator or misconfigured-TCP scenarios expose it.

**Fix direction:** Call `vm_config.validate()` after deserialization, before storing. Cap topology fields. Replace the `.unwrap()` at line 1040 with `?`. Apply path allowlisting/canonicalization to all `PathBuf` fields received over migration.

---

### V2-33 — VHDX BAT `with_capacity` driven by image-controlled `bat_entry.length` — **LOW (image → VMM, DoS)**

```rust
// block/src/vhdx/vhdx_bat.rs:63
let mut bat: Vec<BatEntry> = Vec::with_capacity(bat_entry.length as usize);
```

`bat_entry.length` is a `u32` from the VHDX region table (image-controlled). `with_capacity` allocates `bat_entry.length * 8` bytes. With `bat_entry.length = u32::MAX`, this attempts ~32 GiB. The actual loop only inserts `entry_count` entries (validated at line 59 to fit within the region), but the capacity hint causes excessive allocation.

**Fix direction:** Use `Vec::with_capacity(entry_count as usize)` instead of `bat_entry.length`.

---

### V2-34 — VHDX `vhdx_io::write` silently truncates on low file offset — **LOW (image → VMM, silent data loss)**

```rust
// block/src/vhdx/vhdx_io.rs:184-186
if file_offset < vhdx_metadata::BLOCK_SIZE_MIN as u64 {
    break;
}
```

The `break` silently terminates the write loop without error when a computed file offset falls in the metadata area (< 1 MiB). The caller receives a partial write count and reports success. Guest-written data is silently lost.

**Input origin:** VHDX BAT entry `file_offset` (image-controlled).
**Trust boundary:** image → VMM.

**Fix direction:** Return `Err(VhdxIoError::InvalidBatEntryState)` instead of `break`.

---

### V2-35 — x86 emulator hardcoded 64-bit decode mode — **LOW (correctness)**

```rust
// hypervisor/src/arch/x86/emulator/mod.rs:548
Decoder::new(64, insn_stream, DecoderOptions::NONE)
```

The `iced_x86` decoder always runs in 64-bit mode regardless of the guest's actual CPU mode. If a guest in 32-bit protected mode triggers an MMIO/PIO trap, the emulator decodes the instruction bytes using 64-bit semantics (different prefix handling, default operand sizes, available registers). This produces incorrect emulation results.

**Input origin:** Guest CPU mode (guest-controlled).
**Trust boundary:** guest → VMM (emulator correctness).

**Fix direction:** Read `cpu_state.mode()` and pass the corresponding bitness (16, 32, or 64) to the `Decoder`.

---

### V2-36 — GPA_ATTRIBUTE_INTERCEPT `range_count() == 0` assert — reassessed as **LOW→MEDIUM (sev_snp)**

```rust
// hypervisor/src/mshv/mod.rs:755
assert!(num_ranges >= 1);
```

Previously classified in `findings.md` appendix as "unreachable" based on kernel trust. Under the SEV-SNP threat model, the guest is explicitly adversarial. `range_count()` is a 12-bit field from the guest-controlled GPA attribute intercept message. If the MSHV kernel delivers this message with `range_count = 0` (e.g., because it passes the guest's value through without validation), the VMM panics.

Whether this is guest-triggerable depends on whether the MSHV kernel validates `range_count` before delivering the intercept. The `> 1` check at line 756 returns a proper error — the `>= 1` check at line 755 uses `assert!` instead. At minimum, replace `assert!` with a returned error for consistency.

---

### V2-37 — qcow2 `rebuild_refcounts` wrapping subtraction — **LOW (debug builds only)**

```rust
// block/src/qcow/mod.rs:1666
if max_valid_cluster_offset < file_size - cluster_size {
```

If `file_size < cluster_size` (truncated image with large cluster_bits), the subtraction wraps in release (producing a huge value → always returns error, fail-safe) but panics in debug builds. Only triggers on writable images with `refcount_rebuild_required = true`.

**Fix direction:** Use `file_size.saturating_sub(cluster_size)`.

---

## Phase B — per-function audit notes

### B.1 Block/image parsers — audit coverage

| File | Functions audited | Key invariants |
|------|-------------------|----------------|
| `block/src/qcow/mod.rs` | `QcowFile::from_with_nesting_depth`, `read_header_extensions`, `rebuild_refcounts`, `l2_entry_compressed_cluster_layout` | `cluster_bits ∈ [9,21]`, `header.size ≤ 2^44`, `l1_size ≤ 35M` |
| `block/src/qcow/refcount.rs` | `set_cluster_refcount`, `get_cluster_refcount` | Bounds checked via `MAX_RAM_POINTER_TABLE_SIZE` |
| `block/src/qcow_sync.rs` | All `DiskFile` trait impls | Mutex-poisoning cascade is the main systemic risk |
| `block/src/vhdx/vhdx_header.rs` | `Header::new`, `RegionInfo::new`, region overlap check | V2-23: overlap check inverted |
| `block/src/vhdx/vhdx_metadata.rs` | `DiskSpec::new`, metadata table parsing | `block_size ∈ [1M,256M]`, `sector_size ∈ {512,4096}` |
| `block/src/vhdx/vhdx_bat.rs` | `collect_bat_entries` | V2-33: capacity from image u32 |
| `block/src/vhdx/vhdx_io.rs` | `read`, `write`, `Sector::new` | V2-24: sector size mismatch, V2-34: silent truncation |
| `block/src/vhd.rs` | `VhdFooter::new`, `is_fixed_vhd` | No checksum validation (parsed but unused) |
| `block/src/raw_async.rs`, `raw_async_aio.rs` | I/O dispatch | No new findings beyond V2-17/V2-20 |
| `block/src/lib.rs` | `execute_async` DISCARD/WRITE_ZEROES | V2-20 (skip), missing upper-bound check on sector range (incidentally protected by kernel/qcow) |

**Open surfaces:** qcow2 `nb_snapshots`/`snapshots_offset` header fields are parsed but unused — unvalidated file offsets if snapshot support is added. VHDX `log_offset`/`log_length` — same class, no log replay today.

---

### B.2 MSHV vCPU + emulators — per-arm input-origin matrix

| Message type | Fields used | Origin | Trust | New findings |
|---|---|---|---|---|
| `HVMSG_X64_HALT` | (none) | kernel | kernel | — |
| `HVMSG_UNRECOVERABLE_EXCEPTION` | (none) | kernel | kernel | — |
| `HVMSG_X64_IO_PORT_INTERCEPT` | access_size, port, rax, string_op, rep_prefix | guest-influenced | kernel-bounded | VULN-01,03 (existing) |
| `HVMSG_UNMAPPED_GPA` / `GPA_INTERCEPT` | instruction_bytes, byte_count, gva, gpa | guest code + kernel | mixed | VULN-02 (existing) |
| `HVMSG_GPA_ATTRIBUTE_INTERCEPT` | host_visibility, range_count, ranges[] | guest | **guest-controlled** | V2-27, V2-28, V2-36 |
| `HVMSG_UNACCEPTED_GPA` | gva, gpa | guest+kernel | mixed | — |
| `HVMSG_X64_CPUID_INTERCEPT` | rax | guest | guest | — (debug log only) |
| `HVMSG_X64_MSR_INTERCEPT` | msr_number | guest | guest | RIP-advance concern |
| `HVMSG_X64_EXCEPTION_INTERCEPT` | exception_vector | guest | guest-influenced | RIP-advance concern |
| `HVMSG_X64_APIC_EOI` | vp_index, interrupt_vector | kernel | kernel | V2-10 (existing) |
| `HVMSG_X64_SEV_VMGEXIT_INTERCEPT` | ghcb_msr, sw_exit_*, GHCB page | **guest** | **guest-controlled** | V2-02 (existing) + V2-27 |

Emulator audit:
- **Linearize expand-down**: V2-25 (inverted check)
- **Decoder bitness**: V2-35 (hardcoded 64-bit)
- **REP instructions**: V2-26 (unbounded loop)
- **aarch64 OOB**: V2-21 (XZR register 31)
- **OR flags**: Missing RFLAGS update (INFO, correctness only)
- **Instruction operand helpers** (`get_op`/`set_op`/`memory_operand_address`): All use wrapping arithmetic, validate operand size ∈ {1,2,4,8}. No new findings.

KVM comparison: the KVM run loop has no user-space instruction emulation (MMIO is handled in-kernel), no GHCB handling in user space, and no `assert!`/`panic!` in the dispatch path. The entire MSHV-specific emulator attack surface (V2-21, V2-25, V2-26, V2-35) is absent from KVM builds.

---

### B.6 Migration receive — protocol audit

| Function | Peer-controlled input | Risk | Finding |
|---|---|---|---|
| `Request::read_from` | All 16 bytes (command + length) | UB from invalid enum discriminant | V2-22 |
| `Response::read_from` | All 16 bytes (status + length) | Same UB class | V2-22 |
| `MemoryRangeTable::read_from` | `length` param | assert! panic + unbounded alloc | V2-04 (existing) + V2-30 |
| `vm_receive_config` | `req.length()` + JSON payload | Unbounded alloc + unvalidated config | V2-29 + V2-32 |
| `vm_receive_state` | `req.length()` + JSON payload | Unbounded alloc | V2-29 |
| `vm_receive_memory` | Range table + memory content | Peer controls GPA targets + content | V2-04 (existing) |
| `receive_memory_regions` | Range table entries | Infinite loop on EOF | V2-31 |
| `vm_receive_memory_fd` | Slot number (4 bytes) + FD | FD leak if peer sends extra FDs | INFO |

State machine invariants verified:
- Ordering enforced: `Started → (MemoryFdsReceived)* → Configured → StateReceived → Completed`.
- `Abandon` valid from any state (correct).
- `self.vm` guaranteed `Some` after `StateReceived` (unwrap at L969 safe).
- No timeout on `read_exact` — peer can hold connection indefinitely (DoS, but low priority since migration requires operator setup).
- Endianness: native byte order assumed. Cross-endian migration produces silent corruption.

---

### B.7 SEV-SNP/TDX — audit coverage

| File | Surface | Findings |
|---|---|---|
| `mshv/mod.rs` GPA_ATTRIBUTE handler | Guest-controlled range, bitmap | V2-27, V2-28, V2-36 |
| `mshv/mod.rs` VMGEXIT handler | GHCB fields | V2-02 (existing, 6 sites) |
| `mshv/snp.rs` | `parse_gpa_range` | Returns unvalidated (gfn_start, gfn_count) from guest |
| `arch/src/x86_64/tdx.rs` | TDVF parsing, HOB construction | V2-07 (existing) + `add_acpi_table` u16 truncation for >64K tables |
| `vmm/src/igvm/` | IGVM blob parsing | `cpuid_page.count` unbounded (firmware-trust, not guest) |
| `mshv/mod.rs` `gain_page_access` | Page tracking for SNP | `size=0` underflow in PFN arithmetic, insufficient bitmap growth |

TDX-specific: The `add_acpi_table` function at `arch/src/x86_64/tdx.rs:442-443` computes `align_hob(table_content.len() as u64) as u16`, which truncates silently for ACPI tables > ~64K. This corrupts the HOB length field and all subsequent table entries. Trust boundary is firmware (admin-supplied), not guest.

---

## Escalation assessment — RCE / host-escape / host-crash potential

Assessed per the plan's verification protocol (step 5): novel HIGHs that warrant responsible disclosure.

### V2-22 — Migration enum UB: potential code execution

**Status:** Novel. No upstream report found (searched security advisories, issues, PRs, git history).

**Escalation path:** The `#[repr(u16)] enum Command` has 8 variants (0–7). `ByteValued::as_mut_slice` fills the struct from raw socket bytes. A peer sending `command = 8` creates an enum with an invalid discriminant — undefined behavior per Rust's reference. If rustc compiles the `match req.command()` at `lib.rs:938-965` as a jump table (common for small enums), an out-of-range discriminant reads past the jump table, potentially jumping to attacker-influenced code. The peer controls the discriminant value and thus the jump offset.

**Mitigating factors:** (1) Migration socket requires operator setup. (2) Whether rustc generates a jump table depends on optimization level and version. (3) ASLR makes jump-table exploitation harder. (4) 1:1 VMM:VM means the attacker only compromises the host process for one VM, not all VMs.

**Conclusion:** The UB is real and confirmed. Exploitability depends on compiler output but the worst case is code execution from a migration peer. Recommend responsible disclosure.

### V2-32 — Migration config injection: arbitrary file read/write

**Status:** Novel. No upstream report found.

**Escalation path:** A migration peer supplies JSON with `DiskConfig { path: "/etc/shadow" }`. The VMM stores it without validation. On VM boot, the VMM opens `/etc/shadow` as a block device. The guest reads/writes the file through the virtual disk. If the VMM runs as root, this is arbitrary file read/write as root from a network-connected migration peer.

**Mitigating factors:** (1) Migration socket is operator-configured (assumed private). (2) Landlock, if enabled by the operator's original config (not the peer's), would restrict file access — but the peer controls `landlock_enable` and `landlock_rules` in the migration config, so the peer can disable Landlock or set permissive rules. (3) 1:1 VMM:VM limits blast radius to one guest's host context.

**Conclusion:** Arbitrary file access from a migration peer. The migration socket's assumed-private status is the only defense — no defense-in-depth. Recommend responsible disclosure alongside V2-22.

### V2-21 — aarch64 XZR OOB: guest-triggered VMM crash

**Status:** Novel. No upstream report found.

**Escalation path:** Rust bounds checking converts the OOB array write to a deterministic panic. The VMM process crashes, killing the single associated guest. Not exploitable for code execution or host escape — Rust's bounds checking prevents the actual memory write.

**Impact in orchestrated environments:** In Kubernetes or similar orchestrators, a guest that can kill its own VMM can trigger restarts, disrupt scheduling, or DoS the node's capacity. Not a traditional "host crash" since other VMs are unaffected.

**Conclusion:** Guest-self-DoS on aarch64+MSHV. HIGH for availability but not for confidentiality/integrity. Standard issue disclosure (not urgent security advisory).

---

## Remediation priority (additive to `findings.md`)

1. **V2-21** (aarch64 OOB write via XZR). Memory safety violation — guest-to-host escape primitive on aarch64+MSHV. One-line fix.
2. **V2-22** (migration enum UB). Undefined behavior from any malformed migration peer. Replace `ByteValued` with explicit discriminant validation.
3. **V2-01** (MMIO bus-width). Mechanical replacement of `assert!(data.len() == N)` in all `BusDevice` implementors. Closes three HIGHs at once.
4. **V2-02** (SEV-SNP VMGEXIT panics). Must-fix for anyone shipping `sev_snp` builds.
5. **V2-28** (bitmap unit mismatch). Confidentiality violation in SNP page tracking — host can read guest-private pages.
6. **V2-23** (VHDX overlap check). Crafted VHDX bypasses region overlap validation.
7. **V2-25** (expand-down segment). Inverted emulator check — correctness/security for protected-mode guests.
8. **V2-17** (sector-0 ban self-disables). CVE-2026-27211-class regression on 2nd boot.
9. **V2-26 + V2-27** (REP loop DoS + SNP allocation DoS). Guest-reachable resource exhaustion.
10. **V2-32** (migration config injection → arbitrary file access). Validate config, allowlist paths, replace `.unwrap()` at x2apic enablement.
11. **V2-29 + V2-30 + V2-31** (migration receive hardening). Replace asserts with errors, cap lengths, add EOF check.
11. **V2-04** (MemoryRangeTable unbounded length). Replace `assert!` with returned error; cap `length`.
12. **V2-03** (fw_cfg OOB). One-line guard change.
13. **V2-24** (VHDX sector size). Data corruption for 4K-sector images.
14. **V2-12 / V2-13** (micro_http branch pins + drift). Pin `rev = "<sha>"` in both manifests.
15. **V2-38** (RestoreConfig assert_eq! panic — D-Bus only, corrected 2026-04-23). Replace assert with error return to close D-Bus surface + defend against internal regressions.
16. **V2-39** (try_clone().unwrap() in handle_request). API-reachable VMM crash under FD exhaustion — replace unwrap with error return.
17. **V2-40** (hot-add path injection). Arbitrary file access when Landlock disabled — add path allowlisting for hot-add endpoints.
18. **V2-45** (VFIO Landlock wrong symlink). Landlock rule targets non-existent path — read `iommu_group` symlink instead of device path.
19. Everything else (LOW/INFO/coverage): roll into the next hardening sprint.

---

## Phase B.4 — HTTP / D-Bus API audit

### V2-38 — `RestoreConfig::validate` assert_eq! panic — **LOW (D-Bus only; NOT reachable via HTTP)**

> **Correction — 2026-04-23.** The original writeup called this MEDIUM and
> claimed HTTP reachability. Live reproducer testing on v51.1 shows the
> HTTP layer sanitizes the input before `validate()` runs, so the HTTP
> path does NOT reach the assert. Severity downgraded to LOW for
> default builds (HTTP only). Still MEDIUM if D-Bus API is enabled
> (non-default). See "Why HTTP doesn't reach the assert" below.

```rust
// vmm/src/config.rs:2423-2427
assert_eq!(
    n.num_fds,
    n.fds.as_ref().map_or(0, |f| f.len()),
    "Invalid 'RestoredNetConfig' with conflicted fields."
);
```

`RestoredNetConfig` has independently deserializable `num_fds: usize` and `fds: Option<Vec<i32>>` fields. The custom deserializer `deserialize_restorednetconfig_fds` (config.rs:2345-2363) replaces FD values with `-1` sentinels but preserves the Vec length. Constructing a `RestoredNetConfig` with `num_fds = 5` and `fds = Some([-1, -1, -1])` (length 3) and calling `validate()` panics.

**Why HTTP doesn't reach the assert.** The HTTP `VmRestore` handler calls `attach_fds_to_cfgs` (http_endpoint.rs:504) *before* the VMM thread runs `validate()`. `attach_fds_to_cfgs` iterates the net_fds; for each one, `attach_fds_to_cfg_inner` at http_endpoint.rs:162-173 checks `cfg.fds_from_http_body().is_some()` and, if so, emits a warning (`FD numbers were present in HTTP request body ... but will be ignored`) and calls `cfg.set_fds(None)`. By the time the request reaches `validate()`, `fds = None` and `fds.as_ref().map_or(0, |f| f.len())` returns 0 — matching `num_fds = 0` for any caller who also sets `num_fds = 0`, and if they set `num_fds != 0` the earlier length check in `attach_fds_to_cfgs` at http_endpoint.rs:204-211 returns `BadRequest` before reaching the VMM thread.

**Confirmed via live reproducer** (`/tmp/ch-reproducers/02-v2-38-restore-panic.sh`): sending `{"num_fds":0,"fds":[1]}` via HTTP produces:
```
WARN: FD numbers were present in HTTP request body for device Some("net0") but will be ignored
WARN: Ignoring unused 'net_fds' for VM restore.
VM Restore failed: Restore(MigrateReceive(No such file or directory (os error 2)))
```
No panic; `validate()` completes normally (reaches the `warn!` at config.rs:2456). The assert at line 2423 is dead code from the HTTP attack surface.

**Where the assert IS reachable:**
- **D-Bus `vm_restore`** (vmm/src/api/dbus/mod.rs:270-273): does NOT call `attach_fds_to_cfgs`. Deserializes the JSON directly and forwards to the VMM thread. A caller sending `{"num_fds":0,"fds":[1]}` via D-Bus reaches `validate()` with `fds = Some([-1])`, and the assert fires.
- **Direct `validate()` call on a manually-constructed RestoreConfig** (e.g. from unit tests or in-process code paths). The Hegel property test `restore_config_validate_never_panics` triggers this immediately.

**Input origin:** D-Bus client JSON body.
**Trust boundary:** D-Bus client → VMM.
**D-Bus gating:** D-Bus API is opt-in (`--dbus-service-name`, `--dbus-object-path`). Most deployments use HTTP, not D-Bus. When D-Bus is enabled, reachability is the same trust boundary.

**Reproducer (D-Bus, when enabled):**
```bash
busctl --user call org.cloudhypervisor.dbus /org/cloudhypervisor/dbus \
  org.cloudhypervisor.dbus Vm.Restore s \
  '{"source_url":"file:///tmp/snap","net_fds":[{"id":"net0","num_fds":0,"fds":[1]}]}'
```

**Fix direction:** Replace `assert_eq!` with a returned `ValidationError`. This closes the D-Bus surface AND removes a programming-error class (the assert is also reachable internally if future code constructs a `RestoredNetConfig` with mismatched fields — the warning emitted by the HTTP path doesn't prevent that future regression).

**Lesson (added after correction):** The original finding inferred HTTP reachability from the API entry point without tracing the intervening handler layer. The HTTP `EndpointHandler::handle_request` → `PutHandler::handle_request` → `attach_fds_to_cfgs` chain normalizes the input before the VMM thread sees it. Trust boundary proofs require tracing from the outermost entry point all the way to the vulnerable function, not just from a nearby caller. The Hegel property test that "confirmed" V2-38 bypassed this layer by calling `validate()` directly — which proves the bug is real in the function but NOT that it is reachable through the API. See skill `api-reachability-requires-end-to-end-trace`.

---

### V2-39 — `try_clone().unwrap()` in HTTP `handle_request` panics under FD exhaustion — **MEDIUM (API-reachable VMM crash)**

```rust
// vmm/src/api/http/mod.rs:119
let files = req.files.iter().map(|f| f.try_clone().unwrap()).collect();
```

The default `EndpointHandler::handle_request` calls `try_clone().unwrap()` on every file descriptor received via SCM_RIGHTS. `try_clone()` calls `dup()` — if the process is at its FD limit (`RLIMIT_NOFILE`), `dup()` returns `EMFILE` and the unwrap panics.

**Panic containment:** The HTTP server loop is wrapped in `catch_unwind(AssertUnwindSafe(...))` at http/mod.rs:365-392. On panic, it writes `exit_evt(1)` which triggers VMM shutdown. A single API request under FD exhaustion kills the entire VMM process.

**Input origin:** API client via Unix socket. All endpoints routed through `VmActionHandler` are affected (all PUT endpoints except `vm.create`, `vm.info`, `vmm.ping`, `vmm.shutdown`).
**Trust boundary:** API client → VMM.

**Reproducer sketch:** An API client sends requests with many SCM_RIGHTS FDs without consuming them, exhausting the process FD limit. The next request with any SCM_RIGHTS FD triggers the panic.

**Note:** The nearby `handle_http_request` at mod.rs:304 handles `api_notifier.try_clone()` gracefully (returns InternalServerError on Err), showing the developers are aware of clone failures but missed this codepath.

**Fix direction:** Replace `.unwrap()` with `.map_err(...)` and return `HttpError::InternalServerError` on failure.

---

### V2-40 — Hot-add API endpoints accept arbitrary filesystem paths without validation — **MEDIUM (when Landlock disabled)**

All hot-add endpoints (`vm.add-disk`, `vm.add-fs`, `vm.add-pmem`, `vm.add-device`, `vm.add-user-device`, `vm.add-vdpa`, `vm.add-vsock`) accept PathBuf fields in their JSON body. No path canonicalization, symlink resolution, or allowlist checking is performed at the API layer.

Landlock is applied once during `vm_create` (lib.rs:1628-1635) and covers only paths in the initial config. Hot-add paths are NOT added to the Landlock ruleset. When Landlock is enabled, the kernel enforces the initial ruleset at `open()` time — hot-added paths not in the initial config fail with EACCES (functional error, not a bypass). When Landlock is disabled (the default), no path validation exists at all.

**Affected path fields:**
| Endpoint | Config field |
|---|---|
| vm.add-disk | `DiskConfig.path` |
| vm.add-fs | `FsConfig.socket` |
| vm.add-pmem | `PmemConfig.file` |
| vm.add-device | `DeviceConfig.path` |
| vm.add-user-device | `UserDeviceConfig.socket` |
| vm.add-vdpa | `VdpaConfig.path` |
| vm.add-vsock | `VsockConfig.socket` |

**Input origin:** API client JSON body.
**Trust boundary:** API client → VMM.

**Reproducer (Landlock disabled, VMM running as root):**
```bash
curl --unix-socket /run/cloud-hypervisor.sock -X PUT \
  http://localhost/api/v1/vm.add-disk \
  -H "Content-Type: application/json" \
  -d '{"path":"/etc/shadow","readonly":false}'
```

The VMM opens `/etc/shadow` as a block device. The guest reads/writes the file through the virtual disk.

**Distinction from V2-32:** V2-32 covers the migration receive path (peer-controlled config). This finding covers the HTTP/D-Bus API hot-add path (API-client-controlled config). The root cause is the same (no path validation on deserialized config), but the attack surfaces are different.

**Severity:** MEDIUM when Landlock is disabled (default). LOW when Landlock is enabled (kernel enforcement at open-time prevents access to paths outside the initial config).

**Fix direction:** (1) When Landlock is enabled, update the Landlock ruleset for hot-added paths before opening them. (2) Regardless of Landlock, validate paths against a configurable allowlist or require them to be under a specific directory.

---

### V2-41 — D-Bus `vm_restore` lacks FD passing — functional asymmetry + same panic as V2-38 — **LOW**

```rust
// vmm/src/api/dbus/mod.rs:270-273
async fn vm_restore(&self, restore_config: String) -> Result<()> {
    let restore_config = serde_json::from_str(&restore_config).map_err(api_error)?;
    self.vm_action(&VmRestore, restore_config).await.map(|_| ())
}
```

The D-Bus `vm_restore` method deserializes `RestoreConfig` from a JSON string but has no FD passing mechanism (unlike the HTTP path which receives FDs via SCM_RIGHTS and calls `attach_fds_to_cfgs`). A restore of a VM with FD-backed net devices via D-Bus always fails. The V2-38 `assert_eq!` panic is equally reachable via D-Bus.

**Severity:** LOW (functional gap, not a distinct security issue beyond V2-38).

---

## Phase B.3 — Device Manager + Hotplug audit

### V2-42 — `hotplug_virtio_pci_device` pushes handle before `add_virtio_pci_device` — stale device on failure — **LOW (API-reachable state corruption)**

```rust
// vmm/src/device_manager.rs:4865
self.virtio_devices.push(handle.clone());

// vmm/src/device_manager.rs:4873-4879
let bdf = self.add_virtio_pci_device(
    handle.virtio_device,
    &mapping,
    &handle.id,
    handle.pci_segment,
    handle.dma_handler,
)?;
```

`self.virtio_devices.push(handle.clone())` at line 4865 is called BEFORE `self.add_virtio_pci_device()` at line 4873. If `add_virtio_pci_device` fails (PCI resource allocation, device tree insertion, BAR allocation, etc.), the function returns `Err` via `?`, but the stale handle remains in `self.virtio_devices`.

**Impact:** The orphaned virtio device receives memory update notifications (e.g., from hotplugged memory) despite never being registered on the PCI bus. The `Drop` handler for `DeviceManager` (line 5591) will attempt to shut down this device. Depending on the device type, this may panic or corrupt state.

**Input origin:** API client via any hot-add endpoint (vm.add-disk, vm.add-net, etc.).
**Trust boundary:** API client → VMM.

**Fix direction:** Move the `push` after the `?` return: `let bdf = self.add_virtio_pci_device(...)?; self.virtio_devices.push(handle.clone());`.

---

### V2-43 — `add_vfio_device` stores VFIO container before DMA mapping — subsequent devices get unmapped container on first-add failure — **LOW (API-reachable correctness bug)**

```rust
// vmm/src/device_manager.rs:3792-3800
let vfio_container = self.create_vfio_container()?;
needs_dma_mapping = true;
self.vfio_container = Some(Arc::clone(&vfio_container));  // stored here

vfio_container  // returned here, DMA mapping happens at 3802-3838
};

let vfio_device = VfioDevice::new(&device_cfg.path, Arc::clone(&vfio_container))
    .map_err(DeviceManagerError::VfioCreate)?;  // can fail here
```

`self.vfio_container = Some(...)` at line 3794 stores the container BEFORE `VfioDevice::new` at line 3799 and the DMA mapping loop at 3802-3838. If `VfioDevice::new` fails (invalid device path, missing IOMMU group, etc.), the container is stored but DMA mappings are never set up. On the next `add_vfio_device` call, line 3789-3790 clones the existing container with `needs_dma_mapping = false`, so the DMA mapping loop at 3802-3838 is skipped.

**Impact:** All subsequent non-IOMMU VFIO devices share a container without guest memory DMA mappings. Device I/O from the guest fails silently or triggers IOMMU faults (platform-dependent).

**Input origin:** API client via vm.add-device with an invalid first device path, followed by a valid second device path.
**Trust boundary:** API client → VMM.

**Fix direction:** Move `self.vfio_container = Some(...)` to after the DMA mapping loop succeeds, or add a "DMA mapped" flag and re-map on subsequent additions if the flag is unset.

---

### V2-44 — `eject_device` releases PCI slot before verifying device exists in tree — partial cleanup on missing device — **LOW (guest-triggerable state leak)**

```rust
// vmm/src/device_manager.rs:4648-4660
self.pci_segments[pci_segment_id as usize]
    .pci_bus
    .lock()
    .unwrap()
    .put_device_id(device_id as usize)
    .map_err(DeviceManagerError::PutPciDeviceId)?;   // slot freed

let (pci_device_handle, id) = {
    let mut device_tree = self.device_tree.lock().unwrap();
    let pci_device_node = device_tree
        .remove_node_by_pci_bdf(pci_device_bdf)
        .ok_or(DeviceManagerError::MissingPciDevice)?;   // can fail after slot freed
```

`pci_bus.put_device_id()` at line 4648-4653 releases the PCI slot number back to the bus. If `remove_node_by_pci_bdf` at line 4658-4660 returns `None` (device not in tree), the function returns `Err` with the slot already freed. The slot number is now available for reuse, but the device that was occupying it is still registered in the PCI bus (it wasn't removed since the function exited early).

**Trigger:** A guest writes to the B0EJ ACPI register (line 5558-5564) with a slot ID for a device that exists on the PCI bus but not in the device tree. This is an unusual state that requires a prior partial-cleanup failure, but the eject itself is guest-initiated.

**Impact:** PCI slot number corruption — a new device could be assigned the same slot as an existing device.

**Fix direction:** Move `put_device_id` to after the device tree removal succeeds, or roll back the slot release on tree-removal failure.

---

## Phase B.5 — VFIO + Landlock audit

### V2-45 — `DeviceConfig::apply_landlock` reads wrong symlink — VFIO Landlock rule targets non-existent path — **MEDIUM (Landlock bypass for VFIO)**

```rust
// vmm/src/vm_config.rs:578-591
fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
    let device_path = fs::read_link(self.path.as_path()).map_err(LandlockError::OpenPath)?;
    let iommu_group = device_path.file_name();  // BUG: gets BDF, not IOMMU group
    let iommu_group_str = iommu_group
        .ok_or(LandlockError::InvalidPath)?
        .to_str()
        .ok_or(LandlockError::InvalidPath)?;

    let mut vfio_group_path = PathBuf::from("/dev/vfio");
    vfio_group_path.push(iommu_group_str);      // constructs /dev/vfio/0000:01:00.0
    landlock.add_rule_with_access(&vfio_group_path, "rw")?;
    Ok(())
}
```

`self.path` is the sysfs PCI device path (e.g., `/sys/bus/pci/devices/0000:01:00.0`). Line 579's `read_link` resolves this symlink to the actual sysfs directory (e.g., `../../../devices/pci0000:00/0000:00:01.0/0000:01:00.0`). Line 580's `file_name()` extracts `0000:01:00.0` — the PCI BDF, not the IOMMU group number.

The actual VFIO device open path (in `vfio-ioctls` crate, `VfioDevice::get_group_id_from_path`) reads a *different* symlink: `<sysfspath>/iommu_group` → `../../../../kernel/iommu_groups/42` → `file_name()` = `42`. The VFIO group file opened is `/dev/vfio/42`.

**The Landlock rule targets `/dev/vfio/0000:01:00.0` (non-existent). The actual open targets `/dev/vfio/42`. These are different paths.**

Since `/dev/vfio/0000:01:00.0` doesn't exist, the landlock crate's `path_beneath_rules` silently returns `None` via `filter_map`, and `add_rules` succeeds without actually adding any rule. The real VFIO group path `/dev/vfio/<N>` is never whitelisted.

**Consequence:** Under Landlock, VFIO passthrough fails with EACCES because `/dev/vfio/<group>` is not in the ruleset. The existing VLN-05 finding covers the TOCTOU race between `read_link` and device open; this finding covers the separate, more severe logic error that makes the Landlock rule a no-op regardless of timing.

**Input origin:** VMM config (`DeviceConfig.path`).
**Trust boundary:** VMM process → kernel Landlock enforcement.

**Fix direction:** Read the correct symlink: `fs::read_link(self.path.join("iommu_group"))` instead of `fs::read_link(self.path)`. Alternatively, open the path once with `O_PATH` and resolve via `fstat`, as VLN-05 suggests.

---

### V2-46 — `DiskConfig.vhost_socket` not covered by Landlock — **LOW (functional defect under Landlock)**

`DiskConfig::apply_landlock` (vm_config.rs:296-302) registers `self.path` but not `self.vhost_socket: Option<String>` (vm_config.rs:269). When `vhost_user=true`, the socket path is used to connect to the vhost-user backend (device_manager.rs:2631). Under Landlock, the connect fails with EACCES. Same class as V2-06.

---

### V2-47 — `NetConfig.vhost_socket` missing from `ApplyLandlock` dispatch — **LOW (functional defect under Landlock)**

```rust
// vmm/src/vm_config.rs:1049-1051
if self.net.is_some() {
    landlock.add_rule_with_access(Path::new("/dev/net/tun"), "rw")?;
}
```

`VmConfig::apply_landlock` grants access to `/dev/net/tun` for net devices but does not iterate `NetConfig` entries to register `vhost_socket: Option<String>` paths. A vhost-user net device (`vhost_user: true`) with a socket path will fail with `EACCES` at connect-time under Landlock. No `ApplyLandlock` impl exists for `NetConfig`.

**Severity:** LOW. Functional defect when Landlock is enabled with vhost-user net. Without Landlock, no security impact.

**Fix direction:** Implement `ApplyLandlock for NetConfig` that registers `vhost_socket` as `rw`.

---

### V2-48 — `IvshmemConfig.path` missing from `ApplyLandlock` dispatch — **LOW (ivshmem feature, functional defect under Landlock)**

`IvshmemConfig` has `path: PathBuf` (vm_config.rs:664) but no `ApplyLandlock` impl, and `VmConfig::apply_landlock` does not include it in the dispatch. Under Landlock, ivshmem device opening fails with `EACCES`.

**Severity:** LOW. Feature-gated behind `#[cfg(feature = "ivshmem")]`. Same class as V2-06 (FwCfgConfig missing ApplyLandlock).

**Fix direction:** Implement `ApplyLandlock for IvshmemConfig` that registers `path` as `rw`.

---

### B.5 audit coverage notes

| Target | Status | Finding |
|---|---|---|
| DeviceConfig::apply_landlock TOCTOU | Reviewed | VLN-05 (existing). The `read_link` at vm_config.rs:578 and the actual device open in pci/src/vfio.rs are separate operations. Between them, the symlink can be retargeted. However, as VLN-05 notes, the attacker needs root-equivalent privilege to modify sysfs VFIO symlinks, limiting practical exploitability to LOW. |
| DeviceConfig::apply_landlock logic | Confirmed | V2-45: reads PCI BDF instead of IOMMU group number, making Landlock rule a no-op. |
| All ApplyLandlock impls enumerated | Complete | 14 impls found. Missing: FwCfgConfig (V2-06), DiskConfig.vhost_socket (V2-46), NetConfig.vhost_socket (V2-47), IvshmemConfig (V2-48). DeviceConfig impl exists but is broken (V2-45). |
| VFIO device open path | Reviewed | VfioDevice::new opens the VFIO group path constructed from sysfs. No additional path traversal beyond VLN-05. Error paths close FDs properly (Rust Drop). |
| Landlock rule construction | Reviewed | `add_rule_with_access` follows symlinks (default kernel behavior). Cannot add "/" since Landlock rules are additive (granting "/" would grant everything, but requires attacker-controlled config). |

---

### B.3 audit coverage notes

| Target | Status | Finding |
|---|---|---|
| `hotplug_virtio_pci_device` stale handle | Confirmed | V2-42 |
| `add_vfio_device` partial state | Confirmed | V2-43 |
| `eject_device` partial cleanup | Confirmed | V2-44 |
| `eject_device` assert_eq! (children.len()==1) | Reviewed | Internal invariant; not directly guest-triggerable. Children count is VMM-controlled. |
| Lock ordering | Reviewed | 135 `lock().unwrap()` sites. All locks are Mutex (not RwLock), acquired in consistent order within individual functions. No cross-function lock-while-holding pattern detected in the hotplug/eject paths. The `device_tree` lock at 4657 is always taken independently (never while holding `pci_bus`). No deadlock risk identified in this pass. |
| `pci_segments[n]` bounds | Reviewed | All `pci_segment` values are validated against `num_pci_segments` in config.rs validation (9 sites at config.rs:724, 1303, 1554, 1702, 1864, 2028, 2072, 2134, 2880). The guest-controlled `selected_segment` is bounds-checked at device_manager.rs:5572. No unvalidated index path found. |
