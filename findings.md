# Cloud Hypervisor — Validated Vulnerability Report

**Scope:** `hypervisor/src/mshv/mod.rs`, `hypervisor/src/arch/x86/emulator/mod.rs`, `vmm/src/*`, build scripts.
**Method:** Each candidate from `candidates.md` was verified against current source (v51.1, branch HEAD) and cross-referenced with the relevant dependency sources (`mshv-bindings-0.6.7`, `vm-memory-0.16.2`).
**Threat model used:**
- **Guest → VMM** (untrusted guest kernel/userspace): a panic or memory-safety bug reachable via a single guest instruction is HIGH.
- **API client → VMM** (local Unix socket, typically admin-trusted): privilege escalation or arbitrary-file-write via API is MEDIUM unless the feature is off by default.
- **Hypervisor → VMM** (MSHV kernel): a trusted but non-adversarial boundary; missing defensive checks are LOW unless the kernel’s contract is ambiguous.
- **Build environment**: trusted; hygiene issues are LOW/INFO.

---

## Summary

| ID        | Finding                                               | Severity (validated) | Delta vs. candidates.md |
|-----------|-------------------------------------------------------|----------------------|--------------------------|
| VULN-03   | Guest-reachable `assert!` on string/REP I/O           | **HIGH**             | Same                     |
| VULN-01   | IO-port mask slice/shift on guest-driven `access_size`| MEDIUM               | Downgraded (kernel-bounded, but still latent) |
| VULN-02   | `instruction_byte_count` slice on MSHV-supplied len   | LOW                  | Downgraded (bounded by x86 ISA + kernel) |
| VULN-06   | Emulator skips canonical-address check in long mode   | LOW                  | Same                     |
| VULN-04   | `.unwrap()` on `x.to_*()` message decoders            | INFO                 | Downgraded               |
| VULN-05   | Union loop bounded by `pt_num_cpu_fbanks`             | INFO                 | Downgraded (self-consistent today) |
| VLN-01    | Path traversal via snapshot/coredump `file://` URL    | MEDIUM               | Downgraded (gated by `guest_debug` + API auth) |
| VLN-02    | `micro_http` git dep pinned to branch, not rev        | MEDIUM               | Same                     |
| VLN-03    | `GuestAddress::unchecked_sub(1)` on derived address   | INFO                 | Downgraded (unreachable in practice) |
| VLN-04    | Hotplug `.unwrap()` panics                            | LOW                  | Downgraded (requires enormous API-supplied size) |
| VLN-05    | Landlock symlink TOCTOU on VFIO path                  | LOW                  | Same                     |
| VLN-06    | `Command::new("git")` in build.rs                     | LOW                  | Same                     |
| VLN-07    | `CH_EXTRA_VERSION` newline injection in build.rs      | LOW                  | Same                     |
| VLN-08    | `cfg(fuzzing)` stubs out real offload/MTU/epoll code  | INFO                 | Same                     |
| (new)     | `panic!("mapping num beyond 65535 not supported")`    | LOW                  | Not in candidates.md     |

The single most impactful finding remains **VULN-03**: one guest-side `rep outsb` instruction to any un-skipped port will crash the VMM in release builds.

---

## MSHV hypervisor findings (`hypervisor/src/mshv/mod.rs`)

### VULN-03 — Guest-reachable `assert!` on string/REP port I/O  — **HIGH**

```rust
// hypervisor/src/mshv/mod.rs:640-649
assert!(
    (unsafe { access_info.__bindgen_anon_1.string_op() } != 1),
    "String IN/OUT not supported"
);
assert!(
    (unsafe { access_info.__bindgen_anon_1.rep_prefix() } != 1),
    "Rep IN/OUT not supported"
);
```

`assert!` (not `debug_assert!`) fires in release builds. The port-skip list above (`0x402|0x510|0x511|0x514`) only whitelists four QEMU/OVMF debug ports; any string-form I/O to any other port reaches the assert.

**Reproducer from inside the guest (ring 0):**
```asm
mov dx, 0x80
mov ecx, 1
rep outsb
```
→ VMM panics, guest terminates along with it.

**Impact:** Unprivileged-from-host DoS of the VMM by a guest. On MSHV, this is the one-line crash the candidates.md summary flagged; validated.

**Fix direction:** return `cpu::VmExit::Ignore` (or forward via proper string-I/O emulation) instead of panicking; at minimum downgrade to `debug_assert!` + a structured error so `vm_ops` can fail gracefully.

---

### VULN-01 — IO-port mask slice/shift driven by `access_size` — **MEDIUM**

```rust
// hypervisor/src/mshv/mod.rs:611,655,661,667
let len = unsafe { access_info.__bindgen_anon_1.access_size() } as usize;
...
vm_ops.pio_write(port.into(), &data[0..len])   // line 655
vm_ops.pio_read(port.into(), &mut data[0..len])// line 661
let mask = 0xffffffff >> (32 - len * 8);       // line 667
```

`access_size()` is a **3-bit bitfield** in `mshv-bindings-0.6.7` (`x86_64/bindings.rs:12287`), i.e. values `0..=7`.
- `len == 0`: `32 - 0 == 32`; `u32 >> 32` panics in debug (`attempt to shift right with overflow`) and is implementation-defined in release (LLVM `lshr` on x86 masks the shift amount, yielding `0xffffffff`, which then incorrectly zeroes the low 32 bits of RAX — a correctness bug).
- `len ∈ {5,6,7}`: `data[0..len]` on a `[u8; 4]` buffer panics with a slice-bounds check.

**Reachability:** `access_size` is populated by the MSHV kernel when it decodes the trapping `IN`/`OUT`. For legal operand sizes the kernel emits 1, 2, or 4, so the bug is not guest-triggerable through ordinary instructions. However: there is **no defensive check** in the VMM, and the `SAFETY: access_info is valid` comment at line 611 only covers the union access, not the value. Any future kernel change, any SEV-SNP/TDX edge case, or any test kernel that emits `0`, `3`, `5`, `6`, `7` will panic the VMM.

**Severity:** MEDIUM — not a direct guest-primitive today, but a latent VMM-panic with no defense-in-depth.

**Fix direction:**
```rust
let len = match unsafe { access_info.__bindgen_anon_1.access_size() } as usize {
    n @ (1 | 2 | 4) => n,
    other => return Err(cpu::HypervisorCpuError::RunVcpu(
        anyhow!("MSHV reported invalid IO access_size {other}")
    )),
};
```

---

### VULN-02 — `instruction_byte_count` slice on MSHV-supplied length — **LOW**

```rust
// hypervisor/src/mshv/mod.rs:711,733
let insn_len = info.instruction_byte_count as usize;
...
.emulate_insn_stream(&old_state, &info.instruction_bytes[..insn_len], Some(1))
```

`instruction_bytes` is `[u8; 16]` (`mshv-bindings-0.6.7 x86_64/bindings.rs:12632`). `instruction_byte_count` is `u8` (0–255). If the kernel ever sets it `> 16`, the slice panics.

**Reachability:** x86 instructions are bounded to 15 bytes by the ISA; the MSHV kernel never legitimately emits a higher value. Not reachable from the guest today.

**Severity:** LOW — defensive-check gap, not a live bug.

**Fix direction:** `let insn_len = core::cmp::min(info.instruction_byte_count as usize, info.instruction_bytes.len());` before the slice.

---

### VULN-04 — `.unwrap()` on message type decoders — **INFO**

```rust
// mshv/mod.rs:608,677,710,747,815
let info = x.to_ioport_info().unwrap();
let info = x.to_memory_info().unwrap();
...
let info = x.to_gpa_attribute_info().unwrap();
```

These helpers return `Option` and only succeed when the message type matches the outer `match` arm, which is the case for every branch where they appear. A failure implies an MSHV kernel bug (wrong `header.message_type`), not a guest primitive. Downgraded to INFO.

**Fix direction:** replace with `?` + a typed error for robustness.

---

### VULN-05 — Bounded union loop over `pt_num_cpu_fbanks` — **INFO**

```rust
// mshv/mod.rs:292-295
for i in 0..create_args.pt_num_cpu_fbanks {
    disable_proc_features.as_uint64[i as usize] = create_args.pt_cpu_fbanks[i as usize];
}
```

- `pt_cpu_fbanks: [u64; 2]` and `hv_partition_processor_features.as_uint64: [u64; 2]` (both 2 elements).
- `pt_num_cpu_fbanks` is set by `mshv-ioctls` to `MSHV_NUM_CPU_FEATURES_BANKS = 2`.

The loop bound and the two array sizes are consistent **today**. If a future binding bump raises the constant without resizing the arrays, this panics. Currently unreachable.

---

### VULN-06 — Missing canonical address check in long-mode linearize — **LOW**

```rust
// hypervisor/src/arch/x86/emulator/mod.rs:134-143
CpuMode::Long => {
    // TODO Check that we got a canonical address.
    Ok(logical_addr.checked_add(segment_register.base).ok_or_else(|| …)?)
}
```

Explicit TODO. In long mode the CPU raises `#GP` for non-canonical linear addresses; the emulator silently accepts them. The emulator runs on the MMIO-trap path and operates on attacker-decoded instructions, so divergence from real CPU behavior is a correctness/semantic issue rather than a direct memory-safety bug — the `checked_add` still prevents 64-bit wrap. Confirmed as a LOW finding exactly as stated.

---

## VMM findings

### VLN-01 — Path traversal in `url_to_file` (coredump) — **MEDIUM (conditional)**

```rust
// vmm/src/migration.rs:38-47
pub fn url_to_file(url: &str) -> Result<PathBuf, GuestDebuggableError> {
    let file: PathBuf = url.strip_prefix("file://").ok_or_else(|| … )?.into();
    Ok(file)
}
```

Zero validation. `vm.rs:2989` uses the returned path with `OpenOptions::new().read(true).write(true).create_new(true).open(path)`.

**What's mitigated:** `create_new(true)` fails if the target already exists, so **overwrite** of e.g. `/etc/shadow` is blocked. Symlink-following, path traversal, and **arbitrary new-file creation** are not.
**What's exposed:**
- If the VMM runs as root, a caller can create attacker-controlled content at any non-existent path (e.g. `/etc/cron.d/ch-dump` — the file body is a valid ELF core dump, which a cron parser will reject, but the mere presence and mode of the file may still be useful for persistence/denial primitives).
- The file contents include all guest RAM → arbitrary-guest-memory disclosure to any writable path.

**Gating:** the `coredump` API endpoint is compiled only under `#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]`, and `guest_debug` is **not a default feature** (`vmm/Cargo.toml:12`). It is shipped in debug images only.

**Severity:** MEDIUM when `guest_debug` is enabled; otherwise not compiled in.

**Fix direction:** canonicalize the path (`std::fs::canonicalize` or an equivalent of `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)` under a fixed root) and reject results outside an explicit dump directory.

---

### VLN-02 — `micro_http` pinned to a moving branch — **MEDIUM**

```toml
# vmm/Cargo.toml:61
micro_http = { git = "https://github.com/firecracker-microvm/micro-http", branch = "main" }
```

`micro_http` parses every HTTP request into the VMM’s control-plane API. A branch pin means `cargo update` pulls whatever currently sits on `main`; the reproducible build is dependent on `Cargo.lock`, and any bump via `cargo update -p micro_http` silently accepts new upstream code. A compromised or force-pushed upstream becomes exploitable as soon as one maintainer re-locks.

**Severity:** MEDIUM supply-chain hygiene. Recommend pinning to a `rev = "<sha>"` (and ideally vendoring or using a crates.io release).

---

### VLN-03 — `GuestAddress::unchecked_sub(1)` — **INFO**

```rust
// memory_manager.rs:1011
let end_of_device_area = start_of_platform_device_area.unchecked_sub(1);
// memory_manager.rs:1201
let end_of_ram_area = start_of_device_area.unchecked_sub(1);
```

Both base addresses are derived from `mmio_address_space_size - PLATFORM_DEVICE_AREA_SIZE` and the guest RAM top; neither is zero in any realistic configuration. The `unchecked_sub` is a minor code-smell, not a reachable bug. INFO.

---

### VLN-04 — Hotplug `.unwrap()` chain — **LOW**

```rust
// memory_manager.rs:1694-1696
if start_addr
    .checked_add((size - 1).try_into().unwrap())
    .unwrap()
    > self.end_of_ram_area
```

- Inner `try_into().unwrap()` is `usize → u64`, always `Ok` on 32- and 64-bit. Not a real panic site.
- Outer `.unwrap()` panics only if `start_addr + (size - 1)` overflows `u64`. The only caller is `resize()` (`memory_manager.rs:1960`), which guards `desired_ram > current_ram` and passes `(desired_ram - current_ram) as usize`. Reaching overflow requires an API-provided `desired_ram` near `u64::MAX`.

**Severity:** LOW (requires pathological API input). Candidates.md framed it as a 32-bit `GuestUsize` overflow; `GuestUsize` is `u64` in `vm-memory-0.16.2`, so that framing is incorrect. The actual latent issue is the outer `.unwrap()`.

Separately note the nearby hard-coded panic at `vm.rs:2995` (`panic!("mapping num beyond 65535 not supported")`) — another API-reachable crash on oversized guest-RAM mappings, listed below as a new finding.

---

### VLN-05 — Landlock symlink TOCTOU — **LOW**

```rust
// vm_config.rs:578-591
fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
    let device_path = fs::read_link(self.path.as_path()).map_err(LandlockError::OpenPath)?;
    let iommu_group = device_path.file_name();
    let iommu_group_str = iommu_group.ok_or(…)?.to_str().ok_or(…)?;
    let mut vfio_group_path = PathBuf::from("/dev/vfio");
    vfio_group_path.push(iommu_group_str);
    landlock.add_rule_with_access(&vfio_group_path, "rw")?;
    ...
}
```

`read_link` resolves a user-configured VFIO device path once; the filename is then concatenated into `/dev/vfio/<group>` and granted Landlock access. A racing attacker can retarget the symlink between `read_link` and later device open.

**Why LOW:** the VFIO device nodes are root-owned `root:vfio` 0660 by default. A caller who can modify the symlink already has sufficient privilege. Furthermore, Landlock only **grants** access — a mismatched group number means the VMM will fail to open VFIO, not escalate privileges.

**Fix direction:** open the path once with `O_PATH|O_NOFOLLOW`, obtain the group via `fstatat`, and pass the already-opened descriptor to Landlock if supported.

---

### VLN-06 — `Command::new("git")` in build script — **LOW**

```rust
// cloud-hypervisor/build.rs:12
Command::new("git").args(["describe", "--dirty"]).output()
```

Relies on `$PATH`. Any attacker with the ability to inject a `git` binary into `$PATH` at build time already controls the build. Standard hygiene issue; pin to an absolute `/usr/bin/git` or use `vergen` if the signal matters.

---

### VLN-07 — Cargo directive injection via `CH_EXTRA_VERSION` — **LOW**

```rust
// cloud-hypervisor/build.rs:22-25
if let Ok(extra_version) = env::var("CH_EXTRA_VERSION") {
    println!("cargo:rerun-if-env-changed=CH_EXTRA_VERSION");
    version.push_str(&format!("-{extra_version}"));
}
...
println!("cargo:rustc-env=BUILD_VERSION={version}");
```

A `\n`-containing value splits the `cargo:` line and injects further directives (`cargo:rustc-link-arg=...`, etc.). Requires attacker-controlled environment at build time — same trust boundary as VLN-06.

**Fix direction:** reject `extra_version` if it contains `\n` or any control char.

---

### VLN-08 — `cfg(fuzzing)` disables real code paths — **INFO**

`cfg(fuzzing)` is declared in `vmm/build.rs:7` and `net_util/build.rs:7`, and is consumed at least in:

- `net_util/src/tap.rs:429` (MTU stub) and `:523` (`new_for_fuzzing`)
- `virtio-devices/src/net.rs:774` (skips `tap.set_offload(...)`)
- `virtio-devices/src/epoll_helper.rs:248` (zero-timeout variant)
- Several `wait_for_epoll_threads` stubs

This is only active with `--cfg fuzzing`, not with any Cargo feature, so there is no accidental-feature-flag path. The real risk is a maintainer mistakenly shipping a binary built with `--cfg fuzzing`. INFO.

---

### (New) `panic!()` on >65535 guest RAM mappings — **LOW**

```rust
// vm.rs:2995
} else {
    panic!("mapping num beyond 65535 not supported");
}
```

On the coredump path (again `guest_debug`-gated). API-reachable via `vm.coredump` with a guest configuration producing more than 65 533 mappings. Not guest-triggerable. Include for completeness; recommend replacing with `GuestDebuggableError::Coredump(...)`.

---

## Appendix — findings not worth promoting

- `assert!(num_ranges >= 1)` at `mshv/mod.rs:755` — guarded by sev_snp; `num_ranges` is a 12-bit field whose zero value is treated as "invalid" by the kernel; defensive check but unreachable.
- `assert!(info.vp_index == self.vp_index as u32)` at `mshv/mod.rs:851` — same class (kernel-trust panic).
- Multiple `.unwrap()` calls on `snp::parse_gpa_range(...)` and `info.interrupt_vector.try_into().unwrap()` — same class.

These share the same analysis as VULN-04 (trust-boundary panics) and are not separately reported.

---

## Prioritized remediation list

1. **VULN-03**: replace `assert!` with graceful handling (1-line fix, highest ROI).
2. **VULN-01 + VULN-02**: validate `access_size` ∈ {1,2,4} and `instruction_byte_count ≤ 16` once at intercept entry.
3. **VLN-02**: pin `micro_http` to a commit hash.
4. **VLN-01**: canonicalize + sandbox coredump destination (only relevant when shipping `guest_debug`).
5. **VULN-06**: implement canonical-address check in `linearize`.
6. Housekeeping: VLN-04 outer `.unwrap()`, `vm.rs:2995` panic, VLN-07 newline filter.
