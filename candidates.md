**VULN-01 (CRITICAL) — Integer underflow + OOB in IO port mask (line 667)**
Guest-controlled `access_size()` at line 611 is never validated. Used to slice a 4-byte `data` buffer (`data[0..len]` at lines 655/661) and compute `0xffffffff >> (32 - len * 8)` at line 667. If `len > 4`: OOB slice panics the VMM. If `len == 0`: the shift is `>> 32` which is also UB for u32.

**VULN-02 (HIGH) — OOB read via `instruction_byte_count` (lines 711-733)**
`info.instruction_byte_count` (a `u8`, range 0-255) is used to slice the fixed-size `instruction_bytes` array with no bounds check. Panics if count exceeds array length.

**VULN-03 (HIGH) — Reachable `assert!` on guest string I/O (lines 640-648)**
`assert!` (not `debug_assert!`) fires in release builds when a guest executes `REP INS/OUTS` or string I/O on any non-skipped port. Trivial guest-triggered DoS with a single inline asm instruction.

**VULN-04 (MEDIUM) — `.unwrap()` on guest exit messages (lines 608, 677, 710, 747, 815)**

**VULN-05 (MEDIUM) — Unsafe union loop with unchecked bounds (lines 292-295)**

**VULN-06 (LOW) — Missing canonical address check in emulator linearize (arch/x86/emulator/mod.rs:134)**
Code has an explicit `// TODO` acknowledging the gap.

The strongest CTF flag candidate is VULN-01 or VULN-03 — both are guest-triggerable with a one-liner from inside the VM.

---

# Vulnerability Report: cloud-hypervisor/vmm

**8 findings** — 2 HIGH, 3 MEDIUM, 2 LOW, 1 INFO

## VLN-01: Path Traversal via Snapshot/Coredump URL (HIGH)

`vmm/src/migration.rs:38-47` — `url_to_file()` strips `file://` and returns the raw path with **zero validation**. Used for coredump writes (`vm.rs:2989`), which dump all guest memory to an attacker-chosen path. `url_to_path()` (line 20) only checks `is_dir()` — no canonicalization, no symlink resolution.

**Attack:** `PUT /api/v1/vm.coredump` with `{"destination_url": "file:///etc/cron.d/backdoor"}` → arbitrary file write + guest memory disclosure.

## VLN-02: Unpinned Git Dependency (HIGH)

`vmm/Cargo.toml:61` — `micro_http` (the HTTP API parser) is pinned to `branch = "main"`, not a commit hash. A compromised upstream push goes straight into the VMM.

## VLN-03: `unchecked_sub` Underflow (MEDIUM)

`memory_manager.rs:1011,1201` — `GuestAddress::unchecked_sub(1)` wraps to `u64::MAX` if the address is zero, corrupting guest/device memory boundaries.

## VLN-04: Hotplug Panic DoS (MEDIUM)

`memory_manager.rs:1695` — `.try_into().unwrap()` on API-supplied size panics on 32-bit `GuestUsize` overflow, crashing the VMM.

## VLN-05: Landlock TOCTOU via Symlink (MEDIUM)

`vm_config.rs:578-591` — `read_link()` resolves VFIO device path, then uses filename to grant Landlock access. Symlink can change between resolution and use.

## VLN-06: Build PATH Hijack (LOW)

`cloud-hypervisor/build.rs:12` — `Command::new("git")` without absolute path. Malicious `git` in `$PATH` gets code execution at build time.

## VLN-07: Env Var Injection in Build (LOW)

`cloud-hypervisor/build.rs:22` — `CH_EXTRA_VERSION` concatenated into `cargo:rustc-env` without sanitization. Newlines inject additional cargo directives.

## VLN-08: `cfg(fuzzing)` Disables Security (INFO)

`vmm/build.rs:7` declares the fuzzing cfg. When active, TAP offload, epoll timeouts, and MTU detection are all stubbed out. Accidental production use weakens the hypervisor.

---
