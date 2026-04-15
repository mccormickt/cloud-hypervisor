// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::{fuzz_target, Corpus};
use vm_migration::protocol::{MemoryRangeTable, Request, Response};

// Fuzz the migration receive path.
//
// Exercises:
//   V2-22 — Command/Status enum UB via ByteValued reinterpretation
//   V2-30 — MemoryRangeTable::read_from assert! on non-aligned length
//   V2-04 — MemoryRangeTable::read_from unbounded allocation
//   V2-32 — vm_receive_config unvalidated config (serde_json parse)
//
// The harness feeds raw fuzzer bytes through a Cursor<&[u8]>, which
// implements Read, exercising the same code paths as a real migration
// socket without needing network I/O.
fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.len() < 16 {
        return Corpus::Reject;
    }

    let mut cursor = Cursor::new(bytes);

    // Phase 1: Request::read_from — reads 16 bytes, reinterprets as
    // Request via ByteValued::as_mut_slice. Invalid Command discriminants
    // (>= 8) produce UB under the current implementation (V2-22).
    let req = match Request::read_from(&mut cursor) {
        Ok(r) => r,
        Err(_) => return Corpus::Keep,
    };

    // Phase 2: Depending on command, exercise downstream parsers.
    // We cap the length to avoid OOM kills in the fuzzer (the real code
    // has no cap — that's V2-04/V2-29).
    let length = req.length();

    // For Memory commands, exercise MemoryRangeTable::read_from.
    // This hits V2-30 (assert on non-aligned length) and V2-04 (unbounded alloc).
    // Cap at 64 KiB to keep the fuzzer fast.
    if length > 0 && length <= 65536 {
        let _ = MemoryRangeTable::read_from(&mut cursor, length);
    }

    // For Config commands, exercise serde_json deserialization of the
    // remaining bytes. This hits V2-32 (unvalidated config injection).
    // We don't need the full VmMigrationConfig type — just exercising
    // serde_json::from_slice on the payload is enough to surface panics
    // in the deserialization path.
    let remaining = &bytes[cursor.position() as usize..];
    if !remaining.is_empty() {
        let _ = serde_json::from_slice::<serde_json::Value>(remaining);
    }

    // Phase 3: Response::read_from — same ByteValued pattern as Request.
    // Exercises V2-22 on the Status enum.
    if bytes.len() >= 32 {
        let mut resp_cursor = Cursor::new(&bytes[16..]);
        let _ = Response::read_from(&mut resp_cursor);
    }

    Corpus::Keep
});
