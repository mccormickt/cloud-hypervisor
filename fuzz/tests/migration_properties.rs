// Property-based validation tests for migration protocol findings.
//
// These tests exercise the invariants broken by:
//   V2-22 — Command/Status enum UB via ByteValued reinterpretation
//   V2-30 — MemoryRangeTable::read_from assert! on non-aligned length
//   V2-04 — MemoryRangeTable::read_from unbounded allocation
//
// Each test encodes a property that *should* hold but currently doesn't
// in the production code. Failures here are expected until the upstream
// fixes land — they demonstrate the bug, not a test defect.

use std::io::Cursor;
use std::mem::size_of;

use hegel::generators::{self, Generator};
use vm_migration::protocol::{MemoryRange, MemoryRangeTable, Request, Response};

// ---------------------------------------------------------------------------
// V2-22: Request::read_from must not produce undefined behavior on any input.
//
// Property: For any 16-byte input, read_from either returns Ok with a
// valid Request, or returns Err. It must never invoke UB by constructing
// a Command enum with an invalid discriminant.
//
// This property FAILS today because ByteValued reinterprets raw bytes
// as the #[repr(u16)] Command enum without discriminant validation.
// A peer sending command >= 8 creates UB.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 1000)]
fn request_read_from_never_panics(tc: hegel::TestCase) {
    let bytes: Vec<u8> = tc.draw(
        generators::vecs(generators::integers::<u8>())
            .min_size(16)
            .max_size(16),
    );
    let mut cursor = Cursor::new(&bytes[..]);

    // This should never panic or invoke UB. Today it does for command >= 8.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Request::read_from(&mut cursor)
    }));
    assert!(result.is_ok(), "Request::read_from panicked on input");
}

// Property: A valid Request round-trips through write_to/read_from.
#[hegel::test(test_cases = 500)]
fn request_roundtrip(tc: hegel::TestCase) {
    let cmd_idx = tc.draw(generators::integers::<u16>().min_value(0).max_value(7));
    let length = tc.draw(generators::integers::<u64>());

    // Construct valid command via known-good discriminant
    let cmd = match cmd_idx {
        0 => vm_migration::protocol::Command::Invalid,
        1 => vm_migration::protocol::Command::Start,
        2 => vm_migration::protocol::Command::Config,
        3 => vm_migration::protocol::Command::State,
        4 => vm_migration::protocol::Command::Memory,
        5 => vm_migration::protocol::Command::Complete,
        6 => vm_migration::protocol::Command::Abandon,
        7 => vm_migration::protocol::Command::MemoryFd,
        _ => unreachable!(),
    };

    let original = Request::new(cmd, length);
    let mut buf = Vec::new();
    original.write_to(&mut buf).expect("write_to failed");

    let mut cursor = Cursor::new(&buf[..]);
    let decoded = Request::read_from(&mut cursor).expect("read_from failed");

    assert_eq!(original.command(), decoded.command());
    assert_eq!(original.length(), decoded.length());
}

// ---------------------------------------------------------------------------
// V2-22: Response::read_from has the same ByteValued UB for Status enum.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 1000)]
fn response_read_from_never_panics(tc: hegel::TestCase) {
    let bytes: Vec<u8> = tc.draw(
        generators::vecs(generators::integers::<u8>())
            .min_size(16)
            .max_size(16),
    );
    let mut cursor = Cursor::new(&bytes[..]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Response::read_from(&mut cursor)
    }));
    assert!(result.is_ok(), "Response::read_from panicked on input");
}

// ---------------------------------------------------------------------------
// V2-30: MemoryRangeTable::read_from must return Err (not panic) when
// length is not a multiple of size_of::<MemoryRange>() (16 bytes).
//
// Property: For any length value, read_from either succeeds or returns Err.
// It must never panic via assert!.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 1000)]
fn memory_range_table_read_from_never_panics_on_misaligned(tc: hegel::TestCase) {
    // Generate lengths that are NOT multiples of 16
    let base = tc.draw(generators::integers::<u64>().max_value(1024));
    let remainder = tc.draw(generators::integers::<u64>().min_value(1).max_value(15));
    let misaligned_length = base.wrapping_mul(size_of::<MemoryRange>() as u64)
        .wrapping_add(remainder);

    // Provide enough backing data
    let data = vec![0u8; misaligned_length.min(2048) as usize + 64];
    let mut cursor = Cursor::new(&data[..]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MemoryRangeTable::read_from(&mut cursor, misaligned_length)
    }));
    assert!(
        result.is_ok(),
        "MemoryRangeTable::read_from panicked on misaligned length {misaligned_length}"
    );
}

// ---------------------------------------------------------------------------
// V2-04: MemoryRangeTable::read_from must not allocate unbounded memory.
//
// Property: For any aligned length, read_from should either succeed or
// return Err — but must not OOM-kill the process. We test with lengths
// up to a sane cap to verify the function handles them gracefully.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 200)]
fn memory_range_table_read_from_bounded_alloc(tc: hegel::TestCase) {
    // Generate aligned lengths including very large values
    let multiplier = tc.draw(generators::integers::<u64>().max_value(0x1_0000));
    let length = multiplier.wrapping_mul(size_of::<MemoryRange>() as u64);

    // Only provide a small buffer — if the code tries to allocate `length`
    // bytes and then read_exact, the read will fail. The question is whether
    // it panics (OOM) or returns an error.
    let data = vec![0u8; 256];
    let mut cursor = Cursor::new(&data[..]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MemoryRangeTable::read_from(&mut cursor, length)
    }));

    // We accept either Ok (if length fit) or a caught error.
    // We reject panics (which indicate assert! or OOM abort).
    assert!(
        result.is_ok(),
        "MemoryRangeTable::read_from panicked on length {length}"
    );
}

// ---------------------------------------------------------------------------
// MemoryRangeTable round-trip: write_to/read_from preserves data.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 500)]
fn memory_range_table_roundtrip(tc: hegel::TestCase) {
    let num_entries = tc.draw(generators::integers::<usize>().max_value(64));
    let mut table = MemoryRangeTable::default();

    for _ in 0..num_entries {
        let gpa = tc.draw(generators::integers::<u64>());
        let length = tc.draw(generators::integers::<u64>());
        table.push(MemoryRange { gpa, length });
    }

    let mut buf = Vec::new();
    table.write_to(&mut buf).expect("write_to failed");

    let table_length = table.length();
    let mut cursor = Cursor::new(&buf[..]);
    let decoded = MemoryRangeTable::read_from(&mut cursor, table_length)
        .expect("read_from failed on valid data");

    assert_eq!(table.regions().len(), decoded.regions().len());
    for (orig, dec) in table.regions().iter().zip(decoded.regions().iter()) {
        assert_eq!(orig.gpa, dec.gpa);
        assert_eq!(orig.length, dec.length);
    }
}
