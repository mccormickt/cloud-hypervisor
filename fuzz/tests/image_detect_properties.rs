// Property-based validation tests for image detection findings.
//
// Exercises:
//   V2-17 — Sector-0 write-ban regression after autodetect persistence
//   block/src/lib.rs:1080 detect_image_type parse robustness
//
// Property: detect_image_type must never panic on any input. It should
// return Ok(ImageType) for any file content.

use std::ffi;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::{FromRawFd, RawFd};

use block::detect_image_type;
use hegel::generators;

fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}

fn file_from_bytes(bytes: &[u8]) -> File {
    let shm = memfd_create(&ffi::CString::new("pbt").unwrap(), 0)
        .expect("memfd_create failed");
    let mut f: File = unsafe { File::from_raw_fd(shm) };
    f.write_all(bytes).expect("write failed");
    f.seek(SeekFrom::Start(0)).expect("seek failed");
    f
}

// ---------------------------------------------------------------------------
// Parse robustness: detect_image_type never panics on arbitrary content.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 1000)]
fn detect_image_type_never_panics(tc: hegel::TestCase) {
    let bytes: Vec<u8> = tc.draw(generators::binary().max_size(8192));
    if bytes.is_empty() {
        return;
    }
    let mut f = file_from_bytes(&bytes);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        detect_image_type(&mut f)
    }));
    assert!(result.is_ok(), "detect_image_type panicked");
}

// ---------------------------------------------------------------------------
// Idempotence: calling detect_image_type twice on the same file gives
// the same result (the function should seek back or be idempotent).
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 500)]
fn detect_image_type_idempotent(tc: hegel::TestCase) {
    let bytes: Vec<u8> = tc.draw(generators::binary().min_size(512).max_size(8192));
    let mut f = file_from_bytes(&bytes);

    let first = detect_image_type(&mut f);
    f.seek(SeekFrom::Start(0)).unwrap();
    let second = detect_image_type(&mut f);

    match (first, second) {
        (Ok(a), Ok(b)) => assert_eq!(
            format!("{a}"),
            format!("{b}"),
            "detect_image_type is not idempotent"
        ),
        (Err(_), Err(_)) => {} // both errored, fine
        _ => panic!("detect_image_type returned different Result variants on same input"),
    }
}

// ---------------------------------------------------------------------------
// Magic prefix property: qcow2 magic at offset 0 always detects as Qcow2.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 200)]
fn qcow2_magic_always_detected(tc: hegel::TestCase) {
    let tail_len = tc.draw(generators::integers::<usize>().min_value(508).max_value(4096));
    let tail: Vec<u8> = tc.draw(generators::binary().min_size(tail_len).max_size(tail_len));

    // QFI\xfb magic
    let mut data = vec![0x51, 0x46, 0x49, 0xfb];
    data.extend_from_slice(&tail);

    let mut f = file_from_bytes(&data);
    let result = detect_image_type(&mut f);

    match result {
        Ok(img_type) => assert_eq!(
            format!("{img_type}"),
            "qcow2",
            "qcow2 magic not detected"
        ),
        Err(e) => panic!("detect_image_type failed on qcow2 magic: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Magic prefix property: VHDX signature at offset 0 always detects as Vhdx.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 200)]
fn vhdx_magic_always_detected(tc: hegel::TestCase) {
    let tail_len = tc.draw(generators::integers::<usize>().min_value(504).max_value(4096));
    let tail: Vec<u8> = tc.draw(generators::binary().min_size(tail_len).max_size(tail_len));

    // 'vhdxfile' signature (8 bytes LE u64)
    let mut data = b"vhdxfile".to_vec();
    data.extend_from_slice(&tail);

    let mut f = file_from_bytes(&data);
    let result = detect_image_type(&mut f);

    match result {
        Ok(img_type) => assert_eq!(
            format!("{img_type}"),
            "vhdx",
            "vhdx signature not detected"
        ),
        Err(e) => panic!("detect_image_type failed on vhdx signature: {e}"),
    }
}
