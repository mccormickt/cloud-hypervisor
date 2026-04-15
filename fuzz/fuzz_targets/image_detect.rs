// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::ffi;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::{FromRawFd, RawFd};

use block::detect_image_type;
use libfuzzer_sys::{fuzz_target, Corpus};

// Fuzz the raw image auto-detection path.
//
// Exercises:
//   V2-17 — Sector-0 write-ban regression after autodetect persistence
//   block/src/lib.rs:1080 detect_image_type + downstream vhd/qcow/vhdx magic checks
//
// The harness writes fuzzer bytes to a memfd, then calls detect_image_type.
// This exercises the magic-number parsing, is_fixed_vhd footer check, and
// the aligned block read path without touching the filesystem.
fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.is_empty() {
        return Corpus::Reject;
    }

    let shm = match memfd_create(&ffi::CString::new("fuzz_img").unwrap(), 0) {
        Ok(fd) => fd,
        Err(_) => return Corpus::Reject,
    };
    let mut file: File = unsafe { File::from_raw_fd(shm) };

    if file.write_all(bytes).is_err() {
        return Corpus::Reject;
    }
    if file.seek(SeekFrom::Start(0)).is_err() {
        return Corpus::Reject;
    }

    let _ = detect_image_type(&mut file);

    Corpus::Keep
});

fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
    let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}
