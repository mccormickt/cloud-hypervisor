// Property-based validation tests for API findings.
//
// Exercises:
//   V2-38 — RestoreConfig::validate assert_eq! panic on crafted net_fds
//
// Property: RestoreConfig::validate must never panic on any deserialized
// input. It should return Ok or Err, never abort.

use hegel::generators::{self, Generator};
use vmm::config::{RestoreConfig, RestoredNetConfig};
use vmm::vm_config::VmConfig;

/// Deserialize a minimal VmConfig (no Default impl available).
fn minimal_vm_config() -> VmConfig {
    serde_json::from_str(r#"{"payload":null}"#).expect("minimal VmConfig deser failed")
}

// ---------------------------------------------------------------------------
// V2-38: RestoreConfig deserialized from arbitrary JSON must not panic
// during validate().
//
// The bug: RestoredNetConfig has independently deserializable `num_fds`
// and `fds` fields. The custom deserializer replaces FD values with -1
// sentinels but preserves Vec length. When num_fds != fds.len(), the
// assert_eq! at config.rs:2423 panics.
//
// Property: For any (num_fds, fds_count) pair, validate() returns a
// Result — never panics.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 500)]
fn restore_config_validate_never_panics(tc: hegel::TestCase) {
    let num_fds = tc.draw(generators::integers::<usize>().max_value(32));
    let fds_count = tc.draw(generators::integers::<usize>().max_value(32));
    let id: String = tc.draw(generators::text().min_size(1).max_size(16));

    let fds = if fds_count > 0 {
        Some(vec![-1i32; fds_count])
    } else {
        None
    };

    let net_fd = RestoredNetConfig {
        id,
        num_fds,
        fds,
    };

    let restore = RestoreConfig {
        source_url: "/tmp/test".into(),
        prefault: false,
        net_fds: Some(vec![net_fd]),
    };

    let vm_config = minimal_vm_config();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        restore.validate(&vm_config)
    }));

    assert!(
        result.is_ok(),
        "RestoreConfig::validate panicked (num_fds={num_fds}, fds_count={fds_count})"
    );
}

// ---------------------------------------------------------------------------
// Property: RestoreConfig deserialized from JSON never panics.
//
// This tests the full serde path: arbitrary JSON -> RestoreConfig ->
// validate(). Covers V2-38 via the deserialization route that an API
// caller would actually use.
// ---------------------------------------------------------------------------
#[hegel::test(test_cases = 500)]
fn restore_config_json_roundtrip_never_panics(tc: hegel::TestCase) {
    let num_fds = tc.draw(generators::integers::<u32>().max_value(20));
    let fds_count = tc.draw(generators::integers::<u32>().max_value(20));
    let id = format!("net{}", tc.draw(generators::integers::<u8>()));

    let fds_json = if fds_count > 0 {
        let fds: Vec<String> = (0..fds_count).map(|i| i.to_string()).collect();
        format!("[{}]", fds.join(","))
    } else {
        "null".to_string()
    };

    let json = format!(
        r#"{{"source_url":"file:///tmp/snap","net_fds":[{{"id":"{id}","num_fds":{num_fds},"fds":{fds_json}}}]}}"#,
    );

    let restore: RestoreConfig = match serde_json::from_str(&json) {
        Ok(r) => r,
        Err(_) => return,
    };

    let vm_config = minimal_vm_config();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        restore.validate(&vm_config)
    }));

    assert!(
        result.is_ok(),
        "RestoreConfig::validate panicked on JSON input (num_fds={num_fds}, fds_count={fds_count})"
    );
}
