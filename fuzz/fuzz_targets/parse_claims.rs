#![no_main]
//! Fuzz token-claims deserialization (untrusted token payloads).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<warden::identity::Claims>(data);
});
