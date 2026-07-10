#![no_main]
//! Fuzz the policy (TOML) parser.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = warden::policy::PolicyConfig::from_str(s);
    }
});
