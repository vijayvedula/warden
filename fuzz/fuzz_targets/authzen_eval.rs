#![no_main]
//! Fuzz the AuthZEN PDP evaluation (untrusted request body -> decision).
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use warden::policy::PolicyConfig;

static POLICY: OnceLock<PolicyConfig> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let p = POLICY.get_or_init(|| PolicyConfig::from_str("default = \"deny\"").unwrap());
    let _ = warden::authzen::evaluate(p, data);
});
