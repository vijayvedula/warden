#![no_main]
//! Fuzz the JSON-RPC request parser (the agent-controlled wire input).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<warden::jsonrpc::Request>(data);
});
