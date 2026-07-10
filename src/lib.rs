//! Warden -- an action control plane for AI agents.
//!
//! Library root: the modules are shared by the `warden` binary ([`main.rs`])
//! and by the fuzz targets / future embeddings. The CLI lives in the binary.

pub mod anchor;
pub mod approval_sig;
pub mod approvals;
pub mod audit;
pub mod authzen;
pub mod budget;
pub mod control;
pub mod demo;
pub mod dpop;
pub mod gateway;
pub mod http;
pub mod identity;
pub mod jsonrpc;
pub mod mcp;
pub mod net;
pub mod obs;
pub mod ocsf;
pub mod policy;
pub mod redact;
pub mod revocation;
pub mod sink;
pub mod txntoken;
pub mod upstream;
pub mod util;
