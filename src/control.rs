//! The admin control plane: a Warden-side pause state, backed by a control
//! file so a separate `warden pause` / `warden resume` process can flip it.
//!
//! Revocation model (see `docs/accountable-authorization.md` Sec 6):
//! admin -> pause agent -> update config -> resume agent. "Pause" is enforced at
//! Warden, never by trusting the agent: a paused gateway stops forwarding
//! `tools/call`. On the paused->running transition the gateway reloads policy
//! from disk, so "resume" picks up the updated config without a restart.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlState {
    Running,
    Paused,
}

impl ControlState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ControlState::Running => "running",
            ControlState::Paused => "paused",
        }
    }
}

/// A control file. Missing/empty/unreadable => Running (fail open for liveness;
/// pausing is the deliberate, fail-closed-for-actions act).
#[derive(Clone)]
pub struct Control {
    path: PathBuf,
}

impl Control {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Control { path: path.into() }
    }

    pub fn state(&self) -> ControlState {
        match std::fs::read_to_string(&self.path) {
            Ok(s) if s.trim() == "paused" => ControlState::Paused,
            _ => ControlState::Running,
        }
    }

    pub fn set(path: impl AsRef<Path>, state: ControlState) -> Result<(), String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, state.as_str()).map_err(|e| format!("write control: {e}"))
    }
}
