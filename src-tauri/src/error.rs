// error.rs — Unified application error type

use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Safety violation: {0}")]
    SafetyViolation(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Wipe verification failed: {mismatches} sector(s) did not match pattern")]
    WipeVerificationFailed { mismatches: u64 },

    #[error("Carve error: {0}")]
    CarveError(String),

    #[error("Report error: {0}")]
    ReportError(String),

    #[error("Operation cancelled")]
    Cancelled,
}

// Make AppError serializable so Tauri can send it to the frontend
impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
