// forensics/mod.rs — Evidential integrity & chain-of-custody tracking
//
// PS requirement: "preserving evidential integrity" for forensic-grade recovery.
// Every carved file gets a SHA-256 hash at extraction time.
// Chain-of-custody records the source → extraction → export path.

use std::path::PathBuf;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyRecord {
    pub file_id:         String,
    pub source_image:    String,
    pub source_offset:   u64,
    pub extracted_at:    String,      // ISO-8601
    pub extracted_path:  PathBuf,
    pub sha256_at_extract: String,
    pub exported_paths:  Vec<ExportRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    pub exported_at:   String,
    pub destination:   PathBuf,
    pub sha256_verify: String,
    pub matches:       bool,
}

use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref CUSTODY_LOG: Mutex<Vec<CustodyRecord>> = Mutex::new(Vec::new());
}

/// Record an extraction event and add to the global custody ledger.
pub fn record_extraction(
    file_id:      &str,
    source_image: &str,
    offset:       u64,
    path:         PathBuf,
    sha256:       &str,
) -> CustodyRecord {
    let rec = CustodyRecord {
        file_id:           file_id.to_string(),
        source_image:      source_image.to_string(),
        source_offset:     offset,
        extracted_at:      Utc::now().to_rfc3339(),
        extracted_path:    path,
        sha256_at_extract: sha256.to_string(),
        exported_paths:    vec![],
    };

    if let Ok(mut log) = CUSTODY_LOG.lock() {
        log.push(rec.clone());
    }

    rec
}

/// Add an export event verifying destination SHA-256 match.
pub fn record_export(
    file_id:     &str,
    destination: PathBuf,
) -> std::io::Result<bool> {
    use sha2::{Digest, Sha256};

    let data = std::fs::read(&destination)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hex::encode(hasher.finalize());

    if let Ok(mut log) = CUSTODY_LOG.lock() {
        if let Some(record) = log.iter_mut().find(|r| r.file_id == file_id) {
            let matches = hash == record.sha256_at_extract;
            record.exported_paths.push(ExportRecord {
                exported_at:   Utc::now().to_rfc3339(),
                destination,
                sha256_verify: hash,
                matches,
            });
            return Ok(matches);
        }
    }
    Ok(false)
}

pub mod cmd {
    use super::*;
    use crate::error::Result;

    #[tauri::command]
    pub fn get_chain_of_custody() -> Result<Vec<CustodyRecord>> {
        let log = CUSTODY_LOG.lock().unwrap().clone();
        Ok(log)
    }
}
