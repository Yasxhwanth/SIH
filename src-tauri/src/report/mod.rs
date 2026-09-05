// report/mod.rs — Report module root + Tauri IPC commands

pub mod audit_log;
pub mod pdf_cert;

use std::path::PathBuf;
use serde::Serialize;

use crate::error::Result;
pub use audit_log::{AuditOperation, AuditEntry, BlockchainAnchor, BsaCertificate};

// ── Public API for other modules ─────────────────────────────────────────────

/// Initialize the audit log from main.rs setup.
pub fn init_audit_log(app_data_dir: PathBuf) -> Result<()> {
    audit_log::init(app_data_dir)
}

/// Append an operation to the audit log (called by carver, eraser modules).
pub fn log_event(op: AuditOperation) {
    if let Err(e) = audit_log::append(op) {
        log::error!("audit log append failed: {}", e);
    }
}

// ── Tauri IPC Commands ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ChainVerifyResult {
    pub entries_checked: u64,
    pub chain_valid:     bool,
    pub first_bad_index: Option<u64>,
}

pub mod cmd {
    use super::*;
    use crate::report::pdf_cert::{CertRequest, generate_certificate};

    /// Return all audit log entries for the UI log viewer.
    #[tauri::command]
    pub fn get_audit_log() -> Result<Vec<AuditEntry>> {
        audit_log::read_all()
    }

    /// Verify the hash chain integrity and return results.
    #[tauri::command]
    pub fn verify_chain_integrity() -> Result<ChainVerifyResult> {
        let (checked, valid, bad) = audit_log::verify_chain()?;
        Ok(ChainVerifyResult {
            entries_checked: checked,
            chain_valid:     valid,
            first_bad_index: bad,
        })
    }

    /// Return the binary Merkle Tree root of the audit log.
    #[tauri::command]
    pub fn get_merkle_root() -> Result<String> {
        audit_log::compute_merkle_root()
    }

    /// Anchor current session audit chain to verifiable blockchain state representation.
    #[tauri::command]
    pub fn anchor_blockchain() -> Result<BlockchainAnchor> {
        let anchor = audit_log::anchor_blockchain()?;
        log_event(AuditOperation::Export {
            report_type: "Blockchain Anchor State Seal".into(),
            path: format!("Tx: {}", anchor.tx_hash),
        });
        Ok(anchor)
    }

    /// Generate legal Section 63 BSA 2023 evidentiary certificate.
    #[tauri::command]
    pub fn get_bsa_court_certificate(target: String, standard: String, case_id: String) -> Result<BsaCertificate> {
        audit_log::generate_bsa_certificate(&target, &standard, &case_id)
    }

    /// Generate and save a PDF erasure certificate.
    #[tauri::command]
    pub fn export_pdf_cert(req: CertRequest) -> Result<String> {
        let path = generate_certificate(&req)?;
        log_event(AuditOperation::Export {
            report_type: "PDF Certificate".into(),
            path: path.clone(),
        });
        Ok(path)
    }

    /// Generate a full forensic session report (JSON).
    #[tauri::command]
    pub fn export_forensic_report(output_path: String) -> Result<String> {
        let entries = audit_log::read_all()?;
        let (checked, valid, bad) = audit_log::verify_chain()?;

        let report = serde_json::json!({
            "generator":    "ForensiX v0.1.0",
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "ps_id":        "SIH-26149",
            "organisation": "NTRO",
            "chain_integrity": {
                "entries_checked": checked,
                "valid":           valid,
                "first_bad_index": bad,
            },
            "audit_log": entries,
        });

        std::fs::write(&output_path, serde_json::to_string_pretty(&report)?)?;

        log_event(AuditOperation::Export {
            report_type: "Forensic JSON Report".into(),
            path: output_path.clone(),
        });

        Ok(output_path)
    }
}
