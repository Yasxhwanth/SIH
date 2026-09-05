// eraser/drive/mod.rs — Drive eraser module + Tauri IPC commands

pub mod strategies;
pub mod verify;

use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::error::{AppError, Result};
use crate::report::{AuditOperation, log_event};
use strategies::{WipeStandard, wipe};
use verify::{verify_wipe, ExpectedPattern};

lazy_static::lazy_static! {
    static ref WIPE_CANCEL: Mutex<HashMap<String, Arc<AtomicBool>>> =
        Mutex::new(HashMap::new());
}

#[derive(Serialize)]
pub struct WipeStandardInfo {
    pub id:               String,
    pub label:            &'static str,
    pub passes:           u8,
    pub compliance_note:  &'static str,
}

#[derive(Deserialize)]
pub struct WipeRequest {
    pub job_id:    String,
    pub path:      String,
    pub standard:  WipeStandard,
    pub run_verify: bool,
}

#[derive(Serialize, Clone)]
pub struct WipeProgress {
    pub job_id:        String,
    pub bytes_written: u64,
    pub total_bytes:   u64,
    pub percent:       u8,
    pub current_pass:  u8,
    pub total_passes:  u8,
}

#[derive(Serialize, Clone)]
pub struct WipeResult {
    pub job_id:       String,
    pub path:         String,
    pub standard:     WipeStandard,
    pub bytes_wiped:  u64,
    pub verify:       Option<verify::VerifyResult>,
    pub success:      bool,
    pub error:        Option<String>,
}

pub mod cmd {
    use super::*;

    /// List all available wipe standards for the UI dropdown.
    #[tauri::command]
    pub fn get_wipe_standards() -> Vec<WipeStandardInfo> {
        vec![
            WipeStandardInfo {
                id: "nist_clear".into(),
                label: WipeStandard::NistClear.label(),
                passes: WipeStandard::NistClear.passes(),
                compliance_note: WipeStandard::NistClear.compliance_note(),
            },
            WipeStandardInfo {
                id: "random".into(),
                label: WipeStandard::Random.label(),
                passes: WipeStandard::Random.passes(),
                compliance_note: WipeStandard::Random.compliance_note(),
            },
            WipeStandardInfo {
                id: "dod3".into(),
                label: WipeStandard::Dod3Pass.label(),
                passes: WipeStandard::Dod3Pass.passes(),
                compliance_note: WipeStandard::Dod3Pass.compliance_note(),
            },
            WipeStandardInfo {
                id: "gutmann7".into(),
                label: WipeStandard::Gutmann7.label(),
                passes: WipeStandard::Gutmann7.passes(),
                compliance_note: WipeStandard::Gutmann7.compliance_note(),
            },
            WipeStandardInfo {
                id: "nist_purge".into(),
                label: WipeStandard::NistPurge.label(),
                passes: WipeStandard::NistPurge.passes(),
                compliance_note: WipeStandard::NistPurge.compliance_note(),
            },
        ]
    }

    /// Start a drive/image wipe — runs in worker thread.
    #[tauri::command]
    pub fn start_drive_wipe(app: AppHandle, req: WipeRequest) -> Result<String> {
        // Safety gate: refuse to wipe mounted system paths
        safety_check(&req.path)?;

        let cancel = Arc::new(AtomicBool::new(false));
        WIPE_CANCEL.lock().unwrap()
            .insert(req.job_id.clone(), Arc::clone(&cancel));

        let job_id = req.job_id.clone();
        std::thread::spawn(move || {
            run_wipe_job(app, req, cancel);
        });

        Ok(job_id)
    }
}

fn safety_check(path: &str) -> Result<()> {
    let p = path.to_lowercase();
    let forbidden = [
        "c:\\windows", "c:/windows", "/dev/sda\0", "/",
        "/boot", "/etc", "/usr", "/bin", "/lib", "/sys", "/proc",
    ];
    for f in forbidden {
        if p.starts_with(f) || p == f {
            return Err(AppError::SafetyViolation(
                format!("Refusing to wipe system path: {}", path)
            ));
        }
    }
    Ok(())
}

fn run_wipe_job(app: AppHandle, req: WipeRequest, cancel: Arc<AtomicBool>) {
    let job_id    = req.job_id.clone();
    let standard  = req.standard;
    let total_passes = standard.passes();

    let app_c    = app.clone();
    let jid      = job_id.clone();
    let cancel_c = Arc::clone(&cancel);

    let on_progress = Box::new(move |written: u64, total: u64| {
        let pct = if total > 0 { ((written as f64 / total as f64) * 100.0) as u8 } else { 0 };
        let _ = app_c.emit("wipe_progress", WipeProgress {
            job_id:        jid.clone(),
            bytes_written: written,
            total_bytes:   total,
            percent:       pct,
            current_pass:  1,
            total_passes,
        });
    });

    let wipe_result = wipe(&req.path, standard, cancel_c, on_progress);

    let (bytes_wiped, success, error) = match wipe_result {
        Ok(b)  => (b, true, None),
        Err(e) => (0, false, Some(e.to_string())),
    };

    // Post-wipe verification
    let verify_result = if req.run_verify && success {
        let expected = match standard {
            WipeStandard::NistClear  => ExpectedPattern::Zero,
            WipeStandard::Dod3Pass   => ExpectedPattern::Random,
            WipeStandard::NistPurge  => ExpectedPattern::Random,
            WipeStandard::Random     => ExpectedPattern::Random,
            WipeStandard::Gutmann7   => ExpectedPattern::Random,
        };
        verify_wipe(&req.path, expected).ok()
    } else {
        None
    };

    // Log to audit trail
    log_event(AuditOperation::WipeDrive {
        path:         req.path.clone(),
        standard:     format!("{:?}", standard),
        bytes_wiped,
        verify_pass:  verify_result.as_ref().map(|v| v.pass),
    });

    let result = WipeResult {
        job_id: job_id.clone(),
        path: req.path,
        standard,
        bytes_wiped,
        verify: verify_result,
        success,
        error,
    };

    let _ = app.emit("wipe_complete", result);
}
