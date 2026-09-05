// eraser/file/mod.rs — Secure File & Folder Eraser (Module 2)
//
// PS requirement: selective secure deletion, metadata scrubbing,
// residual trace removal, batch operations, multi-filesystem support.

pub mod shredder;
pub mod metadata;

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use walkdir::WalkDir;

use crate::error::Result;
use crate::report::{AuditOperation, log_event};

#[derive(Deserialize)]
pub struct ShredRequest {
    pub paths:       Vec<String>,
    pub passes:      u8,      // number of overwrite passes (default 3)
    pub scrub_meta:  bool,    // also scrub filesystem metadata
}

#[derive(Serialize, Clone)]
pub struct ShredProgress {
    pub path:      String,
    pub current:   usize,
    pub total:     usize,
    pub percent:   u8,
}

#[derive(Serialize)]
pub struct ShredResult {
    pub shredded: Vec<String>,
    pub failed:   Vec<String>,
}

pub mod cmd {
    use super::*;

    /// Securely shred a list of files/folders.
    #[tauri::command]
    pub fn shred_paths(app: AppHandle, req: ShredRequest) -> Result<ShredResult> {
        let mut all_files: Vec<PathBuf> = Vec::new();

        // Expand folders recursively
        for path_str in &req.paths {
            let p = PathBuf::from(path_str);
            if p.is_dir() {
                for entry in WalkDir::new(&p).contents_first(true)
                    .into_iter().filter_map(|e| e.ok())
                {
                    all_files.push(entry.path().to_path_buf());
                }
            } else {
                all_files.push(p);
            }
        }

        let total = all_files.len();
        let mut shredded = Vec::new();
        let mut failed   = Vec::new();

        for (i, path) in all_files.iter().enumerate() {
            let path_str = path.to_string_lossy().to_string();

            let pct = ((i as f64 / total as f64) * 100.0) as u8;
            let _ = app.emit("shred_progress", ShredProgress {
                path: path_str.clone(), current: i + 1, total, percent: pct,
            });

            if path.is_file() {
                let result = shred_one(path, req.passes, req.scrub_meta);
                match result {
                    Ok(_)  => shredded.push(path_str),
                    Err(e) => {
                        log::warn!("shred failed for {}: {}", path_str, e);
                        failed.push(path_str);
                    }
                }
            } else if path.is_dir() {
                // Remove directory (files already processed above via contents_first)
                let _ = std::fs::remove_dir(path);
            }
        }

        log_event(AuditOperation::WipeFile {
            count: shredded.len(),
            passes: req.passes,
        });

        Ok(ShredResult { shredded, failed })
    }

    /// Wipe free space on a volume to destroy unlinked file residue.
    #[tauri::command]
    pub fn wipe_free_space(app: AppHandle, volume_path: String, passes: u8) -> Result<u64> {
        shredder::wipe_slack_space(&volume_path, passes, move |written, total| {
            let pct = if total > 0 { ((written as f64 / total as f64) * 100.0) as u8 } else { 0 };
            let _ = app.emit("slack_wipe_progress", serde_json::json!({
                "bytes_written": written, "total": total, "percent": pct
            }));
        })
    }
}

/// Shred a single file: overwrite content + scrub metadata + unlink.
fn shred_one(path: &std::path::Path, passes: u8, scrub_meta: bool) -> Result<()> {
    if scrub_meta {
        // Rename to random name to defeat directory scanners
        metadata::rename_random(path)?;
    }

    // Re-open after possible rename
    shredder::overwrite_file(path, passes)?;

    if scrub_meta {
        metadata::scrub_timestamps(path)?;
    }

    std::fs::remove_file(path)?;
    Ok(())
}
