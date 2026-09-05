// carver/mod.rs — Module root + Tauri IPC commands for carver

pub mod signatures;
pub mod scanner;
pub mod extractor;
pub mod validator;
pub mod confidence;
pub mod classifier;
pub mod fragment;
pub mod mft;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::error::{AppError, Result};
use crate::report::{AuditOperation, log_event};
use extractor::CarvedFile;
use signatures::all_signatures;

// ── Session state (shared across commands) ────────────────────────────────────

type SessionId = String;

#[derive(Default)]
pub struct CarveSession {
    pub results:  Vec<CarvedFile>,
    #[allow(dead_code)]
    pub image:    String,
    pub finished: bool,
}

lazy_static::lazy_static! {
    static ref SESSIONS: Mutex<HashMap<SessionId, CarveSession>> =
        Mutex::new(HashMap::new());
    static ref CANCEL_FLAGS: Mutex<HashMap<SessionId, Arc<AtomicBool>>> =
        Mutex::new(HashMap::new());
}

// ── IPC Commands ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct CarveRequest {
    pub session_id:  String,
    pub image_path:  String,
    pub output_dir:  String,
    pub enabled_exts: Vec<String>, // empty = all
}

#[derive(Serialize, Clone)]
pub struct CarveProgress {
    pub session_id:    String,
    pub bytes_scanned: u64,
    pub total_bytes:   u64,
    pub percent:       u8,
    pub files_found:   usize,
}

pub mod cmd {
    use super::*;

    /// Start a carve session — runs in a spawned thread, emits progress events.
    #[tauri::command]
    pub fn start_carve(app: AppHandle, req: CarveRequest) -> Result<String> {
        let session_id = req.session_id.clone();
        let cancel = Arc::new(AtomicBool::new(false));

        CANCEL_FLAGS.lock().unwrap()
            .insert(session_id.clone(), Arc::clone(&cancel));

        SESSIONS.lock().unwrap()
            .insert(session_id.clone(), CarveSession {
                image:   req.image_path.clone(),
                results: vec![],
                finished: false,
            });

        let sid = session_id.clone();
        std::thread::spawn(move || {
            run_carve_session(app, req, cancel, sid);
        });

        Ok(session_id)
    }

    /// Cancel a running carve session.
    #[tauri::command]
    pub fn cancel_carve(session_id: String) -> Result<()> {
        if let Some(flag) = CANCEL_FLAGS.lock().unwrap().get(&session_id) {
            flag.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Get results for a completed (or in-progress) session.
    #[tauri::command]
    pub fn get_carve_results(session_id: String) -> Result<Vec<CarvedFile>> {
        let sessions = SESSIONS.lock().unwrap();
        match sessions.get(&session_id) {
            Some(s) => Ok(s.results.clone()),
            None    => Err(AppError::CarveError(format!("session {} not found", session_id))),
        }
    }

    /// Read a slice of bytes from any file for the interactive Hex & ASCII viewer
    #[tauri::command]
    pub fn read_file_hex(path: String, offset: u64, length: usize) -> Result<HexChunk> {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};
        use std::path::Path;

        let norm = scanner::normalise_path(&path);
        let path_obj = Path::new(&norm);

        let mut target_path = path_obj.to_path_buf();
        if !target_path.exists() {
            let alt1 = Path::new("recovered_evidence").join(&norm);
            if alt1.exists() {
                target_path = alt1;
            } else {
                let alt2 = Path::new("src-tauri").join(&norm);
                if alt2.exists() {
                    target_path = alt2;
                } else {
                    let alt3 = Path::new("src-tauri").join("recovered_evidence").join(&norm);
                    if alt3.exists() {
                        target_path = alt3;
                    }
                }
            }
        }

        let mut f = File::open(&target_path)?;
        let total_size = f.seek(SeekFrom::End(0))?;
        let seek_off = offset.min(total_size);
        f.seek(SeekFrom::Start(seek_off))?;
        let to_read = length.min(4096).min((total_size.saturating_sub(seek_off)) as usize);
        let mut buf = vec![0u8; to_read];
        if to_read > 0 {
            f.read_exact(&mut buf).ok();
        }
        Ok(HexChunk {
            offset: seek_off,
            bytes: buf,
            total_size,
        })
    }

    /// Read visual, video, audio, or textual preview for carved artifacts
    #[tauri::command]
    pub fn read_file_preview(path: String) -> Result<FilePreview> {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};
        use std::path::Path;

        let norm = scanner::normalise_path(&path);
        let path_obj = Path::new(&norm);

        // Attempt multiple resolution paths if relative
        let mut target_path = path_obj.to_path_buf();
        if !target_path.exists() {
            let alt1 = Path::new("recovered_evidence").join(&norm);
            if alt1.exists() {
                target_path = alt1;
            } else {
                let alt2 = Path::new("src-tauri").join(&norm);
                if alt2.exists() {
                    target_path = alt2;
                } else {
                    let alt3 = Path::new("src-tauri").join("recovered_evidence").join(&norm);
                    if alt3.exists() {
                        target_path = alt3;
                    }
                }
            }
        }

        let mut f = File::open(&target_path)?;
        let total_size = f.seek(SeekFrom::End(0))?;
        f.seek(SeekFrom::Start(0))?;

        let ext = target_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let image_exts = [
            "jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "svg", "avif", "tif", "tiff",
            "cr2", "nef", "arw", "dng", "raf", "rw2",
        ];
        let video_exts = [
            "mp4", "m4v", "webm", "mkv", "mov", "avi", "ogg", "ogv", "flv", "3gp", "wmv",
        ];
        let audio_exts = [
            "mp3", "wav", "ogg", "oga", "flac", "m4a", "aac", "wma", "mid", "midi",
        ];
        let text_exts = [
            "txt", "log", "json", "xml", "html", "htm", "xhtml", "css", "js", "mjs", "ts",
            "py", "rs", "c", "cpp", "h", "hpp", "cs", "java", "go", "php", "rb", "sh", "bash",
            "ps1", "bat", "cmd", "csv", "tsv", "sql", "md", "markdown", "yaml", "yml", "toml",
            "ini", "cfg", "conf", "reg", "pem", "crt", "cer", "key", "pub", "asc", "sig", "jwt",
            "env", "rtf", "vtt", "srt", "diff", "patch", "hex", "asm",
        ];

        // 1. IMAGE PREVIEW
        if image_exts.contains(&ext.as_str()) {
            let read_limit = total_size.min(15 * 1024 * 1024) as usize; // up to 15 MB
            let mut buf = vec![0u8; read_limit];
            f.read_exact(&mut buf).ok();

            // Handle Camera RAW thumbnails and SVG vector text
            let mut svg_text_opt: Option<String> = None;
            let (mime, final_buf) = if ext == "svg" {
                let mut text = String::from_utf8_lossy(&buf).to_string();
                if !text.contains("xmlns=") {
                    if let Some(pos) = text.find("<svg") {
                        text.insert_str(pos + 4, " xmlns=\"http://www.w3.org/2000/svg\"");
                    }
                }
                let bytes = text.as_bytes().to_vec();
                svg_text_opt = Some(text);
                ("image/svg+xml", bytes)
            } else if matches!(ext.as_str(), "cr2" | "nef" | "arw" | "dng" | "raf" | "rw2" | "tif" | "tiff") {
                // Search for embedded JPEG thumbnail magic (FF D8 FF)
                if let Some(pos) = buf.windows(3).position(|w| w == [0xFF, 0xD8, 0xFF]) {
                    let eoi = buf[pos..].windows(2).position(|w| w == [0xFF, 0xD9]).map(|p| pos + p + 2).unwrap_or(buf.len());
                    ("image/jpeg", buf[pos..eoi].to_vec())
                } else {
                    ("image/png", buf)
                }
            } else {
                let m = match ext.as_str() {
                    "jpg" | "jpeg" => "image/jpeg",
                    "png"          => "image/png",
                    "gif"          => "image/gif",
                    "bmp"          => "image/bmp",
                    "webp"         => "image/webp",
                    "ico"          => "image/x-icon",
                    "avif"         => "image/avif",
                    _              => "image/png",
                };
                (m, buf)
            };

            let b64 = format!("data:{};base64,{}", mime, base64_encode(&final_buf));
            return Ok(FilePreview {
                is_image: true,
                is_video: false,
                is_audio: false,
                is_text: svg_text_opt.is_some(),
                data_base64: Some(b64),
                text_content: svg_text_opt,
                mime_type: mime.to_string(),
                file_size: total_size,
            });
        }

        // 2. VIDEO PREVIEW
        if video_exts.contains(&ext.as_str()) {
            let read_limit = total_size.min(25 * 1024 * 1024) as usize; // up to 25 MB for video stream
            let mut buf = vec![0u8; read_limit];
            f.read_exact(&mut buf).ok();

            let mime = match ext.as_str() {
                "mp4" | "m4v" => "video/mp4",
                "webm"        => "video/webm",
                "ogg" | "ogv" => "video/ogg",
                "mov"         => "video/mp4", // Modern Chromium plays MP4/MOV h264 natively
                "mkv"         => "video/webm",
                "avi"         => "video/x-msvideo",
                _             => "video/mp4",
            };
            let b64 = format!("data:{};base64,{}", mime, base64_encode(&buf));
            return Ok(FilePreview {
                is_image: false,
                is_video: true,
                is_audio: false,
                is_text: false,
                data_base64: Some(b64),
                text_content: None,
                mime_type: mime.to_string(),
                file_size: total_size,
            });
        }

        // 3. AUDIO PREVIEW
        if audio_exts.contains(&ext.as_str()) {
            let read_limit = total_size.min(20 * 1024 * 1024) as usize; // up to 20 MB
            let mut buf = vec![0u8; read_limit];
            f.read_exact(&mut buf).ok();

            let mime = match ext.as_str() {
                "mp3"         => "audio/mpeg",
                "wav"         => "audio/wav",
                "ogg" | "oga" => "audio/ogg",
                "flac"        => "audio/flac",
                "m4a" | "aac" => "audio/aac",
                "mid" | "midi"=> "audio/midi",
                _             => "audio/mpeg",
            };
            let b64 = format!("data:{};base64,{}", mime, base64_encode(&buf));
            return Ok(FilePreview {
                is_image: false,
                is_video: false,
                is_audio: true,
                is_text: false,
                data_base64: Some(b64),
                text_content: None,
                mime_type: mime.to_string(),
                file_size: total_size,
            });
        }

        // 4. TEXT & CODE PREVIEW
        let read_limit = total_size.min(512 * 1024) as usize; // first 512 KB of text
        let mut buf = vec![0u8; read_limit];
        f.read_exact(&mut buf).ok();

        if text_exts.contains(&ext.as_str()) {
            let text = String::from_utf8_lossy(&buf).to_string();
            return Ok(FilePreview {
                is_image: false,
                is_video: false,
                is_audio: false,
                is_text: true,
                data_base64: None,
                text_content: Some(text),
                mime_type: format!("text/{}", if ext.is_empty() { "plain" } else { &ext }),
                file_size: total_size,
            });
        }

        // 5. CONTENT-BASED TEXT HEURISTIC FALLBACK
        if !buf.is_empty() {
            let sample_len = buf.len().min(4096);
            let sample = &buf[..sample_len];
            let null_count = sample.iter().filter(|&&b| b == 0).count();
            let printable_count = sample.iter().filter(|&&b| {
                b == b'\t' || b == b'\n' || b == b'\r' || (b >= 32 && b <= 126) || b >= 128
            }).count();

            // If zero or near-zero null bytes and high ratio of printable characters
            if null_count == 0 && (printable_count as f32 / sample_len as f32) > 0.85 {
                let text = String::from_utf8_lossy(&buf).to_string();
                return Ok(FilePreview {
                    is_image: false,
                    is_video: false,
                    is_audio: false,
                    is_text: true,
                    data_base64: None,
                    text_content: Some(text),
                    mime_type: "text/plain".into(),
                    file_size: total_size,
                });
            }
        }

        Ok(FilePreview {
            is_image: false,
            is_video: false,
            is_audio: false,
            is_text: false,
            data_base64: None,
            text_content: None,
            mime_type: "application/octet-stream".into(),
            file_size: total_size,
        })
    }

    /// Selectively export chosen carved files to a target directory
    #[tauri::command]
    pub fn export_selected_artifacts(file_ids: Vec<String>, dest_dir: String, session_id: Option<String>) -> Result<usize> {
        use std::fs;
        use std::path::Path;
        let target_dir = Path::new(&dest_dir);
        fs::create_dir_all(target_dir)?;

        let sessions = SESSIONS.lock().unwrap();
        let mut count = 0;

        if let Some(ref sid) = session_id {
            if let Some(session) = sessions.get(sid) {
                for file in &session.results {
                    if file_ids.contains(&file.id) {
                        if let Some(filename) = file.path.file_name() {
                            let dest = target_dir.join(filename);
                            if fs::copy(&file.path, &dest).is_ok() {
                                let _ = crate::forensics::record_export(&file.id, dest);
                                count += 1;
                            }
                        }
                    }
                }
                return Ok(count);
            }
        }

        // Fallback: search across all active sessions
        for session in sessions.values() {
            for file in &session.results {
                if file_ids.contains(&file.id) {
                    if let Some(filename) = file.path.file_name() {
                        let dest = target_dir.join(filename);
                        if fs::copy(&file.path, &dest).is_ok() {
                            let _ = crate::forensics::record_export(&file.id, dest);
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    /// Return statistics on the signature database and supported extension universe (420+ formats)
    #[tauri::command]
    pub fn get_signature_catalog() -> signatures::SignatureCatalogStats {
        signatures::get_catalog_stats()
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARSET[(triple >> 18) & 0x3F] as char);
        out.push(CHARSET[(triple >> 12) & 0x3F] as char);
        if chunk.len() > 1 {
            out.push(CHARSET[(triple >> 6) & 0x3F] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARSET[triple & 0x3F] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HexChunk {
    pub offset:     u64,
    pub bytes:      Vec<u8>,
    pub total_size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FilePreview {
    pub is_image:     bool,
    pub is_video:     bool,
    pub is_audio:     bool,
    pub is_text:      bool,
    pub data_base64:  Option<String>,
    pub text_content: Option<String>,
    pub mime_type:    String,
    pub file_size:    u64,
}


// ── Core carve logic (runs in worker thread) ─────────────────────────────────

fn run_carve_session(
    app:     AppHandle,
    req:     CarveRequest,
    cancel:  Arc<AtomicBool>,
    sid:     SessionId,
) {
    let sigs_all  = all_signatures();
    let sigs: Vec<_> = if req.enabled_exts.is_empty() {
        sigs_all
    } else {
        sigs_all.into_iter()
            .filter(|s| req.enabled_exts.contains(&s.extension.to_string()))
            .collect()
    };

    let output_dir = PathBuf::from(&req.output_dir);
    fs::create_dir_all(&output_dir).ok();

    // — Concurrent Scan & Progressive Extraction Pipeline —
    let sid_clone  = sid.clone();
    let app_clone  = app.clone();
    let cancel_ref = Arc::clone(&cancel);

    let on_progress = Box::new(move |scanned: u64, total: u64| {
        let pct = if total > 0 { ((scanned as f64 / total as f64) * 100.0) as u8 } else { 0 };
        let files_found = SESSIONS.lock().unwrap()
            .get(&sid_clone).map(|s| s.results.len()).unwrap_or(0);
        let _ = app_clone.emit("carve_progress", CarveProgress {
            session_id:    sid_clone.clone(),
            bytes_scanned: scanned,
            total_bytes:   total,
            percent:       pct,
            files_found,
        });
    });

    let (hit_tx, hit_rx) = std::sync::mpsc::channel::<Option<crate::carver::scanner::HitEvent>>();
    let cancel_extractor = Arc::clone(&cancel);
    let app_extractor = app.clone();
    let sid_extractor = sid.clone();
    let image_path_extractor = req.image_path.clone();
    let output_dir_extractor = output_dir.clone();
    let sigs_extractor = sigs.clone();

    // Dedicated concurrent real-time extractor worker
    let extractor_handle = std::thread::spawn(move || {
        while let Ok(maybe_hit) = hit_rx.recv() {
            let hit = match maybe_hit {
                Some(h) => h,
                None => break, // EOF / scan finished
            };

            if cancel_extractor.load(Ordering::Relaxed) {
                break;
            }

            let sig = match sigs_extractor.get(hit.sig_idx) {
                Some(s) => s,
                None => continue,
            };

            match extractor::extract_file(&image_path_extractor, &hit, sig, &output_dir_extractor) {
                Ok(mut carved) => {
                    // Fragment reconstruction for small truncated files
                    if carved.truncated && carved.size <= 2 * 1024 * 1024 && carved.size >= 4096 {
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .read(true)
                            .open(crate::carver::scanner::normalise_path(&image_path_extractor)) {
                            use std::io::{Seek, SeekFrom, Read};
                            f.seek(SeekFrom::Start(hit.offset)).ok();
                            let mut partial = vec![0u8; carved.size];
                            f.read_exact(&mut partial).ok();

                            if let Some(res) = fragment::try_reconstruct(
                                &image_path_extractor, &partial, sig, hit.offset,
                            ) {
                                // Write reassembled file
                                if std::fs::write(&carved.path, &res.assembled).is_ok() {
                                    carved.size                = res.assembled.len();
                                    carved.truncated           = false;
                                    carved.reconstructed       = true;
                                    carved.fragment_count      = 2;
                                    carved.fragment_offsets    = Some(vec![hit.offset, res.frag_offset]);
                                    carved.fragment_gap_bytes  = Some(res.gap_bytes);
                                    carved.kl_divergence       = Some(res.kl_divergence);
                                    carved.confidence          = (carved.confidence + 0.15).min(1.0);
                                    carved.confidence_label    = "High (Bi-Fragment Stitched)".into();
                                }
                            }
                        }
                    }

                    // Auto-classify and extract structural metadata from header (up to 64 KB)
                    if let Ok(mut f_class) = std::fs::File::open(&carved.path) {
                        use std::io::Read;
                        let mut header_buf = vec![0u8; 64 * 1024];
                        if let Ok(n) = f_class.read(&mut header_buf) {
                            header_buf.truncate(n);
                            let classification = classifier::classify(&carved, &header_buf);
                            carved.metadata = classification.metadata;
                        }
                    }

                    // Append to session FIRST so files_found in on_progress reflects immediately
                    if let Some(s) = SESSIONS.lock().unwrap().get_mut(&sid_extractor) {
                        s.results.push(carved.clone());
                    }

                    // Emit to UI immediately in real time
                    let _ = app_extractor.emit("carve_file_found", carved);
                }
                Err(e) => {
                    log::warn!("extract error at offset {}: {}", hit.offset, e);
                }
            }
        }
    });

    let hit_tx_arc = Arc::new(std::sync::Mutex::new(hit_tx));
    let hit_tx_cb = Arc::clone(&hit_tx_arc);
    let on_hit: Option<crate::carver::scanner::HitFn> = Some(Arc::new(move |hit| {
        let _ = hit_tx_cb.lock().unwrap().send(Some(hit));
    }));

    let scan_res = scanner::scan_image_streaming(
        &req.image_path,
        &sigs,
        Arc::clone(&cancel_ref),
        on_progress,
        on_hit,
    );

    // Send Finish signal to extractor
    let _ = hit_tx_arc.lock().unwrap().send(None);

    // Wait for extractor worker to drain any remaining items
    let _ = extractor_handle.join();

    if let Err(e) = scan_res {
        let _ = app.emit("carve_error", format!("{}", e));
        return;
    }

    // Mark session done
    if let Some(s) = SESSIONS.lock().unwrap().get_mut(&sid) {
        s.finished = true;
        let count = s.results.len();
        log_event(AuditOperation::Scan {
            image:        req.image_path.clone(),
            files_found:  count,
            output_dir:   req.output_dir.clone(),
        });
        let _ = app.emit("carve_complete", serde_json::json!({
            "session_id": sid,
            "files_found": count,
        }));
    }
}
