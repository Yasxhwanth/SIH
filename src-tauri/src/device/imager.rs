// device/imager.rs — Forensic Bit-Stream Disk Imaging Engine
//
// Creates an exact physical sector-by-sector copy (.raw / .dd) of any storage
// volume or USB drive with real-time SHA-256 integrity verification.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::error::Result;
use crate::carver::scanner::normalise_path;

lazy_static::lazy_static! {
    static ref IMAGER_CANCEL: Mutex<HashMap<String, Arc<AtomicBool>>> =
        Mutex::new(HashMap::new());
}

#[derive(Serialize, Clone)]
pub struct ImageProgress {
    pub job_id:        String,
    pub bytes_written: u64,
    pub total_bytes:   u64,
    pub percent:       u8,
    pub speed_mb:      f32,
    pub current_lba:   u64,
    pub bad_sectors:   u64,
    pub retries:       u64,
}

#[derive(Serialize, Clone)]
pub struct ImageResult {
    pub job_id:         String,
    pub source:         String,
    pub destination:    String,
    pub total_bytes:    u64,
    pub sha256:         String,
    pub elapsed_secs:   f64,
    pub success:        bool,
    pub bad_sectors:    u64,
    pub fault_map_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadSectorRecord {
    pub lba:   u64,
    pub count: u64,
    pub error: String,
}

fn default_true() -> bool { true }

#[derive(Deserialize)]
pub struct ImageRequest {
    pub job_id:         String,
    pub source_path:    String,
    #[serde(alias = "output_path")]
    pub dest_path:      String,
    #[serde(alias = "calc_sha256", default = "default_true")]
    pub compute_sha256: bool,
}

pub mod cmd {
    use super::*;

    #[tauri::command]
    pub fn start_bitstream_image(app: AppHandle, req: ImageRequest) -> Result<String> {
        let cancel = Arc::new(AtomicBool::new(false));
        IMAGER_CANCEL.lock().unwrap()
            .insert(req.job_id.clone(), Arc::clone(&cancel));

        let job_id = req.job_id.clone();
        std::thread::spawn(move || {
            run_imager_job(app, req, cancel);
        });

        Ok(job_id)
    }

    #[tauri::command]
    pub fn cancel_bitstream_image(job_id: String) -> Result<()> {
        if let Some(cancel) = IMAGER_CANCEL.lock().unwrap().get(&job_id) {
            cancel.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

fn run_imager_job(app: AppHandle, req: ImageRequest, cancel: Arc<AtomicBool>) {
    let norm_source = normalise_path(&req.source_path);
    let start_time = std::time::Instant::now();

    let mut src_opts = OpenOptions::new();
    src_opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        src_opts.custom_flags(0x0800_0000); // FILE_FLAG_SEQUENTIAL_SCAN
    }

    let mut src = match src_opts.open(&norm_source) {
        Ok(f) => f,
        Err(e) => {
            let _ = app.emit("image_error", format!("Failed to open source medium: {}", e));
            return;
        }
    };

    let total_bytes = match get_media_size(&src, &norm_source) {
        Ok(sz) => sz,
        Err(e) => {
            let _ = app.emit("image_error", format!("Failed to determine media capacity: {}", e));
            return;
        }
    };

    let mut dst = match File::create(&req.dest_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = app.emit("image_error", format!("Failed to create destination image: {}", e));
            return;
        }
    };

    const CHUNK: usize = 4 * 1024 * 1024; // 4 MB transfer blocks
    let mut buf = vec![0u8; CHUNK];
    let mut hasher = Sha256::new();
    let mut bytes_written: u64 = 0;
    let mut last_sample = std::time::Instant::now();
    let mut last_bytes = 0u64;
    let mut bad_sectors: u64 = 0;
    let mut total_retries: u64 = 0;
    let mut fault_ledger: Vec<BadSectorRecord> = Vec::new();

    while bytes_written < total_bytes {
        if cancel.load(Ordering::Relaxed) {
            let _ = app.emit("image_error", "Bit-stream imaging cancelled by user.".to_string());
            return;
        }

        let to_read = (total_bytes - bytes_written).min(CHUNK as u64) as usize;
        let n = match src.read(&mut buf[..to_read]) {
            Ok(0) => break,
            Ok(bytes) => bytes,
            Err(e) => {
                // Step down to individual 512-byte LBA sectors with retry logic
                let mut chunk_actual = 0usize;
                let sectors_in_chunk = (to_read + 511) / 512;
                for s_idx in 0..sectors_in_chunk {
                    if cancel.load(Ordering::Relaxed) {
                        let _ = app.emit("image_error", "Bit-stream imaging cancelled by user.".to_string());
                        return;
                    }
                    let sector_offset = bytes_written + (s_idx as u64 * 512);
                    let sector_bytes = ((total_bytes - sector_offset).min(512)) as usize;
                    if sector_bytes == 0 { break; }

                    let lba = sector_offset / 512;
                    let buf_start = s_idx * 512;
                    let buf_end = buf_start + sector_bytes;

                    let mut sector_ok = false;
                    for retry in 0..=2 {
                        if retry > 0 { total_retries += 1; }
                        if src.seek(SeekFrom::Start(sector_offset)).is_ok() {
                            if let Ok(m) = src.read(&mut buf[buf_start..buf_end]) {
                                if m == sector_bytes {
                                    sector_ok = true;
                                    break;
                                }
                            }
                        }
                    }

                    if !sector_ok {
                        bad_sectors += 1;
                        buf[buf_start..buf_end].fill(0x00);
                        fault_ledger.push(BadSectorRecord {
                            lba,
                            count: 1,
                            error: format!("Unreadable physical sector (zero-padded): {}", e),
                        });
                    }
                    chunk_actual += sector_bytes;
                }
                chunk_actual
            }
        };

        if let Err(e) = dst.write_all(&buf[..n]) {
            let _ = app.emit("image_error", format!("Destination image write error: {}", e));
            return;
        }

        if req.compute_sha256 {
            hasher.update(&buf[..n]);
        }

        bytes_written += n as u64;

        if last_sample.elapsed().as_millis() >= 400 {
            let elapsed_sec = last_sample.elapsed().as_secs_f32();
            let speed_mb = ((bytes_written - last_bytes) as f32 / 1_048_576.0) / elapsed_sec;
            let percent = if total_bytes > 0 {
                ((bytes_written as f64 / total_bytes as f64) * 100.0) as u8
            } else { 0 };

            let _ = app.emit("image_progress", ImageProgress {
                job_id:        req.job_id.clone(),
                bytes_written,
                total_bytes,
                percent,
                speed_mb,
                current_lba:   bytes_written / 512,
                bad_sectors,
                retries:       total_retries,
            });

            last_sample = std::time::Instant::now();
            last_bytes = bytes_written;
        }
    }

    let _ = dst.flush();
    let sha256 = if req.compute_sha256 {
        hex::encode(hasher.finalize())
    } else {
        "N/A".to_string()
    };

    let elapsed_secs = start_time.elapsed().as_secs_f64();

    let fault_map_path = if bad_sectors > 0 {
        let map_path = format!("{}.map", req.dest_path);
        let mut map_content = format!(
            "# ForensiX Fault-Tolerant Bitstream Fault Map\n# Source: {}\n# Destination: {}\n# Timestamp: {}\n# Total Bad Sectors: {}\n# Total Retries: {}\n# Format: LBA, SectorCount, Status\n\n",
            req.source_path, req.dest_path, chrono::Utc::now().to_rfc3339(), bad_sectors, total_retries
        );
        for b in &fault_ledger {
            map_content.push_str(&format!("{}, {}, BAD_SECTOR_ZERO_FILLED\n", b.lba, b.count));
        }
        let _ = std::fs::write(&map_path, map_content);
        Some(map_path)
    } else {
        None
    };

    let _ = app.emit("image_complete", ImageResult {
        job_id:         req.job_id,
        source:         req.source_path,
        destination:    req.dest_path,
        total_bytes:    bytes_written,
        sha256,
        elapsed_secs,
        success:        true,
        bad_sectors,
        fault_map_path,
    });
}

fn get_media_size(f: &File, norm: &str) -> std::io::Result<u64> {
    if let Ok(meta) = f.metadata() {
        if meta.is_file() && meta.len() > 0 {
            return Ok(meta.len());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use std::mem;
        use winapi::um::ioapiset::DeviceIoControl;
        use winapi::um::winioctl::{IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, DISK_GEOMETRY_EX};

        let handle = f.as_raw_handle();
        let mut geo: DISK_GEOMETRY_EX = unsafe { mem::zeroed() };
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle as *mut winapi::ctypes::c_void,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                std::ptr::null_mut(), 0,
                &mut geo as *mut _ as *mut _,
                mem::size_of::<DISK_GEOMETRY_EX>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 && returned >= 8 {
            let size_ptr = unsafe {
                let base = &geo as *const DISK_GEOMETRY_EX as *const u8;
                base.add(24) as *const i64
            };
            let size = unsafe { *size_ptr };
            if size > 0 { return Ok(size as u64); }
        }
    }
    let mut f2 = OpenOptions::new().read(true).open(norm)?;
    f2.seek(SeekFrom::End(0))
}
