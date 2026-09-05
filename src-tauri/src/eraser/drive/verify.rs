// eraser/drive/verify.rs — Post-wipe read-back verification with residual entropy analysis
//
// After a wipe completes, re-reads every sector and checks that all bytes
// match the expected pattern for the LAST pass of the selected standard.
// Computes residual Shannon entropy to detect latent flash remnants.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::error::Result;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct VerifyResult {
    pub sectors_checked:      u64,
    pub mismatches:           u64,
    pub pass:                 bool,
    pub first_bad_sector:     Option<u64>,
    pub max_residual_entropy: f64,
}

/// Expected last-pass pattern per standard.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum ExpectedPattern {
    Zero,
    Random,   // Confirm readable with expected non-zero entropy
    Ones,
    Byte(u8),
}

fn query_verify_size(f: &File, norm: &str) -> u64 {
    if let Ok(meta) = f.metadata() {
        if meta.is_file() && meta.len() > 0 {
            return meta.len();
        }
    }

    #[cfg(windows)]
    {
        use std::mem;
        use std::os::windows::io::AsRawHandle;
        use winapi::um::ioapiset::DeviceIoControl;
        use winapi::um::winioctl::{IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, DISK_GEOMETRY_EX};

        let handle = f.as_raw_handle() as *mut winapi::ctypes::c_void;
        let mut geo: DISK_GEOMETRY_EX = unsafe { mem::zeroed() };
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
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
            if size > 0 { return size as u64; }
        }
    }

    let mut f2 = match File::open(norm) {
        Ok(file) => file,
        Err(_) => return 0,
    };
    f2.seek(SeekFrom::End(0)).unwrap_or(0)
}

pub fn verify_wipe(path: &str, pattern: ExpectedPattern) -> Result<VerifyResult> {
    let norm = crate::carver::scanner::normalise_path(path);
    let mut f = File::open(&norm)?;
    let total_bytes = query_verify_size(&f, &norm);
    f.seek(SeekFrom::Start(0))?;

    const SECTOR: usize = 512;
    let mut buf = vec![0u8; SECTOR * 1024]; // 512 KB read blocks
    let mut sectors_checked: u64 = 0;
    let mut mismatches:      u64 = 0;
    let mut first_bad: Option<u64> = None;
    let mut max_entropy: f64 = 0.0;

    while sectors_checked * (SECTOR as u64) < total_bytes {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }

        match pattern {
            ExpectedPattern::Random => {
                let ent = crate::carver::fragment::entropy(&buf[..n]);
                if ent > max_entropy { max_entropy = ent; }
                let all_zero = buf[..n].iter().all(|&b| b == 0);
                if all_zero {
                    mismatches += 1;
                    if first_bad.is_none() { first_bad = Some(sectors_checked); }
                }
            }
            ExpectedPattern::Zero => {
                for (chunk_idx, chunk) in buf[..n].chunks(SECTOR).enumerate() {
                    let ent = crate::carver::fragment::entropy(chunk);
                    if ent > max_entropy { max_entropy = ent; }
                    let mismatch = chunk.iter().any(|&b| b != 0x00);
                    if mismatch {
                        mismatches += 1;
                        if first_bad.is_none() {
                            first_bad = Some(sectors_checked + chunk_idx as u64);
                        }
                    }
                }
            }
            ExpectedPattern::Ones => {
                for (chunk_idx, chunk) in buf[..n].chunks(SECTOR).enumerate() {
                    let mismatch = chunk.iter().any(|&b| b != 0xFF);
                    if mismatch {
                        mismatches += 1;
                        if first_bad.is_none() {
                            first_bad = Some(sectors_checked + chunk_idx as u64);
                        }
                    }
                }
            }
            ExpectedPattern::Byte(expected) => {
                for (chunk_idx, chunk) in buf[..n].chunks(SECTOR).enumerate() {
                    let mismatch = chunk.iter().any(|&b| b != expected);
                    if mismatch {
                        mismatches += 1;
                        if first_bad.is_none() {
                            first_bad = Some(sectors_checked + chunk_idx as u64);
                        }
                    }
                }
            }
        }

        sectors_checked += (n / SECTOR) as u64;
    }

    Ok(VerifyResult {
        sectors_checked,
        mismatches,
        pass: mismatches == 0,
        first_bad_sector: first_bad,
        max_residual_entropy: max_entropy,
    })
}
