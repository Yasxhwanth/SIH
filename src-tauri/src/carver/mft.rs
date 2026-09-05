// carver/mft.rs — Zero-Copy NTFS $MFT Parser & Timestomp Anomaly Detector
//
// Forensics standard:
//  - SANS FOR508: "Advanced Digital Forensics, Incident Response, and Threat Hunting"
//  - Carrier (2005): "File System Forensic Analysis" (Addison-Wesley)
//
// Capabilities:
//  1. Parses NTFS Master File Table 1024-byte File Record Segments (FRS).
//  2. Decodes $STANDARD_INFORMATION (0x10) and $FILE_NAME (0x30) attributes.
//  3. Detects Anti-Forensic Timestomping: Compares $SI vs $FN timestamps.
//     Because userland APIs only manipulate $SI, timestomp tools leave $FN unchanged.
//  4. Recovers deleted files ($MFT record flags: in_use = false).

use std::fs::File;
use std::io::Read;
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacbTimestamps {
    pub created:      String,
    pub modified:     String,
    pub mft_altered:  String,
    pub accessed:     String,
    pub created_raw:  u64,
    pub modified_raw: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestompAlert {
    pub severity:           String,
    pub description:        String,
    pub delta_seconds:      i64,
    pub subsecond_zeroed:   bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftRecord {
    pub record_number:      u64,
    pub record_offset:      u64,
    pub is_in_use:          bool,
    pub is_directory:       bool,
    pub filename:           String,
    pub parent_record:      u64,
    pub file_size:          u64,
    pub is_resident:        bool,
    pub resident_preview:   Option<String>,
    pub can_extract:        bool,
    pub standard_info:      Option<MacbTimestamps>,
    pub file_name_info:     Option<MacbTimestamps>,
    pub timestomp_detected: bool,
    pub timestomp_alert:    Option<TimestompAlert>,
}

/// Convert a 64-bit Windows FILETIME (100-ns intervals since Jan 1, 1601) to ISO-8601 string.
pub fn filetime_to_rfc3339(ft: u64) -> String {
    if ft == 0 { return "1601-01-01T00:00:00Z".to_string(); }
    // Windows epoch (1601-01-01) to Unix epoch (1970-01-01) is 11,644,473,600 seconds
    const WINDOWS_TICK: u64 = 10_000_000;
    const SEC_TO_UNIX:  u64 = 11_644_473_600;

    let total_secs = ft / WINDOWS_TICK;
    let subsec_nanos = ((ft % WINDOWS_TICK) * 100) as u32;

    if total_secs < SEC_TO_UNIX {
        return "1601-01-01T00:00:00Z".to_string();
    }

    let unix_secs = (total_secs - SEC_TO_UNIX) as i64;
    DateTime::from_timestamp(unix_secs, subsec_nanos)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Parse a single 1024-byte NTFS MFT Record at offset 0.
#[allow(dead_code)]
pub fn parse_mft_record(record: &[u8], record_idx: u64) -> Option<MftRecord> {
    parse_mft_record_at(record, record_idx, 0)
}

/// Parse a single 1024-byte NTFS MFT Record with known absolute offset.
pub fn parse_mft_record_at(record: &[u8], record_idx: u64, record_offset: u64) -> Option<MftRecord> {
    if record.len() < 1024 { return None; }
    // Magic: "FILE"
    if &record[0..4] != b"FILE" { return None; }

    let update_seq_offset = u16::from_le_bytes([record[4], record[5]]) as usize;
    let update_seq_size   = u16::from_le_bytes([record[6], record[7]]) as usize;
    let first_attr_offset = u16::from_le_bytes([record[20], record[21]]) as usize;
    let flags             = u16::from_le_bytes([record[22], record[23]]);

    let is_in_use    = (flags & 0x01) != 0;
    let is_directory = (flags & 0x02) != 0;

    // Apply NTFS Fixup array if valid
    let mut data = record.to_vec();
    if update_seq_offset + update_seq_size * 2 <= data.len() && update_seq_size >= 2 {
        let fixup_val = [data[update_seq_offset], data[update_seq_offset + 1]];
        for sec in 1..update_seq_size {
            let sector_end = sec * 512 - 2;
            let fixup_entry = update_seq_offset + sec * 2;
            if sector_end + 1 < data.len() && fixup_entry + 1 < data.len() {
                if data[sector_end] == fixup_val[0] && data[sector_end + 1] == fixup_val[1] {
                    data[sector_end]     = data[fixup_entry];
                    data[sector_end + 1] = data[fixup_entry + 1];
                }
            }
        }
    }

    let mut attr_offset = first_attr_offset;
    let mut std_info: Option<MacbTimestamps> = None;
    let mut fn_info:  Option<MacbTimestamps> = None;
    let mut filename = format!("FRS_{:06}", record_idx);
    let mut parent_record = 0u64;
    let mut file_size = 0u64;
    let mut is_resident = false;
    let mut resident_preview: Option<String> = None;
    let mut can_extract = false;

    while attr_offset + 8 <= data.len() {
        let attr_type = u32::from_le_bytes(data[attr_offset..attr_offset+4].try_into().unwrap());
        if attr_type == 0xFFFF_FFFF || attr_type == 0 { break; } // End marker

        let attr_len = u32::from_le_bytes(data[attr_offset+4..attr_offset+8].try_into().unwrap()) as usize;
        if attr_len == 0 || attr_offset + attr_len > data.len() { break; }

        let non_resident = data[attr_offset + 8] != 0;

        match attr_type {
            // $STANDARD_INFORMATION (0x10)
            0x10 if !non_resident => {
                let content_off = u16::from_le_bytes(data[attr_offset+20..attr_offset+22].try_into().unwrap()) as usize;
                let c_start = attr_offset + content_off;
                if c_start + 32 <= data.len() {
                    let cr = u64::from_le_bytes(data[c_start..c_start+8].try_into().unwrap());
                    let mo = u64::from_le_bytes(data[c_start+8..c_start+16].try_into().unwrap());
                    let mf = u64::from_le_bytes(data[c_start+16..c_start+24].try_into().unwrap());
                    let ac = u64::from_le_bytes(data[c_start+24..c_start+32].try_into().unwrap());

                    std_info = Some(MacbTimestamps {
                        created:      filetime_to_rfc3339(cr),
                        modified:     filetime_to_rfc3339(mo),
                        mft_altered:  filetime_to_rfc3339(mf),
                        accessed:     filetime_to_rfc3339(ac),
                        created_raw:  cr,
                        modified_raw: mo,
                    });
                }
            }

            // $FILE_NAME (0x30)
            0x30 if !non_resident => {
                let content_off = u16::from_le_bytes(data[attr_offset+20..attr_offset+22].try_into().unwrap()) as usize;
                let c_start = attr_offset + content_off;
                if c_start + 66 <= data.len() {
                    parent_record = u64::from_le_bytes(data[c_start..c_start+8].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
                    let cr = u64::from_le_bytes(data[c_start+8..c_start+16].try_into().unwrap());
                    let mo = u64::from_le_bytes(data[c_start+16..c_start+24].try_into().unwrap());
                    let mf = u64::from_le_bytes(data[c_start+24..c_start+32].try_into().unwrap());
                    let ac = u64::from_le_bytes(data[c_start+32..c_start+40].try_into().unwrap());
                    let fn_len = data[c_start + 64] as usize;
                    let namespace = data[c_start + 65];

                    let fn_start = c_start + 66;
                    if fn_start + fn_len * 2 <= data.len() {
                        let utf16_chars: Vec<u16> = (0..fn_len).map(|i| {
                            u16::from_le_bytes([data[fn_start + i*2], data[fn_start + i*2 + 1]])
                        }).collect();
                        let decoded = String::from_utf16_lossy(&utf16_chars);
                        // Win32 / POSIX namespace preferred over DOS 8.3
                        if namespace != 2 || filename.starts_with("FRS_") {
                            filename = decoded;
                        }
                    }

                    if fn_info.is_none() || namespace != 2 {
                        fn_info = Some(MacbTimestamps {
                            created:      filetime_to_rfc3339(cr),
                            modified:     filetime_to_rfc3339(mo),
                            mft_altered:  filetime_to_rfc3339(mf),
                            accessed:     filetime_to_rfc3339(ac),
                            created_raw:  cr,
                            modified_raw: mo,
                        });
                    }
                }
            }

            // $DATA (0x80)
            0x80 => {
                if !non_resident {
                    is_resident = true;
                    can_extract = true;
                    let c_size = u32::from_le_bytes(data[attr_offset+16..attr_offset+20].try_into().unwrap_or([0; 4])) as usize;
                    let c_off = u16::from_le_bytes(data[attr_offset+20..attr_offset+22].try_into().unwrap_or([0; 2])) as usize;
                    file_size = c_size as u64;
                    if attr_offset + c_off + c_size <= data.len() {
                        let res_bytes = &data[attr_offset + c_off .. attr_offset + c_off + c_size];
                        let preview: String = res_bytes.iter()
                            .take(64)
                            .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
                            .collect();
                        resident_preview = Some(preview);
                    }
                } else if attr_offset + 56 <= data.len() {
                    is_resident = false;
                    can_extract = true;
                    let real_size = u64::from_le_bytes(data[attr_offset+48..attr_offset+56].try_into().unwrap_or([0; 8]));
                    file_size = real_size;
                }
            }

            _ => {}
        }

        attr_offset += attr_len;
    }

    let timestomp_alert = detect_timestomp(&std_info, &fn_info);
    let timestomp_detected = timestomp_alert.is_some();

    Some(MftRecord {
        record_number: record_idx,
        record_offset,
        is_in_use,
        is_directory,
        filename,
        parent_record,
        file_size,
        is_resident,
        resident_preview,
        can_extract,
        standard_info: std_info,
        file_name_info: fn_info,
        timestomp_detected,
        timestomp_alert,
    })
}

/// Detect Anti-Forensics: Compare $STANDARD_INFORMATION against $FILE_NAME timestamps.
pub fn detect_timestomp(
    std_info: &Option<MacbTimestamps>,
    fn_info:  &Option<MacbTimestamps>,
) -> Option<TimestompAlert> {
    let (si, fi) = (std_info.as_ref()?, fn_info.as_ref()?);

    const TICKS_PER_SEC: u64 = 10_000_000;

    // Condition 1: $SI modified earlier than $FN created by > 2 seconds
    if si.modified_raw + 2 * TICKS_PER_SEC < fi.created_raw {
        let delta_secs = (fi.created_raw as i64 - si.modified_raw as i64) / TICKS_PER_SEC as i64;
        return Some(TimestompAlert {
            severity: "CRITICAL".to_string(),
            description: format!(
                "Anti-Forensic Timestomp: $STANDARD_INFORMATION modified date ({}) precedes $FILE_NAME creation date ({}) by {} seconds.",
                si.modified, fi.created, delta_secs
            ),
            delta_seconds: delta_secs,
            subsecond_zeroed: (si.modified_raw % TICKS_PER_SEC) == 0,
        });
    }

    // Condition 2: $SI created earlier than $FN created by > 2 seconds
    if si.created_raw + 2 * TICKS_PER_SEC < fi.created_raw {
        let delta_secs = (fi.created_raw as i64 - si.created_raw as i64) / TICKS_PER_SEC as i64;
        return Some(TimestompAlert {
            severity: "CRITICAL".to_string(),
            description: format!(
                "Anti-Forensic Timestomp: $STANDARD_INFORMATION creation date ({}) rolled back before $FILE_NAME creation date ({}) by {} seconds.",
                si.created, fi.created, delta_secs
            ),
            delta_seconds: delta_secs,
            subsecond_zeroed: (si.created_raw % TICKS_PER_SEC) == 0,
        });
    }

    // Condition 3: Subsecond nanoseconds completely zeroed out (common in naive timestomp scripts)
    if (si.modified_raw % TICKS_PER_SEC) == 0 && (fi.modified_raw % TICKS_PER_SEC) != 0 {
        return Some(TimestompAlert {
            severity: "WARNING".to_string(),
            description: "Sub-second zeroing detected in $STANDARD_INFORMATION while $FILE_NAME maintains microsecond precision (Anti-forensic timestamp wiper indicator).".to_string(),
            delta_seconds: 0,
            subsecond_zeroed: true,
        });
    }

    None
}

/// Scan an entire disk image or MFT dump for NTFS File Record Segments with real-time record streaming.
pub fn scan_image_mft_streaming<F>(image_path: &str, max_records: usize, mut on_record: F) -> Result<Vec<MftRecord>>
where
    F: FnMut(&MftRecord),
{
    use std::io::{Seek, SeekFrom};
    let norm = crate::carver::scanner::normalise_path(image_path);
    let mut file = File::open(&norm).map_err(AppError::Io)?;

    let mut buf = vec![0u8; 1024];
    let mut records = Vec::new();
    let mut current_offset = 0u64;

    while records.len() < max_records {
        if file.seek(SeekFrom::Start(current_offset)).is_err() { break; }
        match file.read_exact(&mut buf) {
            Ok(_) => {
                if &buf[0..4] == b"FILE" {
                    if let Some(rec) = parse_mft_record_at(&buf, records.len() as u64, current_offset) {
                        on_record(&rec);
                        records.push(rec);
                        current_offset += 1024;
                        continue;
                    }
                }
                current_offset += 512;
            }
            Err(_) => break,
        }
    }

    Ok(records)
}

/// Scan an entire disk image or MFT dump for NTFS File Record Segments.
#[allow(dead_code)]
pub fn scan_image_mft(image_path: &str, max_records: usize) -> Result<Vec<MftRecord>> {
    scan_image_mft_streaming(image_path, max_records, |_| {})
}

/// Extract a file from an NTFS MFT record (resident or non-resident data run).
pub fn extract_mft_record_file(
    image_path: &str,
    record_offset: u64,
    output_dir: &str,
) -> Result<String> {
    use std::io::{Seek, SeekFrom, Read};
    use sha2::{Sha256, Digest};

    let norm = crate::carver::scanner::normalise_path(image_path);
    let mut file = std::fs::File::open(&norm).map_err(AppError::Io)?;
    file.seek(SeekFrom::Start(record_offset)).map_err(AppError::Io)?;

    let mut buf = vec![0u8; 1024];
    file.read_exact(&mut buf).map_err(AppError::Io)?;

    let rec = parse_mft_record_at(&buf, 0, record_offset)
        .ok_or_else(|| AppError::CarveError("Invalid MFT record at specified offset".into()))?;

    // Find 0x80 attribute in buf
    let mut attr_offset = u16::from_le_bytes([buf[20], buf[21]]) as usize;
    let mut file_bytes = Vec::new();

    while attr_offset + 8 <= buf.len() {
        let attr_type = u32::from_le_bytes(buf[attr_offset..attr_offset+4].try_into().unwrap_or([0; 4]));
        if attr_type == 0xFFFF_FFFF || attr_type == 0 { break; }
        let attr_len = u32::from_le_bytes(buf[attr_offset+4..attr_offset+8].try_into().unwrap_or([0; 4])) as usize;
        if attr_len == 0 || attr_offset + attr_len > buf.len() { break; }

        let non_resident = buf[attr_offset + 8] != 0;
        if attr_type == 0x80 {
            if !non_resident {
                let c_size = u32::from_le_bytes(buf[attr_offset+16..attr_offset+20].try_into().unwrap_or([0; 4])) as usize;
                let c_off = u16::from_le_bytes(buf[attr_offset+20..attr_offset+22].try_into().unwrap_or([0; 2])) as usize;
                if attr_offset + c_off + c_size <= buf.len() {
                    file_bytes = buf[attr_offset + c_off .. attr_offset + c_off + c_size].to_vec();
                }
            } else if attr_offset + 56 <= buf.len() {
                let real_size = u64::from_le_bytes(buf[attr_offset+48..attr_offset+56].try_into().unwrap_or([0; 8])) as usize;
                let run_off = u16::from_le_bytes(buf[attr_offset+32..attr_offset+34].try_into().unwrap_or([0; 2])) as usize;
                let mut run_pos = attr_offset + run_off;
                let mut current_lcn = 0i64;

                while run_pos < attr_offset + attr_len && buf[run_pos] != 0 {
                    let b = buf[run_pos];
                    let len_len = (b & 0x0F) as usize;
                    let off_len = ((b >> 4) & 0x0F) as usize;
                    run_pos += 1;

                    if run_pos + len_len + off_len > buf.len() { break; }

                    let mut cl_count = 0u64;
                    for i in 0..len_len {
                        cl_count |= (buf[run_pos + i] as u64) << (i * 8);
                    }
                    run_pos += len_len;

                    if off_len > 0 {
                        let mut lcn_delta = 0i64;
                        for i in 0..off_len {
                            lcn_delta |= (buf[run_pos + i] as i64) << (i * 8);
                        }
                        if (buf[run_pos + off_len - 1] & 0x80) != 0 {
                            for i in off_len..8 {
                                lcn_delta |= (0xFF as i64) << (i * 8);
                            }
                        }
                        current_lcn += lcn_delta;
                        run_pos += off_len;

                        if current_lcn > 0 {
                            let cluster_byte_offset = (current_lcn as u64) * 4096;
                            if let Ok(_) = file.seek(SeekFrom::Start(cluster_byte_offset)) {
                                let read_target = (cl_count * 4096) as usize;
                                let mut cl_buf = vec![0u8; read_target];
                                if let Ok(n) = file.read(&mut cl_buf) {
                                    file_bytes.extend_from_slice(&cl_buf[..n]);
                                }
                            }
                        }
                    } else {
                        file_bytes.resize(file_bytes.len() + (cl_count * 4096) as usize, 0);
                    }

                    if file_bytes.len() >= real_size {
                        file_bytes.truncate(real_size);
                        break;
                    }
                }
            }
            break;
        }
        attr_offset += attr_len;
    }

    if file_bytes.is_empty() && rec.file_size > 0 {
        return Err(AppError::CarveError("No recoverable data stream present in MFT record".into()));
    }

    let out_dir = std::path::PathBuf::from(output_dir);
    std::fs::create_dir_all(&out_dir).map_err(AppError::Io)?;
    let clean_name = rec.filename.replace(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_', "_");
    let safe_name = if clean_name.is_empty() { format!("mft_rec_{}.bin", rec.record_number) } else { clean_name };
    let out_path = out_dir.join(&safe_name);

    std::fs::write(&out_path, &file_bytes).map_err(AppError::Io)?;

    let mut hasher = Sha256::new();
    hasher.update(&file_bytes);
    let hash = hex::encode(hasher.finalize());

    crate::forensics::record_extraction(
        &hash[..16],
        &format!("MFT Inode #{} (Offset 0x{:X})", rec.record_number, record_offset),
        record_offset,
        out_path.clone(),
        &hash,
    );

    Ok(out_path.to_string_lossy().to_string())
}

pub mod cmd {
    use super::*;

    #[tauri::command]
    pub fn scan_filesystem_mft(
        app: tauri::AppHandle,
        image_path: String,
        max_records: Option<usize>,
    ) -> Result<Vec<MftRecord>> {
        use tauri::Emitter;
        let limit = max_records.unwrap_or(500);
        scan_image_mft_streaming(&image_path, limit, |rec| {
            let _ = app.emit("mft_record_found", rec);
        })
    }

    #[tauri::command]
    pub fn extract_mft_record_file(
        image_path: String,
        record_offset: u64,
        output_dir: Option<String>,
    ) -> Result<String> {
        let out_dir = output_dir.unwrap_or_else(|| "recovered_evidence".into());
        super::extract_mft_record_file(&image_path, record_offset, &out_dir)
    }
}
