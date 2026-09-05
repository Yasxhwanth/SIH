// carver/extractor.rs — File boundary detection and extraction
//
// Given a HitEvent, reads forward from the hit offset to determine the file
// boundary, then writes the extracted bytes to the output directory.

use std::io::{Read, Seek, SeekFrom, Write};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::carver::signatures::FileSignature;
use crate::carver::scanner::{HitEvent, normalise_path};
use crate::carver::confidence::{compute_confidence, ConfidenceLabel};
use crate::carver::validator::validate;
use crate::error::{AppError, Result};

/// A successfully extracted file with metadata.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CarvedFile {
    pub id:          String,   // hex of first 8 bytes of sha256
    pub path:        PathBuf,
    pub offset:      u64,
    pub size:        usize,
    pub extension:   &'static str,
    pub description: &'static str,
    pub category:    String,
    pub category_icon: &'static str,
    pub confidence:  f32,
    pub confidence_label: String,
    pub sha256:      String,
    pub truncated:   bool,     // hit max_size → likely fragment
    pub reconstructed: bool,   // assembled from fragments
    pub fragment_count: usize, // number of non-contiguous fragments
    pub fragment_offsets: Option<Vec<u64>>, // LBAs of stitched fragments
    pub fragment_gap_bytes: Option<u64>,    // gap distance jumped
    pub kl_divergence: Option<f64>,        // Kullback-Leibler continuity score
    pub entropy:     f64,      // Shannon entropy (0.00–8.00 bits/byte)
    pub metadata:    Vec<(String, String)>, // Key-value embedded structural metadata
}

/// Extract one file hit from the image into output_dir.
pub fn extract_file(
    image_path: &str,
    hit: &HitEvent,
    sig: &FileSignature,
    output_dir: &Path,
) -> Result<CarvedFile> {
    let norm = normalise_path(image_path);
    let mut f = std::fs::OpenOptions::new().read(true).open(&norm)?;

    // Sector-aligned seek & read logic (vital for Windows raw device handles \\.\D:, \\.\PhysicalDrive0)
    let sector_aligned_offset = (hit.offset / 512) * 512;
    let intra_offset = (hit.offset % 512) as usize;
    f.seek(SeekFrom::Start(sector_aligned_offset))?;

    // Cap initial probe size intelligently:
    // - For files with a footer window (PDF, JPEG, ZIP), read up to footer_window (max 16 MB)
    // - For other files, bound to 4 MB to prevent multi-hundred-MB memory spikes per candidate
    let probe_limit = if sig.footer.is_some() && sig.footer_window > 0 {
        sig.footer_window.min(16 * 1024 * 1024)
    } else {
        sig.max_size.min(4 * 1024 * 1024)
    };

    let aligned_alloc = ((probe_limit + intra_offset + 511) / 512) * 512;
    let mut raw_buf = vec![0u8; aligned_alloc];
    let n_read = read_fully(&mut f, &mut raw_buf)?;
    raw_buf.truncate(n_read);

    if raw_buf.len() <= intra_offset {
        return Err(AppError::CarveError(format!("Candidate at 0x{:X} beyond media boundary", hit.offset)));
    }
    let buf = raw_buf[intra_offset..].to_vec();

    // Determine actual end of file
    let (end_offset, truncated) = find_end(&buf, sig);
    let data = &buf[..end_offset];

    // Compute Shannon Entropy
    let entropy = crate::carver::fragment::entropy(data);

    // Minimum viable size check
    if data.len() < sig.magic.len() + 4 {
        return Err(AppError::CarveError(format!(
            "Rejected carved {} candidate at offset 0x{:X}: truncated payload ({} bytes)",
            sig.extension, hit.offset, data.len()
        )));
    }

    // Structural validation
    let structure_ok = validate(sig, data);

    // CRITICAL FORENSIC REQUIREMENT: Strictly discard failed validations!
    if sig.extra_validation.is_some() && !structure_ok {
        return Err(AppError::CarveError(format!(
            "Rejected carved {} candidate at offset 0x{:X}: failed structural validation",
            sig.extension, hit.offset
        )));
    }

    // Confidence scoring
    let has_footer = sig.footer.is_some() && end_offset < n_read;
    let confidence = compute_confidence(
        sig.confidence_base,
        has_footer,
        structure_ok,
        truncated,
        false, // overlap — extractor doesn't know yet, set by dedup pass
    );
    let label = ConfidenceLabel::from(confidence);

    // Write output file ONLY for validated artifacts
    let category_dir = output_dir.join(sig.category.as_str());
    fs::create_dir_all(&category_dir)?;
    let filename = format!("{:016x}.{}", hit.offset, sig.extension);
    let out_path = category_dir.join(&filename);

    let mut out = File::create(&out_path)?;
    out.write_all(data)?;

    // SHA-256 for evidential integrity
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = hex::encode(hasher.finalize());
    let id = sha256[..16].to_string();

    crate::forensics::record_extraction(
        &id,
        &format!("Sector LBA 0x{:016x}", hit.offset / 512),
        hit.offset,
        out_path.clone(),
        &sha256,
    );

    Ok(CarvedFile {
        id,
        path: out_path,
        offset: hit.offset,
        size: data.len(),
        extension: sig.extension,
        description: sig.description,
        category: sig.category.as_str().to_string(),
        category_icon: sig.category.icon(),
        confidence,
        confidence_label: label.to_string(),
        sha256,
        truncated,
        reconstructed: false,
        fragment_count: 1,
        fragment_offsets: Some(vec![hit.offset]),
        fragment_gap_bytes: None,
        kl_divergence: None,
        entropy,
        metadata: Vec::new(),
    })
}

/// Find the end of the file data in `buf` using format-aware parsing or heuristics.
/// Returns (end_byte_exclusive, was_truncated).
fn find_end(buf: &[u8], sig: &FileSignature) -> (usize, bool) {
    match sig.extension {
        "jpg" | "jpeg" => {
            if let Some(pos) = find_jpeg_boundary(buf, sig.footer_window) {
                return (pos, false);
            }
        }
        "png" => {
            if let Some(pos) = find_png_boundary(buf) {
                return (pos, false);
            }
        }
        "pdf" => {
            if let Some(pos) = find_pdf_boundary(buf, sig.footer_window) {
                return (pos, false);
            }
        }
        "zip" | "docx" | "xlsx" | "pptx" => {
            if let Some(pos) = find_zip_boundary(buf, sig.footer_window) {
                return (pos, false);
            }
        }
        "bmp" => {
            if let Some(pos) = find_bmp_boundary(buf) {
                return (pos, false);
            }
        }
        _ => {}
    }

    // Default fallback: search for footer
    if let Some(footer) = &sig.footer {
        let search_end = buf.len().min(sig.footer_window);
        if let Some(pos) = find_last_bytes(&buf[..search_end], footer) {
            return (pos + footer.len(), false);
        }
    }

    // Entropy heuristic: look for a 32-byte run of zero bytes (slack space)
    if let Some(slack_start) = find_slack_region(buf) {
        return (slack_start, false);
    }

    // Fallback: use full buffer — mark as truncated fragment
    (buf.len(), true)
}

/// Parse JPEG segments to bypass embedded EXIF thumbnails (which contain their own FF D9)
/// and locate the true terminating EOI marker after SOS (Start of Scan 0xFFDA).
fn find_jpeg_boundary(buf: &[u8], max_window: usize) -> Option<usize> {
    if buf.len() < 4 || !buf.starts_with(&[0xFF, 0xD8]) { return None; }
    let limit = buf.len().min(max_window);
    let mut i = 2usize;
    let mut in_scan = false;

    while i + 1 < limit {
        if !in_scan {
            if buf[i] != 0xFF {
                i += 1;
                continue;
            }
            let marker = buf[i + 1];
            if marker == 0xDA {
                // Start of Scan: skip SOS header (length is 2 bytes at i+2..i+4)
                if i + 4 <= limit {
                    let sos_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
                    i += 2 + sos_len;
                    in_scan = true;
                    continue;
                } else {
                    in_scan = true;
                    i += 2;
                    continue;
                }
            } else if marker == 0xD9 {
                // Standalone EOI
                return Some(i + 2);
            } else if (0xD0..=0xD8).contains(&marker) || marker == 0x01 {
                // Restart marker or SOI with no payload length
                i += 2;
            } else if i + 3 < limit {
                // Segment with 2-byte big-endian length
                let seg_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
                if seg_len < 2 { break; }
                i += 2 + seg_len;
            } else {
                break;
            }
        } else {
            // Inside entropy-coded scan data: scan for 0xFF 0xD9
            if buf[i] == 0xFF {
                let next = buf[i + 1];
                if next == 0xD9 {
                    // Confirmed End of Image
                    return Some(i + 2);
                } else if next == 0x00 || (0xD0..=0xD7).contains(&next) {
                    // Byte-stuffed 0xFF or restart marker — skip
                    i += 2;
                    continue;
                }
            }
            i += 1;
        }
    }
    // Fallback: search backwards for FF D9 in scanned data
    find_last_bytes(&buf[..limit], &[0xFF, 0xD9]).map(|pos| pos + 2)
}

/// Walk PNG chunk hierarchy: [4-byte length][4-byte type][data][4-byte CRC]
/// Returns exact byte boundary at IEND chunk end (offset + 12).
fn find_png_boundary(buf: &[u8]) -> Option<usize> {
    if buf.len() < 8 || &buf[..8] != b"\x89PNG\r\n\x1a\n" { return None; }
    let mut i = 8usize;
    let mut chunks = 0;
    while i + 12 <= buf.len() && chunks < 10_000 {
        let length = u32::from_be_bytes(buf[i..i + 4].try_into().unwrap()) as usize;
        let chunk_type = &buf[i + 4..i + 8];
        if chunk_type == b"IEND" {
            return Some(i + 12);
        }
        if i + 12 + length > buf.len() { break; }
        i += 12 + length;
        chunks += 1;
    }
    // Fallback to IEND search
    find_last_bytes(buf, b"IEND\xaeB`\x82").map(|pos| pos + 8)
}

/// Find the LAST %%EOF in PDF document to include all revisions/incremental updates.
fn find_pdf_boundary(buf: &[u8], max_window: usize) -> Option<usize> {
    let search_end = buf.len().min(max_window);
    let slice = &buf[..search_end];
    let pos = find_last_bytes(slice, b"%%EOF")?;
    let mut end = pos + 5;
    // Consume trailing newline or whitespace if present
    while end < slice.len() && (slice[end] == b'\r' || slice[end] == b'\n' || slice[end] == b' ') {
        end += 1;
    }
    Some(end)
}

/// Locate ZIP End of Central Directory (EOCD) record (PK\x05\x06) from tail
/// and include full 22-byte structure plus comment length.
fn find_zip_boundary(buf: &[u8], max_window: usize) -> Option<usize> {
    let search_end = buf.len().min(max_window);
    let slice = &buf[..search_end];
    let pos = find_last_bytes(slice, b"PK\x05\x06")?;
    if pos + 22 <= slice.len() {
        let comment_len = u16::from_le_bytes(slice[pos + 20..pos + 22].try_into().unwrap()) as usize;
        let total = (pos + 22 + comment_len).min(slice.len());
        Some(total)
    } else {
        Some(pos + 4)
    }
}

/// Validate BMP file size field from header: bytes 2..6.
fn find_bmp_boundary(buf: &[u8]) -> Option<usize> {
    if buf.len() < 14 || &buf[..2] != b"BM" { return None; }
    let file_size = u32::from_le_bytes(buf[2..6].try_into().unwrap()) as usize;
    if file_size >= 54 && file_size <= buf.len() {
        Some(file_size)
    } else {
        None
    }
}

/// Find the LAST occurrence of needle in haystack (searching backwards).
fn find_last_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return None; }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Detect a 32-byte zero run as probable slack space (file end heuristic).
fn find_slack_region(buf: &[u8]) -> Option<usize> {
    const WINDOW: usize = 32;
    if buf.len() < WINDOW { return None; }
    for i in (WINDOW..buf.len()).rev() {
        if buf[i - WINDOW..i].iter().all(|&b| b == 0) {
            return Some(i - WINDOW);
        }
    }
    None
}

/// Read as many bytes as available into buf (file may be smaller than buf).
fn read_fully(f: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match f.read(&mut buf[total..]) {
            Ok(0)    => break,
            Ok(n)    => total += n,
            Err(e)   => return Err(AppError::Io(e)),
        }
    }
    Ok(total)
}
