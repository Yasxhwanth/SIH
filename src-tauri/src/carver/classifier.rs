// carver/classifier.rs — Automatic file classification
//
// After extraction, classifies files into category/subtype and extracts
// whatever metadata is readable without external libraries.

use crate::carver::extractor::CarvedFile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub category:    String,
    pub subtype:     String,
    pub mime_type:   String,
    pub metadata:    Vec<(String, String)>,  // key-value pairs
}

/// Classify a carved file and extract embedded metadata.
pub fn classify(file: &CarvedFile, data: &[u8]) -> Classification {
    let (subtype, mime_type, metadata) = match file.extension {
        "jpg"  => classify_jpeg(data),
        "png"  => classify_png(data),
        "pdf"  => classify_pdf(data),
        "zip"  => classify_zip(data),
        "elf"  => classify_elf(data),
        "exe"  => classify_pe(data),
        "sqlite" => classify_sqlite(data),
        "mp3"  => classify_mp3(data),
        _      => (file.description.to_string(), generic_mime(file.extension), vec![]),
    };

    Classification {
        category:  file.category.clone(),
        subtype,
        mime_type,
        metadata,
    }
}

fn generic_mime(ext: &str) -> String {
    match ext {
        "jpg"  => "image/jpeg",
        "png"  => "image/png",
        "gif"  => "image/gif",
        "bmp"  => "image/bmp",
        "tif"  => "image/tiff",
        "pdf"  => "application/pdf",
        "zip"  => "application/zip",
        "rar"  => "application/x-rar-compressed",
        "7z"   => "application/x-7z-compressed",
        "gz"   => "application/gzip",
        "mp3"  => "audio/mpeg",
        "wav"  => "audio/wav",
        "ogg"  => "audio/ogg",
        "flac" => "audio/flac",
        "mp4"  => "video/mp4",
        "mkv"  => "video/x-matroska",
        "elf"  => "application/x-elf",
        "exe"  => "application/x-msdownload",
        "sqlite" => "application/x-sqlite3",
        "pem"  => "application/x-pem-file",
        _      => "application/octet-stream",
    }.to_string()
}

// ── JPEG ─────────────────────────────────────────────────────────────────────
fn classify_jpeg(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut meta = vec![];
    // JFIF or Exif APP0/APP1
    if data.len() > 12 {
        if &data[6..10] == b"JFIF" {
            meta.push(("Format".into(), "JFIF".into()));
        } else if &data[6..10] == b"Exif" {
            meta.push(("Format".into(), "Exif".into()));
        }
    }
    // Try to extract dimensions from SOF0 marker
    if let Some(dims) = jpeg_dimensions(data) {
        meta.push(("Width".into(),  dims.0.to_string()));
        meta.push(("Height".into(), dims.1.to_string()));
    }
    ("JPEG Image".into(), "image/jpeg".into(), meta)
}

fn jpeg_dimensions(data: &[u8]) -> Option<(u16, u16)> {
    let mut i = 2usize;
    while i + 8 < data.len() {
        if data[i] != 0xFF { break; }
        let marker = data[i + 1];
        let seg_len = u16::from_be_bytes([data[i+2], data[i+3]]) as usize;
        // SOF markers: C0, C1, C2
        if matches!(marker, 0xC0 | 0xC1 | 0xC2) && seg_len >= 7 {
            let h = u16::from_be_bytes([data[i+5], data[i+6]]);
            let w = u16::from_be_bytes([data[i+7], data[i+8]]);
            return Some((w, h));
        }
        i += 2 + seg_len;
        if i >= data.len() { break; }
    }
    None
}

// ── PNG ──────────────────────────────────────────────────────────────────────
fn classify_png(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut meta = vec![];
    if data.len() >= 24 {
        // IHDR: width at bytes 16-19, height at 20-23
        let w = u32::from_be_bytes(data[16..20].try_into().unwrap());
        let h = u32::from_be_bytes(data[20..24].try_into().unwrap());
        meta.push(("Width".into(),  w.to_string()));
        meta.push(("Height".into(), h.to_string()));
        if data.len() > 24 {
            let bit_depth  = data[24];
            let color_type = data[25];
            meta.push(("Bit Depth".into(),  bit_depth.to_string()));
            meta.push(("Color Type".into(), png_color_type(color_type).into()));
        }
    }
    ("PNG Image".into(), "image/png".into(), meta)
}

fn png_color_type(ct: u8) -> &'static str {
    match ct { 0 => "Grayscale", 2 => "RGB", 3 => "Indexed", 4 => "Grayscale+Alpha", 6 => "RGBA", _ => "Unknown" }
}

// ── PDF ──────────────────────────────────────────────────────────────────────
fn classify_pdf(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut meta = vec![];
    // Extract version from header
    if data.len() >= 8 {
        let ver: String = data[5..8].iter()
            .take_while(|&&b| b != b'\n' && b != b'\r')
            .map(|&b| b as char).collect();
        meta.push(("PDF Version".into(), ver));
    }
    // Count page references (rough)
    let s = String::from_utf8_lossy(&data[..data.len().min(65536)]);
    let page_count = s.matches("/Page ").count();
    if page_count > 0 {
        meta.push(("Approx Pages".into(), page_count.to_string()));
    }
    ("PDF Document".into(), "application/pdf".into(), meta)
}

// ── ZIP ──────────────────────────────────────────────────────────────────────
fn classify_zip(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut meta = vec![];
    // Count local file headers
    let count = data.windows(4).filter(|w| *w == b"PK\x03\x04").count();
    meta.push(("File Count".into(), count.to_string()));
    // Detect OOXML sub-type
    let is_docx  = data.windows(11).any(|w| w == b"word/doc.xm".as_ref());
    let is_xlsx  = data.windows(15).any(|w| w == b"xl/workbook.xm".as_ref());
    let is_pptx  = data.windows(19).any(|w| w == b"ppt/presentation.xm".as_ref());
    let subtype = if is_docx { "Word Document (.docx)" }
                  else if is_xlsx { "Excel Workbook (.xlsx)" }
                  else if is_pptx { "PowerPoint (.pptx)" }
                  else { "ZIP Archive" };
    (subtype.into(), "application/zip".into(), meta)
}

// ── ELF ──────────────────────────────────────────────────────────────────────
fn classify_elf(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut meta = vec![];
    if data.len() >= 20 {
        meta.push(("Class".into(),    if data[4] == 1 { "32-bit".into() } else { "64-bit".into() }));
        meta.push(("Endian".into(),   if data[5] == 1 { "Little".into() } else { "Big".into() }));
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        meta.push(("Type".into(), match e_type {
            1 => "Relocatable".into(), 2 => "Executable".into(),
            3 => "Shared Object".into(), 4 => "Core Dump".into(),
            _ => format!("0x{:04x}", e_type),
        }));
    }
    ("ELF Binary".into(), "application/x-elf".into(), meta)
}

// ── PE ───────────────────────────────────────────────────────────────────────
fn classify_pe(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut meta = vec![];
    if data.len() >= 68 {
        let e_lfanew = u32::from_le_bytes(data[60..64].try_into().unwrap()) as usize;
        if e_lfanew + 6 < data.len() {
            let machine = u16::from_le_bytes(data[e_lfanew+4..e_lfanew+6].try_into().unwrap());
            meta.push(("Machine".into(), match machine {
                0x014c => "x86".into(), 0x8664 => "x64".into(),
                0xAA64 => "ARM64".into(), _ => format!("0x{:04x}", machine),
            }));
        }
    }
    ("PE Executable".into(), "application/x-msdownload".into(), meta)
}

// ── SQLite ───────────────────────────────────────────────────────────────────
pub fn classify_sqlite(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut meta = vec![];
    if data.len() >= 100 {
        let raw_page_size = u16::from_be_bytes([data[16], data[17]]);
        let page_size = if raw_page_size == 1 { 65536 } else { raw_page_size as u32 };
        meta.push(("Page Size".into(), format!("{} bytes", page_size)));

        let page_count = u32::from_be_bytes(data[28..32].try_into().unwrap_or([0; 4]));
        meta.push(("Total Database Pages".into(), page_count.to_string()));

        let freelist_pages = u32::from_be_bytes(data[36..40].try_into().unwrap_or([0; 4]));
        if freelist_pages > 0 {
            meta.push(("Deleted Records / Freelist Pages".into(), format!("{} pages (Recoverable Deleted Rows)", freelist_pages)));
        } else {
            meta.push(("Freelist Pages".into(), "0 (Clean / Vacuumed)".into()));
        }

        let encoding_code = u32::from_be_bytes(data[56..60].try_into().unwrap_or([0; 4]));
        let encoding_str = match encoding_code {
            1 => "UTF-8",
            2 => "UTF-16LE",
            3 => "UTF-16BE",
            _ => "Standard",
        };
        meta.push(("Text Encoding".into(), encoding_str.into()));

        let user_version = u32::from_be_bytes(data[60..64].try_into().unwrap_or([0; 4]));
        if user_version > 0 {
            meta.push(("User Schema Version".into(), user_version.to_string()));
        }

        let version = u32::from_be_bytes(data[96..100].try_into().unwrap_or([0; 4]));
        if version > 0 {
            let major = version / 1000000;
            let minor = (version / 1000) % 1000;
            let patch = version % 1000;
            meta.push(("SQLite Library Version".into(), format!("{}.{}.{}", major, minor, patch)));
        }

        // Scan page 1 for table definitions in sqlite_master
        let search_limit = (page_size as usize).min(data.len());
        if search_limit > 108 {
            let p1 = &data[100..search_limit];
            let needle = b"CREATE TABLE ";
            let mut tables = Vec::new();
            for (idx, w) in p1.windows(needle.len()).enumerate() {
                if w == needle {
                    let rem = &p1[idx + needle.len()..];
                    let mut name = String::new();
                    for &b in rem {
                        if b == b' ' || b == b'(' || b == b'"' || b == b'`' || b == b'[' {
                            if !name.is_empty() { break; }
                        } else if b.is_ascii_graphic() {
                            name.push(b as char);
                        } else {
                            break;
                        }
                    }
                    if !name.is_empty() && !tables.contains(&name) && name != "IF" {
                        tables.push(name);
                    }
                }
            }
            if !tables.is_empty() {
                meta.push(("Discovered Tables".into(), tables.join(", ")));
            }
        }
    }
    ("SQLite Database".into(), "application/x-sqlite3".into(), meta)
}

// ── MP3 ──────────────────────────────────────────────────────────────────────
fn classify_mp3(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let mut meta = vec![];
    if data.len() >= 10 && &data[..3] == b"ID3" {
        let major = data[3];
        meta.push(("ID3 Version".into(), format!("2.{}", major)));
        // Extract title from TIT2 frame (simple, no encoding handling)
        if let Some(title) = find_id3_frame(data, b"TIT2") {
            meta.push(("Title".into(), title));
        }
        if let Some(artist) = find_id3_frame(data, b"TPE1") {
            meta.push(("Artist".into(), artist));
        }
    }
    ("MP3 Audio".into(), "audio/mpeg".into(), meta)
}

fn find_id3_frame<'a>(data: &'a [u8], frame_id: &[u8]) -> Option<String> {
    let pos = data.windows(4).position(|w| w == frame_id)?;
    if pos + 11 > data.len() { return None; }
    let size = u32::from_be_bytes(data[pos+4..pos+8].try_into().ok()?) as usize;
    if pos + 11 + size > data.len() { return None; }
    // Skip encoding byte
    let text: String = data[pos+11..pos+11+size.min(100)]
        .iter()
        .filter(|&&b| b >= 32 && b < 127)
        .map(|&b| b as char)
        .collect();
    if text.is_empty() { None } else { Some(text) }
}

// ── Anti-Forensics: Chi-Square Test & Cluster Slack Analyzer ─────────────────

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChiSquareResult {
    pub shannon_entropy:    f64,
    pub chi_square:         f64,
    pub degrees_of_freedom: usize,
    pub is_uniform_random:  bool,
    pub classification:     String,
    pub interpretation:     String,
}

/// Chi-Square (χ²) Goodness-of-Fit test for uniform distribution over 256 byte bins.
/// Distinguishes compressed archives (skewed distribution) from encrypted payloads (uniform).
#[allow(dead_code)]
pub fn calculate_chi_square_uniformity(data: &[u8]) -> ChiSquareResult {
    if data.is_empty() {
        return ChiSquareResult {
            shannon_entropy: 0.0,
            chi_square: 0.0,
            degrees_of_freedom: 255,
            is_uniform_random: false,
            classification: "Empty".into(),
            interpretation: "Zero-length byte sequence".into(),
        };
    }

    let h = crate::carver::fragment::entropy(data);
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }

    let n = data.len() as f64;
    let expected = n / 256.0;

    let mut chi_square = 0.0;
    for &o in &freq {
        let diff = o as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    // Uniform random distribution with 255 degrees of freedom has p-value [0.05, 0.95] in [215, 295].
    // Compressed files have local table skews causing χ² > 350 even with entropy > 7.9.
    let is_uniform_random = h >= 7.85 && chi_square <= 380.0 && n >= 512.0;

    let (classification, interpretation) = if is_uniform_random {
        (
            "Encrypted Volume / High-Entropy Payload".into(),
            format!("Shannon entropy ({:.3}) with uniform Chi-square ({:.2}) indicates authentic cryptographic randomness.", h, chi_square)
        )
    } else if h >= 7.50 {
        (
            "Compressed Container / Archive".into(),
            format!("Shannon entropy ({:.3}) with skewed Chi-square ({:.2}) indicates compressed dictionary/Huffman encoding.", h, chi_square)
        )
    } else {
        (
            "Structured / Plaintext Data".into(),
            format!("Entropy ({:.3}) with Chi-square ({:.2}) indicates standard binary or text formatting.", h, chi_square)
        )
    };

    ChiSquareResult {
        shannon_entropy: h,
        chi_square,
        degrees_of_freedom: 255,
        is_uniform_random,
        classification,
        interpretation,
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackReport {
    pub logical_size:      u64,
    pub cluster_size:      usize,
    pub slack_bytes_total: usize,
    pub non_zero_bytes:    usize,
    pub anomaly_detected:  bool,
    pub ascii_preview:     Option<String>,
    pub findings:          String,
}

/// Inspect cluster slack space between a file's logical EOF and its cluster boundary.
#[allow(dead_code)]
pub fn inspect_cluster_slack(
    image_path:   &str,
    file_offset:  u64,
    logical_size: u64,
    cluster_size: usize,
) -> Result<SlackReport, std::io::Error> {
    use std::io::{Read, Seek, SeekFrom};
    let c_size = if cluster_size == 0 { 4096 } else { cluster_size };
    let remainder = (logical_size as usize) % c_size;
    let slack_len = if remainder == 0 { 0 } else { c_size - remainder };

    if slack_len == 0 {
        return Ok(SlackReport {
            logical_size,
            cluster_size: c_size,
            slack_bytes_total: 0,
            non_zero_bytes: 0,
            anomaly_detected: false,
            ascii_preview: None,
            findings: "File is cluster-aligned; 0 bytes slack space.".into(),
        });
    }

    let slack_offset = file_offset + logical_size;
    let norm = crate::carver::scanner::normalise_path(image_path);
    let mut f = std::fs::File::open(&norm)?;
    f.seek(SeekFrom::Start(slack_offset))?;

    let mut buf = vec![0u8; slack_len];
    let n = f.read(&mut buf).unwrap_or(0);
    buf.truncate(n);

    let non_zeros = buf.iter().filter(|&&b| b != 0).count();
    let printable = buf.iter().filter(|&&b| b >= 32 && b <= 126).count();

    let anomaly_detected = non_zeros > 16;
    let ascii_preview = if printable >= 8 {
        let text: String = buf.iter()
            .filter(|&&b| b >= 32 && b <= 126)
            .take(64)
            .map(|&b| b as char)
            .collect();
        Some(text)
    } else {
        None
    };

    let findings = if anomaly_detected {
        format!(
            "ALERT: Cluster slack contains {} non-zero bytes (Steganography / Hidden payload indicator).",
            non_zeros
        )
    } else {
        "Clean: Slack space consists of null padding or zero-filled blocks.".into()
    };

    Ok(SlackReport {
        logical_size,
        cluster_size: c_size,
        slack_bytes_total: slack_len,
        non_zero_bytes: non_zeros,
        anomaly_detected,
        ascii_preview,
        findings,
    })
}
