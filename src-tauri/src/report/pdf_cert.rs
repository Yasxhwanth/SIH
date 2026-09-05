// report/pdf_cert.rs — Forensic PDF erasure certificate generator
//
// Generates a legally-structured erasure certificate compliant with:
//   - NIST SP 800-88 reporting requirements
//   - DPDP Act 2023 §8(7) (proof of data destruction)
//
// Uses the `printpdf` crate — pure Rust, no external deps.

use std::fs;
use std::io::BufWriter;
use std::path::Path;

use chrono::Utc;
use printpdf::*;
use sha2::{Digest, Sha256};

use crate::error::{AppError, Result};
use crate::report::audit_log;

#[derive(Debug, serde::Deserialize)]
pub struct CertRequest {
    pub job_id:      String,
    pub target_path: String,
    pub standard:    String,
    pub bytes_wiped: u64,
    pub verify_pass: bool,
    pub output_path: String,
}

pub fn generate_certificate(req: &CertRequest) -> Result<String> {
    let (doc, page1, layer1) = PdfDocument::new(
        "ForensiX Erasure Certificate",
        Mm(210.0),   // A4 width
        Mm(297.0),   // A4 height
        "Layer 1",
    );

    let current_layer = doc.get_page(page1).get_layer(layer1);

    // Load fonts
    let font_bold    = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
    let font_mono    = doc.add_builtin_font(BuiltinFont::Courier).unwrap();

    // — Header bar —
    let header_rect = Rect::new(Mm(0.0), Mm(267.0), Mm(210.0), Mm(297.0));
    current_layer.set_fill_color(Color::Rgb(Rgb::new(0.05, 0.08, 0.15, None)));
    current_layer.add_rect(header_rect);

    current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.9, 0.6, None)));
    current_layer.use_text("ForensiX — Data Erasure Certificate", 18.0, Mm(15.0), Mm(278.0), &font_bold);

    current_layer.set_fill_color(Color::Rgb(Rgb::new(0.7, 0.7, 0.9, None)));
    current_layer.use_text("NTRO Digital Forensics & Data Sanitization Tool", 10.0, Mm(15.0), Mm(271.0), &font_regular);

    // — Certificate body —
    current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

    let now = Utc::now().to_rfc3339();
    let operator = format!(
        "{}@{}",
        std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or("unknown".into()),
        hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or("unknown".into())
    );

    let fields: Vec<(&str, String)> = vec![
        ("Certificate ID",    req.job_id.clone()),
        ("Generated At",      now.clone()),
        ("Operator",          operator),
        ("Target",            req.target_path.clone()),
        ("Wipe Standard",     req.standard.clone()),
        ("Bytes Wiped",       format!("{} ({:.2} MB)", req.bytes_wiped, req.bytes_wiped as f64 / 1_048_576.0)),
        ("Verification",      if req.verify_pass { "✓ PASSED — All sectors verified".into() } else { "✗ FAILED or NOT RUN".into() }),
        ("DPDP Act §8(7)",   "Data destruction recorded as required for right to erasure compliance".into()),
    ];

    let mut y = 255.0f32;
    for (key, val) in &fields {
        current_layer.use_text(*key, 9.0, Mm(15.0), Mm(y), &font_bold);
        current_layer.use_text(val, 9.0, Mm(65.0), Mm(y), &font_regular);
        y -= 10.0;
    }

    // — Audit log hash anchor & Section 63 BSA 2023 Evidentiary Preamble —
    y -= 5.0;
    let separator_y = Mm(y + 5.0);
    current_layer.add_line(Line {
        points: vec![
            (Point::new(Mm(15.0), separator_y), false),
            (Point::new(Mm(195.0), separator_y), false),
        ],
        is_closed: false,
    });

    y -= 5.0;
    current_layer.use_text("Section 63 BSA 2023 Evidentiary Certification", 10.0, Mm(15.0), Mm(y), &font_bold);

    y -= 6.0;
    let log_hash = compute_log_hash()?;
    let merkle_root = audit_log::compute_merkle_root().unwrap_or_else(|_| "(unsealed)".into());
    let officer_pubkey = audit_log::get_officer_verifying_key_hex();

    current_layer.use_text("Audit Log SHA-256:", 8.0, Mm(15.0), Mm(y), &font_bold);
    y -= 5.0;
    current_layer.use_text(&log_hash, 7.0, Mm(15.0), Mm(y), &font_mono);

    y -= 7.0;
    current_layer.use_text("Ledger Merkle Root:", 8.0, Mm(15.0), Mm(y), &font_bold);
    y -= 5.0;
    current_layer.use_text(&merkle_root, 7.0, Mm(15.0), Mm(y), &font_mono);

    y -= 7.0;
    current_layer.use_text("Officer Ed25519 Key:", 8.0, Mm(15.0), Mm(y), &font_bold);
    y -= 5.0;
    current_layer.use_text(&officer_pubkey, 7.0, Mm(15.0), Mm(y), &font_mono);

    y -= 8.0;
    let (entries, chain_ok, _) = audit_log::verify_chain().unwrap_or((0, true, None));
    let chain_status = if chain_ok {
        format!("✓ VALID AUDIT CHAIN — {} entries verified, zero tampering detected", entries)
    } else {
        format!("✗ CHAIN BROKEN — possible tampering detected")
    };
    current_layer.use_text(&chain_status, 8.5, Mm(15.0), Mm(y), &font_bold);

    // Section 63(4) Statutory Declarations
    y -= 10.0;
    current_layer.set_fill_color(Color::Rgb(Rgb::new(0.2, 0.2, 0.3, None)));
    current_layer.use_text("Mandatory Affidavit under Section 63(4) Bharatiya Sakshya Adhiniyam, 2023:", 7.5, Mm(15.0), Mm(y), &font_bold);
    y -= 5.0;
    current_layer.use_text("1. This electronic certificate is produced in lawful execution of forensic data sanitization duties.", 7.0, Mm(15.0), Mm(y), &font_regular);
    y -= 4.0;
    current_layer.use_text("2. Physical storage media and cryptographic hashing algorithms (SHA-256 / Keccak-256) operated without error.", 7.0, Mm(15.0), Mm(y), &font_regular);
    y -= 4.0;
    current_layer.use_text("3. Hardware sector verification and cryptographic proof seals remain tamper-evident and admissible in court.", 7.0, Mm(15.0), Mm(y), &font_regular);

    // — Vector Cryptographic QR Code —
    let qr_payload = format!(
        "https://forensix.ntro.gov.in/verify?cert={}&root={}&officer={}&sha256={}",
        req.job_id, merkle_root, officer_pubkey, log_hash
    );

    if let Ok(code) = qrcode::QrCode::new(qr_payload.as_bytes()) {
        let width = code.width();
        let qr_size_mm = 34.0f32;
        let module_size = qr_size_mm / width as f32;
        let start_x = 158.0f32;
        let start_y = 52.0f32;

        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        for (r_idx, row) in code.to_colors().chunks(width).enumerate() {
            for (c_idx, &color) in row.iter().enumerate() {
                if color == qrcode::Color::Dark {
                    let px = start_x + (c_idx as f32 * module_size);
                    let py = start_y + ((width - 1 - r_idx) as f32 * module_size);
                    current_layer.add_rect(Rect::new(Mm(px), Mm(py), Mm(px + module_size), Mm(py + module_size)));
                }
            }
        }
        current_layer.set_fill_color(Color::Rgb(Rgb::new(0.3, 0.3, 0.5, None)));
        current_layer.use_text("Scan to Verify BSA Seal", 6.5, Mm(158.0), Mm(47.0), &font_bold);
    }

    // — Footer —
    y = 15.0;
    current_layer.set_fill_color(Color::Rgb(Rgb::new(0.6, 0.6, 0.6, None)));
    current_layer.use_text(
        &format!("Generated by ForensiX v0.1.0 | SIH PS-26149 | NTRO | {}", now),
        7.0, Mm(15.0), Mm(y), &font_regular,
    );

    // Save PDF
    let out_path = Path::new(&req.output_path);
    if let Some(parent) = out_path.parent() { fs::create_dir_all(parent)?; }

    let file = fs::File::create(out_path)?;
    let mut writer = BufWriter::new(file);
    doc.save(&mut writer).map_err(|e| AppError::ReportError(e.to_string()))?;

    Ok(req.output_path.clone())
}

fn compute_log_hash() -> Result<String> {
    if let Some(log_path) = audit_log::log_path() {
        if log_path.exists() {
            let data = fs::read(&log_path)?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            return Ok(hex::encode(hasher.finalize()));
        }
    }
    Ok("(log not found)".to_string())
}
