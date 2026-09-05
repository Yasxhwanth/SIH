// tests/unit_tests.rs — Comprehensive unit test suite for ForensiX

use forensix_lib::carver::signatures::{all_signatures, FileCategory};
use forensix_lib::carver::confidence::{compute_confidence, ConfidenceLabel};
use forensix_lib::carver::validator::validate;
use forensix_lib::eraser::drive::strategies::WipeStandard;

#[test]
fn test_signature_database_completeness() {
    let sigs = all_signatures();
    assert!(sigs.len() >= 80, "Should have at least 80 signatures defined, found {}", sigs.len());

    // Check critical types
    let has_jpg = sigs.iter().any(|s| s.extension == "jpg" && s.category == FileCategory::Image);
    let has_png = sigs.iter().any(|s| s.extension == "png" && s.category == FileCategory::Image);
    let has_pdf = sigs.iter().any(|s| s.extension == "pdf" && s.category == FileCategory::Document);
    let has_zip = sigs.iter().any(|s| s.extension == "zip" && s.category == FileCategory::Archive);
    let has_elf = sigs.iter().any(|s| s.extension == "elf" && s.category == FileCategory::Executable);
    let has_sqlite = sigs.iter().any(|s| s.extension == "sqlite" && s.category == FileCategory::Database);

    // Check professional RAW, CAD, Virtualization, and Defense types
    let has_cr3 = sigs.iter().any(|s| s.extension == "cr3");
    let has_dwg = sigs.iter().any(|s| s.extension == "dwg");
    let has_heic = sigs.iter().any(|s| s.extension == "heic");
    let has_zst = sigs.iter().any(|s| s.extension == "zst");
    let has_pf = sigs.iter().any(|s| s.extension == "pf");

    assert!(has_jpg, "Missing JPG signature");
    assert!(has_png, "Missing PNG signature");
    assert!(has_pdf, "Missing PDF signature");
    assert!(has_zip, "Missing ZIP signature");
    assert!(has_elf, "Missing ELF signature");
    assert!(has_sqlite, "Missing SQLite signature");
    assert!(has_cr3, "Missing Canon CR3 RAW signature");
    assert!(has_dwg, "Missing AutoCAD DWG signature");
    assert!(has_heic, "Missing Apple HEIC signature");
    assert!(has_zst, "Missing Zstandard signature");
    assert!(has_pf, "Missing Windows Prefetch forensic signature");

    use forensix_lib::carver::signatures::get_catalog_stats;
    let stats = get_catalog_stats();
    assert!(stats.total_signatures >= 80);
    assert!(stats.total_extensions >= 400, "Catalog must cover 400+ extensions (found {})", stats.total_extensions);
}

#[test]
fn test_confidence_scoring() {
    // Case 1: High confidence (magic + footer + struct valid)
    let score1 = compute_confidence(0.9, true, true, false, false);
    let label1 = ConfidenceLabel::from(score1);
    assert!(score1 >= 0.85);
    assert_eq!(label1, ConfidenceLabel::High);

    // Case 2: Truncated file reduces score
    let score2 = compute_confidence(0.9, false, true, true, false);
    assert!(score2 < score1);

    // Case 3: Structural check fail drops score
    let score3 = compute_confidence(0.7, false, false, false, false);
    let label3 = ConfidenceLabel::from(score3);
    assert!(score3 < score1);
    assert_ne!(label3, ConfidenceLabel::High);
}

#[test]
fn test_jpeg_validator() {
    let sigs = all_signatures();
    let jpg_sig = sigs.iter().find(|s| s.extension == "jpg").expect("jpg sig");

    // Valid minimal JPEG
    let valid_jpeg = vec![
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00,
        0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0xFF, 0xD9,
    ];
    assert!(validate(jpg_sig, &valid_jpeg));

    // Corrupt JPEG (no footer)
    let bad_jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F'];
    assert!(!validate(jpg_sig, &bad_jpeg));
}

#[test]
fn test_png_validator() {
    let sigs = all_signatures();
    let png_sig = sigs.iter().find(|s| s.extension == "png").expect("png sig");

    // Valid minimal PNG chunk
    let valid_png = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
        0xDE, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, // IEND
        0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    assert!(validate(png_sig, &valid_png));

    // Corrupted PNG header
    let bad_png = vec![0x89, 0x50, 0x4E, 0x47, 0x00, 0x00, 0x00, 0x00];
    assert!(!validate(png_sig, &bad_png));
}

#[test]
fn test_pdf_validator() {
    let sigs = all_signatures();
    let pdf_sig = sigs.iter().find(|s| s.extension == "pdf").expect("pdf sig");

    let valid_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF";
    assert!(validate(pdf_sig, valid_pdf));

    let bad_pdf = b"Not a pdf document at all";
    assert!(!validate(pdf_sig, bad_pdf));
}

#[test]
fn test_elf_validator() {
    let sigs = all_signatures();
    let elf_sig = sigs.iter().find(|s| s.extension == "elf").expect("elf sig");

    let mut elf = vec![0u8; 64];
    elf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    elf[4] = 2; // 64-bit
    elf[5] = 1; // Little endian
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // EXEC
    elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // x86_64
    assert!(validate(elf_sig, &elf));
}

#[test]
fn test_wipe_standards_specs() {
    assert_eq!(WipeStandard::NistClear.passes(), 1);
    assert_eq!(WipeStandard::Dod3Pass.passes(), 3);
    assert_eq!(WipeStandard::Gutmann7.passes(), 7);

    assert!(WipeStandard::NistClear.label().contains("NIST"));
    assert!(WipeStandard::Dod3Pass.label().contains("DoD"));
}

#[test]
fn test_mft_parser_and_timestomp_detection() {
    use forensix_lib::carver::mft::{parse_mft_record, MacbTimestamps, detect_timestomp};

    // Construct a synthetic 1024-byte MFT Record
    let mut rec = vec![0u8; 1024];
    rec[0..4].copy_from_slice(b"FILE");
    rec[4..6].copy_from_slice(&0x30u16.to_le_bytes()); // update seq offset
    rec[6..8].copy_from_slice(&3u16.to_le_bytes());    // update seq count
    rec[20..22].copy_from_slice(&56u16.to_le_bytes()); // first attr offset
    rec[22..24].copy_from_slice(&1u16.to_le_bytes());  // in use

    // Add $STANDARD_INFORMATION attribute at offset 56
    let si_off = 56;
    rec[si_off..si_off+4].copy_from_slice(&0x10u32.to_le_bytes()); // Type 0x10
    rec[si_off+4..si_off+8].copy_from_slice(&96u32.to_le_bytes()); // Length 96
    rec[si_off+8] = 0; // Resident
    rec[si_off+20..si_off+22].copy_from_slice(&24u16.to_le_bytes()); // Content offset
    // Timestamps: Windows tick 133500000000000000
    let ft_created = 133_500_000_000_000_000u64;
    let ft_modified = 133_500_100_000_000_000u64;
    let c_start = si_off + 24;
    rec[c_start..c_start+8].copy_from_slice(&ft_created.to_le_bytes());
    rec[c_start+8..c_start+16].copy_from_slice(&ft_modified.to_le_bytes());

    let parsed = parse_mft_record(&rec, 42).expect("mft parse");
    assert!(parsed.is_in_use);
    assert!(parsed.standard_info.is_some());

    // Test Timestomping detector
    // SI modified earlier than FN created by 500 seconds
    let fake_si = Some(MacbTimestamps {
        created: "2026-01-01T00:00:00Z".into(),
        modified: "2025-12-31T23:00:00Z".into(),
        mft_altered: "2026-01-01T00:00:00Z".into(),
        accessed: "2026-01-01T00:00:00Z".into(),
        created_raw: 133_000_000_000_000_000,
        modified_raw: 132_999_000_000_000_000,
    });
    let fake_fn = Some(MacbTimestamps {
        created: "2026-01-01T01:00:00Z".into(),
        modified: "2026-01-01T01:00:00Z".into(),
        mft_altered: "2026-01-01T01:00:00Z".into(),
        accessed: "2026-01-01T01:00:00Z".into(),
        created_raw: 133_000_050_000_000_000,
        modified_raw: 133_000_050_000_000_000,
    });
    let alert = detect_timestomp(&fake_si, &fake_fn);
    assert!(alert.is_some(), "Timestomp should be flagged");
    assert_eq!(alert.unwrap().severity, "CRITICAL");
}

#[test]
fn test_chi_square_uniformity_analyzer() {
    use forensix_lib::carver::classifier::calculate_chi_square_uniformity;
    use rand::RngCore;

    // 1. Uniform random data (simulation of AES ciphertext / encrypted container)
    let mut random_data = vec![0u8; 16384];
    rand::thread_rng().fill_bytes(&mut random_data);
    let crypto_res = calculate_chi_square_uniformity(&random_data);
    assert!(crypto_res.shannon_entropy >= 7.90);
    assert!(crypto_res.is_uniform_random, "CSPRNG random data should pass uniform Chi-square");

    // 2. Structured text / repetitive data
    let structured_data = b"FORENSIX_DEFENSE_FORENSICS_EVIDENTIARY_RECORD".repeat(500);
    let struct_res = calculate_chi_square_uniformity(&structured_data);
    assert!(!struct_res.is_uniform_random);
    assert!(struct_res.chi_square > 500.0);
}

#[test]
fn test_credential_and_secret_signatures() {
    let sigs = all_signatures();
    let aws_sig = sigs.iter().find(|s| s.extension == "key" && s.description.contains("AWS")).expect("aws sig");
    let gh_sig  = sigs.iter().find(|s| s.extension == "token" && s.description.contains("GitHub")).expect("gh sig");
    let jwt_sig = sigs.iter().find(|s| s.extension == "jwt").expect("jwt sig");
    let pem_sig = sigs.iter().find(|s| s.extension == "pem").expect("pem sig");

    // AWS validation
    assert!(validate(aws_sig, b"AKIAIOSFODNN7EXAMPLE"));
    assert!(!validate(aws_sig, b"AKIA123")); // too short
    assert!(!validate(aws_sig, b"AKIAlower_case_fail_!"));

    // GitHub PAT validation
    assert!(validate(gh_sig, b"ghp_1234567890abcdefghijklmnopqrstuvwxyz"));
    assert!(!validate(gh_sig, b"ghp_short"));

    // JWT Bearer validation
    let valid_jwt = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert!(validate(jwt_sig, valid_jwt));
    assert!(!validate(jwt_sig, b"eyJnot_a_valid_jwt"));

    // PEM validation
    let valid_pem = b"-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg...\n-----END PRIVATE KEY-----\n";
    assert!(validate(pem_sig, valid_pem));
}

#[test]
fn test_court_ready_pdf_qr_and_bsa63() {
    use forensix_lib::report::pdf_cert::{generate_certificate, CertRequest};

    let temp_dir = std::env::temp_dir();
    let cert_path = temp_dir.join("forensix_test_bsa63_cert.pdf");

    let req = CertRequest {
        job_id: "JOB-TEST-BSA63-001".into(),
        target_path: "PhysicalDrive1".into(),
        standard: "NIST SP 800-88 Rev 1 Purge".into(),
        bytes_wiped: 1048576 * 500,
        verify_pass: true,
        output_path: cert_path.to_string_lossy().to_string(),
    };

    let res = generate_certificate(&req);
    assert!(res.is_ok(), "Certificate generation should succeed");
    assert!(cert_path.exists(), "PDF certificate file should exist");
    assert!(cert_path.metadata().unwrap().len() > 1000, "PDF should have content");

    let _ = std::fs::remove_file(cert_path);
}

#[test]
fn test_chain_of_custody_lifecycle() {
    use forensix_lib::forensics::{record_extraction, cmd::get_chain_of_custody};
    use std::path::PathBuf;

    let rec = record_extraction(
        "evidence_test_01",
        "PhysicalDrive1",
        1048576,
        PathBuf::from("C:\\ForensiX\\Carved\\evidence_test_01.pdf"),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );

    assert_eq!(rec.file_id, "evidence_test_01");
    let custody = get_chain_of_custody().expect("get custody");
    assert!(custody.iter().any(|r| r.file_id == "evidence_test_01"));
}

#[test]
fn test_bifragment_kl_divergence_and_gap() {
    use forensix_lib::carver::fragment::try_reconstruct;
    use forensix_lib::carver::signatures::all_signatures;

    let sigs = all_signatures();
    let zip_sig = sigs.iter().find(|s| s.extension == "zip").expect("zip sig");

    // Head fragment (starts with PK\x03\x04, at least 4096 bytes)
    let mut head = vec![0x50, 0x4B, 0x03, 0x04];
    // Fill head with realistic payload up to 4096 bytes
    for i in 0..4092 {
        head.push((i % 251) as u8);
    }

    // Tail fragment (at least 4096 bytes, similar distribution, ending with EOCD PK\x05\x06)
    let mut tail = Vec::with_capacity(4096);
    for i in 0..4074 {
        tail.push(((i + 7) % 251) as u8);
    }
    // EOCD record
    tail.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    tail.extend_from_slice(&[0u8; 18]);

    // Construct disk image: Head at offset 0, followed by a 4096-byte wiped gap (0x00), then Tail
    let gap_size = 4096usize;
    let mut image = head.clone();
    image.extend_from_slice(&vec![0x00; gap_size]);
    let tail_offset = image.len() as u64;
    image.extend_from_slice(&tail);

    let temp_img = std::env::temp_dir().join("forensix_test_bifragment.img");
    std::fs::write(&temp_img, &image).expect("write temp img");

    let img_path_str = temp_img.to_string_lossy().to_string();
    let res = try_reconstruct(&img_path_str, &head, zip_sig, 0);

    let _ = std::fs::remove_file(&temp_img);

    assert!(res.is_some(), "Bi-fragment assembly should successfully bridge the wiped gap");
    let recon = res.unwrap();
    assert_eq!(recon.frag_offset, tail_offset, "Should locate tail fragment at correct LBA");
    assert_eq!(recon.gap_bytes, gap_size as u64, "Gap distance should equal 4096 bytes");
    assert!(recon.kl_divergence < 5.0, "KL divergence continuity score should be bounded");
    assert!(recon.assembled.len() >= 8192, "Assembled payload should combine head and tail");
}

#[test]
fn test_sqlite_deep_metadata_classification() {
    use forensix_lib::carver::classifier::classify_sqlite;

    let mut db_header = vec![0u8; 512];
    db_header[..16].copy_from_slice(b"SQLite format 3\0");
    // Page size at offset 16 (big endian u16) = 4096
    db_header[16..18].copy_from_slice(&4096u16.to_be_bytes());
    // Total pages at offset 28 (big endian u32) = 150
    db_header[28..32].copy_from_slice(&150u32.to_be_bytes());
    // Freelist pages at offset 36 (big endian u32) = 12
    db_header[36..40].copy_from_slice(&12u32.to_be_bytes());
    // Text encoding at offset 56 = 1 (UTF-8)
    db_header[56..60].copy_from_slice(&1u32.to_be_bytes());

    let (subtype, mime, metadata) = classify_sqlite(&db_header);
    assert_eq!(subtype, "SQLite Database");
    assert_eq!(mime, "application/x-sqlite3");

    let page_size_meta = metadata.iter().find(|(k, _)| k == "Page Size");
    assert!(page_size_meta.is_some());
    assert_eq!(page_size_meta.unwrap().1, "4096 bytes");

    let freelist_meta = metadata.iter().find(|(k, _)| k == "Deleted Records / Freelist Pages");
    assert!(freelist_meta.is_some());
    assert_eq!(freelist_meta.unwrap().1, "12 pages (Recoverable Deleted Rows)");
}
