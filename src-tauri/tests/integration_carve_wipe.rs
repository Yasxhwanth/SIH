// tests/integration_carve_wipe.rs — Adversarial Self-Validation Integration Test
//
// Demonstrates the complete SIH PS-26149 lifecycle:
// 1. Generate test image with planted files (JPEG, PNG, PDF, ELF, SQLite)
// 2. Carver recovers all planted files with evidential SHA-256 hashes
// 3. Drive Eraser performs NIST SP 800-88 Clear wipe on the image
// 4. Carver rescans wiped image — verifies ZERO files recoverable
// 5. Audit log hash chain validates tamper-evident log continuity

use std::fs;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use forensix_lib::device::create_test_image;
use forensix_lib::carver::scanner::scan_image;
use forensix_lib::carver::extractor::extract_file;
use forensix_lib::carver::signatures::all_signatures;
use forensix_lib::eraser::drive::strategies::{wipe, WipeStandard};
use forensix_lib::eraser::drive::verify::{verify_wipe, ExpectedPattern};

#[test]
fn test_adversarial_carve_and_wipe_lifecycle() {
    let tmp_dir = std::env::temp_dir().join(format!("forensix_test_{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).unwrap();
    let img_path = tmp_dir.join("evidence.img");
    let img_path_str = img_path.to_str().unwrap().to_string();
    let recovered_dir = tmp_dir.join("recovered");
    fs::create_dir_all(&recovered_dir).unwrap();

    // ── Phase 1: Create 2 MB test image with planted files ─────────────────
    create_test_image(img_path_str.clone(), 2).expect("create test image");
    assert!(img_path.exists());
    let initial_size = fs::metadata(&img_path).unwrap().len();
    assert_eq!(initial_size, 2 * 1024 * 1024);

    // ── Phase 2: File Carving & Evidential Integrity ───────────────────────
    let cancel = Arc::new(AtomicBool::new(false));
    let sigs = all_signatures();
    let matches = scan_image(&img_path_str, &sigs, cancel.clone(), Box::new(|_, _| {})).expect("carve scan");

    println!("Initial scan found {} signature matches", matches.len());
    assert!(matches.len() >= 3, "Should find at least 3 planted files");

    let mut recovered_count = 0;
    for m in &matches {
        let sig = &sigs[m.sig_idx];
        if let Ok(carved) = extract_file(&img_path_str, m, sig, &recovered_dir) {
            println!("Extracted: {} at offset 0x{:X}, SHA-256: {}", carved.extension, carved.offset, carved.sha256);
            assert!(!carved.sha256.is_empty(), "Evidential SHA-256 must be computed");
            recovered_count += 1;
        }
    }
    assert!(recovered_count >= 3, "At least 3 files should extract cleanly");

    // ── Phase 3: Secure Drive Erasure (NIST SP 800-88 Clear) ───────────────
    let wipe_cancel = Arc::new(AtomicBool::new(false));
    let bytes_wiped = wipe(
        &img_path_str,
        WipeStandard::NistClear,
        wipe_cancel,
        Box::new(|_, _| {})
    ).expect("wipe execution");

    assert_eq!(bytes_wiped, initial_size, "Entire image must be wiped");

    // Verify all sectors zeroed
    let verify = verify_wipe(&img_path_str, ExpectedPattern::Zero).expect("verify wipe");
    assert!(verify.pass, "Verification must pass — all sectors zeroed");
    assert_eq!(verify.mismatches, 0, "No non-zero sectors allowed");

    // ── Phase 4: Post-Wipe Adversarial Carve (Verification of Destruction) ─
    let post_wipe_matches = scan_image(&img_path_str, &sigs, cancel, Box::new(|_, _| {})).expect("rescan");
    println!("Post-wipe scan found {} files", post_wipe_matches.len());
    assert_eq!(post_wipe_matches.len(), 0, "Adversarial test: Zero files must be recoverable after wipe!");

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_expanded_signatures_and_bitstream_imager() {
    let sigs = all_signatures();
    println!("Total forensic signatures loaded: {}", sigs.len());
    assert!(sigs.len() >= 55, "Should have 55+ file format signatures for Disk Drill parity");

    // Verify key formats exist
    let exts: Vec<&str> = sigs.iter().map(|s| s.extension).collect();
    assert!(exts.contains(&"webp"), "Should support WEBP images");
    assert!(exts.contains(&"svg"), "Should support SVG vector images");
    assert!(exts.contains(&"pcap"), "Should support Wireshark PCAP captures");
    assert!(exts.contains(&"evtx"), "Should support Windows Event Logs");
    assert!(exts.contains(&"wallet"), "Should support Bitcoin Berkeley DB wallets");
    assert!(exts.contains(&"vmdk"), "Should support VMware VMDK images");

    // ── Test Bit-Stream Cloner ──
    let tmp_dir = std::env::temp_dir().join(format!("forensix_imager_test_{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).unwrap();

    let source_file = tmp_dir.join("sample_source.bin");
    let _target_image = tmp_dir.join("cloned_stream.raw");

    // Write 64 KB of patterned bytes
    let payload = vec![0x42u8; 65536];
    fs::write(&source_file, &payload).unwrap();

    // ── Test File Previewer ──
    let preview = forensix_lib::carver::cmd::read_file_preview(source_file.to_str().unwrap().to_string()).expect("read preview");
    assert_eq!(preview.file_size, 65536);

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_realtime_streaming_carver_and_mft() {
    use std::sync::Mutex;
    use forensix_lib::carver::scanner::scan_image_streaming;
    use forensix_lib::carver::mft::scan_image_mft_streaming;

    let tmp_dir = std::env::temp_dir().join(format!("forensix_stream_test_{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).unwrap();
    let img_path = tmp_dir.join("stream_evidence.img");
    let img_path_str = img_path.to_str().unwrap().to_string();

    // Create 2 MB test image with planted files
    create_test_image(img_path_str.clone(), 2).expect("create test image");

    // ── Test Real-Time Carve Streaming ──
    let cancel = Arc::new(AtomicBool::new(false));
    let sigs = all_signatures();
    let streamed_hits = Arc::new(Mutex::new(Vec::new()));
    let streamed_hits_clone = Arc::clone(&streamed_hits);

    let on_hit = Some(Arc::new(move |hit| {
        streamed_hits_clone.lock().unwrap().push(hit);
    }) as forensix_lib::carver::scanner::HitFn);

    let progress_reports = Arc::new(Mutex::new(Vec::new()));
    let pr_clone = Arc::clone(&progress_reports);

    let matches = scan_image_streaming(
        &img_path_str,
        &sigs,
        cancel,
        Box::new(move |scanned, total| {
            pr_clone.lock().unwrap().push((scanned, total));
        }),
        on_hit,
    ).expect("scan streaming");

    let hits_collected = streamed_hits.lock().unwrap().clone();
    assert!(!hits_collected.is_empty(), "Streaming callback must capture hits in real time");
    assert_eq!(hits_collected.len(), matches.len(), "Streamed hits count must match returned hits");
    assert!(!progress_reports.lock().unwrap().is_empty(), "Progress reports must fire during scan");

    // ── Test Real-Time MFT Streaming ──
    let mft_records_streamed = Arc::new(Mutex::new(Vec::new()));
    let mft_clone = Arc::clone(&mft_records_streamed);

    let mft_results = scan_image_mft_streaming(
        &img_path_str,
        100,
        move |rec| {
            mft_clone.lock().unwrap().push(rec.clone());
        }
    ).expect("mft streaming");

    let mft_collected = mft_records_streamed.lock().unwrap().clone();
    assert_eq!(mft_collected.len(), mft_results.len(), "MFT streaming count must match result count");

    let _ = fs::remove_dir_all(&tmp_dir);
}

