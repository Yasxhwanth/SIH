// main.rs — Tauri application entry point

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod carver;
mod eraser;
mod report;
mod device;
mod forensics;
mod adversarial;
mod error;

use tauri::Manager;

fn main() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            // Device & Imaging
            device::list_devices,
            device::create_test_image,
            device::get_drive_diagnostics,
            device::imager::cmd::start_bitstream_image,
            device::imager::cmd::cancel_bitstream_image,
            // Carver & Artifacts
            carver::cmd::start_carve,
            carver::cmd::cancel_carve,
            carver::cmd::get_carve_results,
            carver::cmd::read_file_hex,
            carver::cmd::read_file_preview,
            carver::cmd::export_selected_artifacts,
            carver::cmd::get_signature_catalog,
            carver::mft::cmd::scan_filesystem_mft,
            carver::mft::cmd::extract_mft_record_file,
            // Forensics & Chain of Custody
            forensics::cmd::get_chain_of_custody,
            // Drive Eraser
            eraser::drive::cmd::start_drive_wipe,
            eraser::drive::cmd::get_wipe_standards,
            // File Eraser
            eraser::file::cmd::shred_paths,
            eraser::file::cmd::wipe_free_space,
            // Adversarial Verification Lab
            adversarial::run_adversarial_demo,
            // Report
            report::cmd::get_audit_log,
            report::cmd::verify_chain_integrity,
            report::cmd::get_merkle_root,
            report::cmd::anchor_blockchain,
            report::cmd::get_bsa_court_certificate,
            report::cmd::export_pdf_cert,
            report::cmd::export_forensic_report,
        ])
        .setup(|app| {
            let app_data = app.path().app_data_dir().expect("no app data dir");
            std::fs::create_dir_all(&app_data)?;
            report::init_audit_log(app_data)?;
            device::start_device_watcher(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running ForensiX");
}
