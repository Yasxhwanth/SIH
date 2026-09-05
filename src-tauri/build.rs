fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=forensix.exe.manifest");
        let manifest = include_str!("forensix.exe.manifest");
        let windows = tauri_build::WindowsAttributes::new().app_manifest(manifest);
        if let Err(e) = tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows)) {
            panic!("Tauri build error: {:?}", e);
        }
    }
    #[cfg(not(windows))]
    {
        tauri_build::build();
    }
}
