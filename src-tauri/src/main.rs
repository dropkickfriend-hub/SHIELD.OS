#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod connections;
mod processes;
mod scanner;
mod threats;

fn main() {
    let threat_handle = threats::ThreatHandle::new();
    // Warm up the cache on launch so the first call doesn't block the UI.
    {
        let h = threat_handle.clone();
        std::thread::spawn(move || h.ensure_loaded());
    }

    tauri::Builder::default()
        .manage(threat_handle)
        .invoke_handler(tauri::generate_handler![
            processes::list_processes,
            processes::kill_process,
            connections::list_connections,
            scanner::scan_path,
            threats::refresh_threat_intel,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
