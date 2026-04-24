#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod processes;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            processes::list_processes,
            processes::kill_process,
            processes::list_connections,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
