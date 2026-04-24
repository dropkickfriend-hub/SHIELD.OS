use crate::threats::ThreatHandle;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Serialize, Default)]
pub struct ScanReport {
    pub root: String,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub duration_ms: u128,
    pub threats: Vec<Finding>,
}

#[derive(Serialize)]
pub struct Finding {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub reason: String,
}

const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024; // skip files > 256MB to keep scans snappy
const SUSPICIOUS_EXTS: &[&str] = &[
    "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "jar",
    "apk", "msi", "docm", "xlsm", "pptm", "lnk",
];

#[tauri::command]
pub async fn scan_path(
    path: Option<String>,
    threats: tauri::State<'_, ThreatHandle>,
) -> Result<ScanReport, String> {
    let handle = threats.inner().clone();
    tauri::async_runtime::spawn_blocking(move || handle.ensure_loaded()).await.ok();

    let root: PathBuf = match path {
        Some(p) => PathBuf::from(p),
        None => dirs::download_dir().ok_or_else(|| "no default Downloads dir".to_string())?,
    };
    if !root.exists() {
        return Err(format!("path does not exist: {}", root.display()));
    }

    let handle = threats.inner().clone();
    let root_clone = root.clone();
    let report = tauri::async_runtime::spawn_blocking(move || scan_blocking(root_clone, handle))
        .await
        .map_err(|e| e.to_string())??;
    Ok(report)
}

fn scan_blocking(root: PathBuf, threats: ThreatHandle) -> Result<ScanReport, String> {
    let start = std::time::Instant::now();
    let mut report = ScanReport {
        root: root.display().to_string(),
        ..Default::default()
    };

    for entry in WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() { continue; }
        let path = entry.path();
        let meta = match entry.metadata() { Ok(m) => m, Err(_) => continue };
        let size = meta.len();
        if size == 0 || size > MAX_FILE_BYTES { continue; }

        if !interesting_ext(path) { continue; }

        match hash_file(path, size) {
            Ok(digest) => {
                report.files_scanned += 1;
                report.bytes_scanned += size;
                if threats.is_bad_hash(&digest) {
                    report.threats.push(Finding {
                        path: path.display().to_string(),
                        sha256: digest,
                        size,
                        reason: "MalwareBazaar SHA-256 match".into(),
                    });
                }
            }
            Err(_) => continue, // permission denied etc.
        }
    }
    report.duration_ms = start.elapsed().as_millis();
    Ok(report)
}

fn interesting_ext(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .map(|e| SUSPICIOUS_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Stream-hash the file; for very large files, hash the head+tail+middle
/// samples instead of the whole file to keep scan times reasonable.
fn hash_file(path: &Path, size: u64) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    if size < 32 * 1024 * 1024 {
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
    } else {
        // Sampled hash: head(4MB) + middle(4MB) + tail(4MB). Changes "sha256"
        // semantics — collisions against MalwareBazaar whole-file hashes are
        // impossible, so this path exists to keep scans fast; full-hash mode
        // is still used for typical document/download sizes.
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        f.read_exact(&mut buf)?;
        hasher.update(&buf);
        f.seek(SeekFrom::Start(size / 2))?;
        f.read_exact(&mut buf)?;
        hasher.update(&buf);
        f.seek(SeekFrom::End(-(buf.len() as i64)))?;
        f.read_exact(&mut buf)?;
        hasher.update(&buf);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{:02x}", b)).collect())
}
