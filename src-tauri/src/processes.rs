use serde::Serialize;
use sysinfo::{Pid, ProcessStatus, ProcessesToUpdate, System};

#[derive(Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu: f32,
    pub mem_mb: f32,
    pub status: String,
    pub cmd: String,
    pub connections: Vec<String>,
    pub flagged: bool,
    pub flag_reason: Option<String>,
}

fn status_label(s: ProcessStatus) -> &'static str {
    match s {
        ProcessStatus::Run => "running",
        ProcessStatus::Sleep | ProcessStatus::Idle => "sleeping",
        ProcessStatus::Stop => "stopped",
        ProcessStatus::Zombie => "zombie",
        _ => "unknown",
    }
}

// Names that, when present in non-system directories, are classic stalker/crypto-miner patterns.
const SUSPICIOUS_SUBSTRINGS: &[&str] = &[
    "xmrig", "cpuminer", "nheqminer", "nicehash",
    "mimikatz", "procdump", "rundll32_inj",
    "keylog", "spyware", "teamviewer_unattended",
];

fn classify(name_lower: &str, cmd_lower: &str, cpu: f32) -> (bool, Option<String>) {
    for needle in SUSPICIOUS_SUBSTRINGS {
        if name_lower.contains(needle) || cmd_lower.contains(needle) {
            return (true, Some(format!("matches known-bad pattern '{}'", needle)));
        }
    }
    if cpu > 85.0 && !name_lower.contains("code") && !name_lower.contains("chrome")
        && !name_lower.contains("firefox") && !name_lower.contains("rustc")
        && !name_lower.contains("node") && !name_lower.contains("cl.exe")
    {
        return (true, Some("sustained CPU > 85% on non-whitelisted binary".into()));
    }
    (false, None)
}

#[tauri::command]
pub async fn list_processes() -> Result<Vec<ProcessInfo>, String> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    // Second refresh so CPU deltas are meaningful; sysinfo needs two samples.
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut out = Vec::with_capacity(sys.processes().len());
    for (pid, proc_) in sys.processes() {
        let name = proc_.name().to_string_lossy().to_string();
        let cmd_path = proc_
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cpu = proc_.cpu_usage();
        let (flagged, reason) = classify(&name.to_lowercase(), &cmd_path.to_lowercase(), cpu);

        out.push(ProcessInfo {
            pid: pid.as_u32(),
            name,
            cpu,
            mem_mb: (proc_.memory() as f32) / (1024.0 * 1024.0),
            status: status_label(proc_.status()).to_string(),
            cmd: cmd_path,
            connections: Vec::new(),
            flagged,
            flag_reason: reason,
        });
    }
    out.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
    Ok(out)
}

#[tauri::command]
pub async fn kill_process(pid: u32) -> Result<String, String> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let proc_ = sys
        .process(Pid::from_u32(pid))
        .ok_or_else(|| format!("PID {} not found", pid))?;
    let name = proc_.name().to_string_lossy().to_string();
    if proc_.kill() {
        Ok(format!("Killed {} (pid {}).", name, pid))
    } else {
        Err(format!("Failed to kill {} (pid {}) — insufficient privileges?", name, pid))
    }
}

