use crate::threats::ThreatHandle;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use serde::Serialize;
use sysinfo::{Pid, ProcessesToUpdate, System};

#[derive(Serialize)]
pub struct Connection {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub protocol: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub severity: String, // "unknown" | "safe" | "suspicious" | "malicious"
    pub reason: Option<String>,
}

fn is_private(ip: &str) -> bool {
    ip == "127.0.0.1"
        || ip == "::1"
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("169.254.")
        || (ip.starts_with("172.") && {
            let second = ip.split('.').nth(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            (16..=31).contains(&second)
        })
        || ip.starts_with("0.0.0.0")
        || ip.starts_with("fe80:")
        || ip.starts_with("fc")
        || ip.starts_with("fd")
}

#[tauri::command]
pub async fn list_connections(
    threats: tauri::State<'_, ThreatHandle>,
) -> Result<Vec<Connection>, String> {
    let handle = threats.inner().clone();
    tauri::async_runtime::spawn_blocking(move || handle.ensure_loaded()).await.ok();

    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = get_sockets_info(af, proto).map_err(|e| e.to_string())?;

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut out = Vec::new();
    for si in sockets {
        let pid = si.associated_pids.first().copied();
        let process_name = pid.and_then(|p| sys.process(Pid::from_u32(p))).map(|p| p.name().to_string_lossy().to_string());

        let (local_addr, remote_addr, state, protocol) = match &si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(t) => (
                format!("{}:{}", t.local_addr, t.local_port),
                format!("{}:{}", t.remote_addr, t.remote_port),
                format!("{:?}", t.state),
                "TCP".to_string(),
            ),
            ProtocolSocketInfo::Udp(u) => (
                format!("{}:{}", u.local_addr, u.local_port),
                "*:*".to_string(),
                "OPEN".to_string(),
                "UDP".to_string(),
            ),
        };

        let remote_ip = remote_addr.rsplit_once(':').map(|(ip, _)| ip).unwrap_or("");
        let (severity, reason) = classify(remote_ip, &threats);

        out.push(Connection {
            local_addr,
            remote_addr,
            state,
            protocol,
            pid,
            process_name,
            severity,
            reason,
        });
    }

    // Malicious first, then suspicious, then active, then the rest.
    out.sort_by_key(|c| match c.severity.as_str() {
        "malicious" => 0,
        "suspicious" => 1,
        "safe" => 2,
        _ => 3,
    });
    Ok(out)
}

fn classify(remote_ip: &str, threats: &ThreatHandle) -> (String, Option<String>) {
    if remote_ip.is_empty() || remote_ip == "*" || remote_ip == "0.0.0.0" {
        return ("unknown".into(), None);
    }
    if is_private(remote_ip) {
        return ("safe".into(), Some("RFC1918/private".into()));
    }
    if threats.is_bad_ip(remote_ip) {
        return ("malicious".into(), Some("FireHOL Level 1 hit".into()));
    }
    ("unknown".into(), None)
}
