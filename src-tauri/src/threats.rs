//! Threat-intel fetcher + 24h on-disk cache.
//!
//! Sources:
//! - FireHOL Level 1 IP blocklist (public, no key)
//!   https://iplists.firehol.org/files/firehol_level1.netset
//! - MalwareBazaar SHA-256 dump (last 7 days, CSV, no key)
//!   https://bazaar.abuse.ch/export/csv/recent/
//!
//! If the network fetch fails (offline, outage), classification falls back to
//! "unknown" — the app stays usable.

use parking_lot::RwLock;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const IP_URL: &str = "https://iplists.firehol.org/files/firehol_level1.netset";
const MB_URL: &str = "https://bazaar.abuse.ch/export/csv/recent/";
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Default)]
pub struct ThreatDb {
    pub bad_ips: HashSet<String>,
    pub bad_cidrs: Vec<(u32, u32)>, // (network, mask) for IPv4 CIDR entries
    pub bad_hashes: HashSet<String>, // lowercase SHA-256 hex
    pub fetched_at: Option<SystemTime>,
    pub last_error: Option<String>,
}

#[derive(Clone, Default)]
pub struct ThreatHandle(Arc<RwLock<ThreatDb>>);

impl ThreatHandle {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(ThreatDb::default())))
    }

    pub fn snapshot_stats(&self) -> (usize, usize, Option<String>) {
        let r = self.0.read();
        (r.bad_ips.len() + r.bad_cidrs.len(), r.bad_hashes.len(), r.last_error.clone())
    }

    pub fn is_bad_ip(&self, ip: &str) -> bool {
        let r = self.0.read();
        if r.bad_ips.contains(ip) { return true; }
        if let Ok(parsed) = ipv4_to_u32(ip) {
            return r.bad_cidrs.iter().any(|(net, mask)| (parsed & mask) == *net);
        }
        false
    }

    pub fn is_bad_hash(&self, sha256_hex: &str) -> bool {
        self.0.read().bad_hashes.contains(&sha256_hex.to_lowercase())
    }

    /// Load from cache if fresh, otherwise fetch. Non-fatal on failure.
    pub fn ensure_loaded(&self) {
        {
            let r = self.0.read();
            if let Some(at) = r.fetched_at {
                if at.elapsed().unwrap_or(Duration::MAX) < CACHE_TTL
                    && (!r.bad_ips.is_empty() || !r.bad_cidrs.is_empty() || !r.bad_hashes.is_empty())
                {
                    return;
                }
            }
        }
        let cache = cache_dir();
        let ip_cache = cache.join("firehol_level1.netset");
        let hash_cache = cache.join("mb_recent.csv");
        let _ = fs::create_dir_all(&cache);

        // IP list
        match fetch_with_cache(IP_URL, &ip_cache) {
            Ok(body) => {
                let (ips, cidrs) = parse_ipset(&body);
                let mut w = self.0.write();
                w.bad_ips = ips;
                w.bad_cidrs = cidrs;
                w.last_error = None;
            }
            Err(e) => {
                self.0.write().last_error = Some(format!("ip list fetch failed: {e}"));
            }
        }

        // Hash list
        match fetch_with_cache(MB_URL, &hash_cache) {
            Ok(body) => {
                let hashes = parse_mb_csv(&body);
                let mut w = self.0.write();
                w.bad_hashes = hashes;
            }
            Err(e) => {
                let mut w = self.0.write();
                // Append to last_error if there was already one.
                let prev = w.last_error.take().unwrap_or_default();
                w.last_error = Some(if prev.is_empty() {
                    format!("hash list fetch failed: {e}")
                } else {
                    format!("{prev}; hash list fetch failed: {e}")
                });
            }
        }

        self.0.write().fetched_at = Some(SystemTime::now());
    }
}

fn cache_dir() -> PathBuf {
    dirs::cache_dir().unwrap_or_else(|| std::env::temp_dir()).join("shield-os")
}

fn fetch_with_cache(url: &str, cache: &PathBuf) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("shield-os/0.1")
        .build()
        .map_err(|e| e.to_string())?;
    match client.get(url).send().and_then(|r| r.error_for_status()).and_then(|r| r.text()) {
        Ok(body) => {
            let _ = fs::write(cache, &body);
            Ok(body)
        }
        Err(_net_err) => {
            // Fall back to stale cache if present.
            fs::read_to_string(cache).map_err(|e| format!("no network and no cache: {e}"))
        }
    }
}

fn parse_ipset(body: &str) -> (HashSet<String>, Vec<(u32, u32)>) {
    let mut ips = HashSet::new();
    let mut cidrs = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') { continue; }
        if let Some((ip_str, prefix)) = l.split_once('/') {
            if let (Ok(ip), Ok(p)) = (ipv4_to_u32(ip_str), prefix.parse::<u32>()) {
                if p <= 32 {
                    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                    cidrs.push((ip & mask, mask));
                }
            }
        } else {
            ips.insert(l.to_string());
        }
    }
    (ips, cidrs)
}

fn ipv4_to_u32(s: &str) -> Result<u32, ()> {
    let mut parts = [0u32; 4];
    let mut idx = 0;
    for part in s.split('.') {
        if idx >= 4 { return Err(()); }
        parts[idx] = part.parse().map_err(|_| ())?;
        if parts[idx] > 255 { return Err(()); }
        idx += 1;
    }
    if idx != 4 { return Err(()); }
    Ok((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
}

fn parse_mb_csv(body: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in BufReader::new(body.as_bytes()).lines().flatten() {
        if line.starts_with('#') || line.trim().is_empty() { continue; }
        // MalwareBazaar CSV is quoted. Column 2 is sha256_hash.
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 3 { continue; }
        let hash = cols[2].trim_matches('"').to_lowercase();
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            out.insert(hash);
        }
    }
    out
}

#[tauri::command]
pub async fn refresh_threat_intel(state: tauri::State<'_, ThreatHandle>) -> Result<serde_json::Value, String> {
    let handle = state.inner().clone();
    let _ = tauri::async_runtime::spawn_blocking(move || handle.ensure_loaded()).await;
    let (ips, hashes, err) = state.snapshot_stats();
    Ok(serde_json::json!({ "bad_ips": ips, "bad_hashes": hashes, "error": err }))
}
