import {invoke} from '@tauri-apps/api/core';
import type {
  Capabilities, ProcessEntry, NetworkConnection, WifiScanResult,
  BleDevice, KillResult, ScanReport, ThreatIntelStats, Severity,
} from './types';

interface RawProcess {
  pid: number;
  name: string;
  cpu: number;
  mem_mb: number;
  status: string;
  connections: string[];
  cmd: string;
  flagged: boolean;
  flag_reason?: string;
}

interface RawConnection {
  local_addr: string;
  remote_addr: string;
  state: string;
  protocol: string;
  pid?: number;
  process_name?: string;
  severity: Severity;
  reason?: string;
}

interface RawScanReport {
  root: string;
  files_scanned: number;
  bytes_scanned: number;
  duration_ms: number;
  threats: Array<{path: string; sha256: string; size: number; reason: string}>;
}

const normalizeStatus = (s: string): ProcessEntry['status'] => {
  if (s === 'sleeping' || s === 'idle') return 'sleeping';
  if (s === 'stopped' || s === 'zombie') return 'suspended';
  return 'running';
};

export const tauriCapabilities: Capabilities = {
  platform: 'desktop',
  supports: {
    realProcesses: true,
    killProcess: true,
    networkMonitor: true,
    wifiScan: false,
    bleScan: false,
    fileScan: true,
    blockDomain: false,
  },
  async listProcesses(): Promise<ProcessEntry[]> {
    const raw = await invoke<RawProcess[]>('list_processes');
    return raw.map((p) => ({
      id: String(p.pid),
      name: p.name,
      cpu: p.cpu,
      mem: p.mem_mb,
      status: normalizeStatus(p.status),
      connections: p.connections,
      flagged: p.flagged,
      flagReason: p.flag_reason,
      extra: {cmd: p.cmd},
    }));
  },
  async killProcess(id: string): Promise<KillResult> {
    try {
      const msg = await invoke<string>('kill_process', {pid: Number(id)});
      return {ok: true, message: msg};
    } catch (e) {
      return {ok: false, message: String(e)};
    }
  },
  async listConnections(): Promise<NetworkConnection[]> {
    const raw = await invoke<RawConnection[]>('list_connections');
    return raw.map((c) => ({
      localAddr: c.local_addr,
      remoteAddr: c.remote_addr,
      state: c.state,
      protocol: c.protocol,
      pid: c.pid,
      processName: c.process_name,
      severity: c.severity,
      reason: c.reason,
    }));
  },
  async scanWifi(): Promise<WifiScanResult[]> { return []; },
  async scanBle(): Promise<BleDevice[]> { return []; },
  async scanFiles(path?: string): Promise<ScanReport> {
    const raw = await invoke<RawScanReport>('scan_path', {path: path ?? null});
    return {
      root: raw.root,
      filesScanned: raw.files_scanned,
      bytesScanned: raw.bytes_scanned,
      durationMs: raw.duration_ms,
      findings: raw.threats.map((t) => ({
        path: t.path,
        sha256: t.sha256,
        size: t.size,
        reason: t.reason,
      })),
    };
  },
  async refreshThreatIntel(): Promise<ThreatIntelStats> {
    const r = await invoke<{bad_ips: number; bad_hashes: number; error?: string}>('refresh_threat_intel');
    return {badIps: r.bad_ips, badHashes: r.bad_hashes, error: r.error};
  },
};
