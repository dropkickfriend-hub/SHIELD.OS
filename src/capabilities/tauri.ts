import {invoke} from '@tauri-apps/api/core';
import type {Capabilities, ProcessEntry, NetworkConnection, WifiScanResult, KillResult} from './types';

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
    try {
      return await invoke<NetworkConnection[]>('list_connections');
    } catch {
      return [];
    }
  },
  async scanWifi(): Promise<WifiScanResult[]> {
    return [];
  },
};
