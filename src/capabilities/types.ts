export type Platform = 'web' | 'desktop' | 'android';

export interface ProcessEntry {
  id: string;
  name: string;
  label?: string;
  cpu?: number;
  mem?: number;
  status: 'running' | 'sleeping' | 'suspended' | 'installed';
  connections: string[];
  flagged?: boolean;
  flagReason?: string;
  extra?: Record<string, unknown>;
}

export interface NetworkConnection {
  localAddr: string;
  remoteAddr: string;
  state: string;
  pid?: number;
  processName?: string;
}

export interface WifiScanResult {
  ssid: string;
  bssid: string;
  rssi: number;
  channel?: number;
  encryption?: string;
  suspicious?: boolean;
}

export interface KillResult {
  ok: boolean;
  message: string;
}

export interface Capabilities {
  platform: Platform;
  supports: {
    realProcesses: boolean;
    killProcess: boolean;
    networkMonitor: boolean;
    wifiScan: boolean;
    blockDomain: boolean;
  };
  listProcesses(): Promise<ProcessEntry[]>;
  killProcess(id: string): Promise<KillResult>;
  listConnections(): Promise<NetworkConnection[]>;
  scanWifi(): Promise<WifiScanResult[]>;
}
