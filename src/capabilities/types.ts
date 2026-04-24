export type Platform = 'web' | 'desktop' | 'android';

export type Severity = 'unknown' | 'safe' | 'suspicious' | 'malicious';

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
  protocol: string;
  pid?: number;
  processName?: string;
  severity: Severity;
  reason?: string;
}

export interface WifiScanResult {
  ssid: string;
  bssid: string;
  rssi: number;
  channel?: number;
  encryption?: string;
  suspicious?: boolean;
  reason?: string;
}

export interface BleDevice {
  address: string;
  name?: string;
  rssi: number;
  txPower?: number;
  connectable?: boolean;
}

export interface KillResult {
  ok: boolean;
  message: string;
}

export interface ScanFinding {
  path: string;
  sha256: string;
  size?: number;
  reason: string;
  packageName?: string;
  label?: string;
}

export interface ScanReport {
  root: string;
  filesScanned: number;
  bytesScanned: number;
  durationMs: number;
  findings: ScanFinding[];
}

export interface ThreatIntelStats {
  badIps: number;
  badHashes: number;
  error?: string;
}

export interface Capabilities {
  platform: Platform;
  supports: {
    realProcesses: boolean;
    killProcess: boolean;
    networkMonitor: boolean;
    wifiScan: boolean;
    bleScan: boolean;
    fileScan: boolean;
    blockDomain: boolean;
  };
  listProcesses(): Promise<ProcessEntry[]>;
  killProcess(id: string): Promise<KillResult>;
  listConnections(): Promise<NetworkConnection[]>;
  scanWifi(): Promise<WifiScanResult[]>;
  scanBle(): Promise<BleDevice[]>;
  scanFiles(path?: string, knownBadHashes?: string[]): Promise<ScanReport>;
  refreshThreatIntel(): Promise<ThreatIntelStats>;
}
