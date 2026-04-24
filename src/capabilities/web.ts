import type {
  Capabilities, ProcessEntry, NetworkConnection, WifiScanResult,
  BleDevice, KillResult, ScanReport, ThreatIntelStats,
} from './types';

const mockProcesses: string[] = [
  'kernel_task', 'launchd', 'securityd', 'WindowServer',
  'com.android.chrome', 'system_server', 'zygote64', 'adbd',
  'com.droid.sentry', 'networkstack', 'dns_resolver', 'remote_trace',
];

export const webCapabilities: Capabilities = {
  platform: 'web',
  supports: {
    realProcesses: false,
    killProcess: false,
    networkMonitor: false,
    wifiScan: false,
    bleScan: false,
    fileScan: false,
    blockDomain: false,
  },
  async listProcesses(): Promise<ProcessEntry[]> {
    return mockProcesses.map((name) => ({
      id: String(Math.floor(Math.random() * 9000) + 100),
      name,
      cpu: Math.random() * 5,
      mem: Math.random() * 300,
      status: Math.random() > 0.8 ? 'sleeping' : 'running',
      connections: Math.random() > 0.7
        ? [`${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.0.1:443`]
        : [],
    }));
  },
  async killProcess(): Promise<KillResult> {
    return {ok: false, message: 'Kill unavailable in browser demo mode.'};
  },
  async listConnections(): Promise<NetworkConnection[]> { return []; },
  async scanWifi(): Promise<WifiScanResult[]> { return []; },
  async scanBle(): Promise<BleDevice[]> { return []; },
  async scanFiles(): Promise<ScanReport> {
    return {root: '', filesScanned: 0, bytesScanned: 0, durationMs: 0, findings: []};
  },
  async refreshThreatIntel(): Promise<ThreatIntelStats> {
    return {badIps: 0, badHashes: 0, error: 'Threat intel disabled in browser demo.'};
  },
};
