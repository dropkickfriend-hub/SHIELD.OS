import {registerPlugin} from '@capacitor/core';
import type {
  Capabilities, ProcessEntry, NetworkConnection, WifiScanResult,
  BleDevice, KillResult, ScanReport, ScanFinding, ThreatIntelStats,
} from './types';

interface ShieldNative {
  listInstalledApps(): Promise<{apps: RawApp[]}>;
  uninstallApp(options: {packageName: string}): Promise<{ok: boolean; message: string}>;
  scanWifi(): Promise<{results: RawWifi[]}>;
  scanBle(): Promise<{devices: RawBle[]}>;
  listConnections(): Promise<{connections: Array<{localAddr: string; remoteAddr: string; state: string}>}>;
  scanApkHashes(options: {knownBadHashes: string[]}): Promise<{scanned: number; findings: RawApkFinding[]}>;
  fetchThreatIntel(): Promise<{bad_ips: number; bad_hashes: number}>;
}

interface RawApp {
  packageName: string;
  label: string;
  versionName?: string;
  installerPackage?: string;
  isSystem: boolean;
  dangerousPermissions: string[];
  suspicious: boolean;
  suspicionReason?: string;
  dataDir?: string;
}

interface RawWifi {
  ssid: string;
  bssid: string;
  level: number;
  frequency: number;
  capabilities: string;
}

interface RawBle {
  address: string;
  name: string;
  rssi: number;
  txPower: number;
  connectable: boolean;
}

interface RawApkFinding {
  packageName: string;
  label: string;
  path: string;
  sha256: string;
  sizeBytes: number;
  reason: string;
}

const Shield = registerPlugin<ShieldNative>('Shield');

const FIREHOL_URL = 'https://iplists.firehol.org/files/firehol_level1.netset';
const MB_RECENT_URL = 'https://bazaar.abuse.ch/export/csv/recent/';
const TTL_MS = 24 * 60 * 60 * 1000;

class IntelCache {
  badIps = new Set<string>();
  badCidrs: Array<[number, number]> = [];
  badHashes = new Set<string>();
  fetchedAt = 0;
  lastError?: string;

  isBadIp(ip: string): boolean {
    if (this.badIps.has(ip)) return true;
    const parsed = ipv4ToU32(ip);
    if (parsed == null) return false;
    return this.badCidrs.some(([net, mask]) => (parsed & mask) === net);
  }

  async refresh(): Promise<ThreatIntelStats> {
    if (Date.now() - this.fetchedAt < TTL_MS && (this.badIps.size || this.badHashes.size)) {
      return {badIps: this.badIps.size + this.badCidrs.length, badHashes: this.badHashes.size};
    }
    const errs: string[] = [];
    try {
      const body = await fetch(FIREHOL_URL).then((r) => r.text());
      this.badIps.clear();
      this.badCidrs.length = 0;
      for (const raw of body.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const slash = line.indexOf('/');
        if (slash >= 0) {
          const u = ipv4ToU32(line.slice(0, slash));
          const p = Number(line.slice(slash + 1));
          if (u != null && Number.isFinite(p) && p >= 0 && p <= 32) {
            const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
            this.badCidrs.push([(u & mask) >>> 0, mask]);
          }
        } else {
          this.badIps.add(line);
        }
      }
    } catch (e) { errs.push(`IP list: ${e}`); }
    try {
      const body = await fetch(MB_RECENT_URL).then((r) => r.text());
      this.badHashes.clear();
      for (const raw of body.split('\n')) {
        if (!raw || raw.startsWith('#')) continue;
        const cols = raw.split(',');
        if (cols.length < 3) continue;
        const hash = cols[2].replace(/"/g, '').toLowerCase();
        if (hash.length === 64 && /^[0-9a-f]+$/.test(hash)) this.badHashes.add(hash);
      }
    } catch (e) { errs.push(`Hash list: ${e}`); }
    this.fetchedAt = Date.now();
    this.lastError = errs.length ? errs.join('; ') : undefined;
    return {
      badIps: this.badIps.size + this.badCidrs.length,
      badHashes: this.badHashes.size,
      error: this.lastError,
    };
  }
}

const intel = new IntelCache();

function ipv4ToU32(s: string): number | null {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let u = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    u = ((u << 8) | n) >>> 0;
  }
  return u;
}

const mapWifi = (w: RawWifi): WifiScanResult => {
  const ch = w.frequency >= 2412 && w.frequency <= 2484
    ? Math.round((w.frequency - 2407) / 5)
    : w.frequency >= 5170 ? Math.round((w.frequency - 5000) / 5) : undefined;
  const openNet = !/WEP|WPA|SAE/i.test(w.capabilities);
  const enc = openNet ? 'OPEN' : (w.capabilities.match(/WPA3|WPA2|WPA|WEP/)?.[0] ?? 'UNKNOWN');
  const suspicious = openNet || w.level > -30;
  const reason = openNet ? 'Open (unencrypted) network'
    : w.level > -30 ? 'Very high RSSI — near-field device'
    : undefined;
  return {
    ssid: w.ssid || '(hidden)',
    bssid: w.bssid,
    rssi: w.level,
    channel: ch,
    encryption: enc,
    suspicious,
    reason,
  };
};

const isPrivate = (ip: string): boolean => {
  if (!ip) return false;
  if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.') || ip.startsWith('fe80:')) return true;
  if (ip.startsWith('172.')) {
    const second = Number(ip.split('.')[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
};

export const androidCapabilities: Capabilities = {
  platform: 'android',
  supports: {
    realProcesses: true,
    killProcess: true,
    networkMonitor: true,
    wifiScan: true,
    bleScan: true,
    fileScan: true,
    blockDomain: false,
  },
  async listProcesses(): Promise<ProcessEntry[]> {
    const {apps} = await Shield.listInstalledApps();
    return apps.map((a) => ({
      id: a.packageName,
      name: a.packageName,
      label: a.label,
      status: 'installed',
      connections: [],
      flagged: a.suspicious,
      flagReason: a.suspicionReason,
      extra: {
        version: a.versionName,
        isSystem: a.isSystem,
        installer: a.installerPackage,
        dangerousPermissions: a.dangerousPermissions,
      },
    }));
  },
  async killProcess(id: string): Promise<KillResult> {
    return Shield.uninstallApp({packageName: id});
  },
  async listConnections(): Promise<NetworkConnection[]> {
    await intel.refresh().catch(() => {});
    const {connections} = await Shield.listConnections();
    return (connections ?? []).map((c) => {
      const remoteIp = c.remoteAddr.split(':').slice(0, -1).join(':').replace(/^\[|\]$/g, '');
      const severity: NetworkConnection['severity'] = isPrivate(remoteIp)
        ? 'safe'
        : intel.isBadIp(remoteIp) ? 'malicious' : 'unknown';
      return {
        localAddr: c.localAddr,
        remoteAddr: c.remoteAddr,
        state: c.state,
        protocol: 'TCP',
        severity,
        reason: severity === 'malicious' ? 'FireHOL Level 1 hit'
          : severity === 'safe' ? 'RFC1918/private' : undefined,
      };
    });
  },
  async scanWifi(): Promise<WifiScanResult[]> {
    const {results} = await Shield.scanWifi();
    return results.map(mapWifi);
  },
  async scanBle(): Promise<BleDevice[]> {
    const {devices} = await Shield.scanBle();
    return devices.map((d) => ({
      address: d.address,
      name: d.name || undefined,
      rssi: d.rssi,
      txPower: d.txPower,
      connectable: d.connectable,
    }));
  },
  async scanFiles(): Promise<ScanReport> {
    await intel.refresh().catch(() => {});
    const hashes = Array.from(intel.badHashes);
    const res = await Shield.scanApkHashes({knownBadHashes: hashes});
    const findings: ScanFinding[] = res.findings.map((f) => ({
      path: f.path,
      sha256: f.sha256,
      size: f.sizeBytes,
      reason: f.reason,
      packageName: f.packageName,
      label: f.label,
    }));
    return {
      root: '/ (installed APKs)',
      filesScanned: res.scanned,
      bytesScanned: 0,
      durationMs: 0,
      findings,
    };
  },
  async refreshThreatIntel(): Promise<ThreatIntelStats> {
    return intel.refresh();
  },
};
