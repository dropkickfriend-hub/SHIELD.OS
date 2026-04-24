import {registerPlugin} from '@capacitor/core';
import type {Capabilities, ProcessEntry, NetworkConnection, WifiScanResult, KillResult} from './types';

interface ShieldNative {
  listInstalledApps(): Promise<{apps: RawApp[]}>;
  uninstallApp(options: {packageName: string}): Promise<{ok: boolean; message: string}>;
  scanWifi(): Promise<{results: RawWifi[]}>;
  listConnections(): Promise<{connections: NetworkConnection[]}>;
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

const Shield = registerPlugin<ShieldNative>('Shield');

const mapWifi = (w: RawWifi): WifiScanResult => {
  const ch = w.frequency >= 2412 && w.frequency <= 2484
    ? Math.round((w.frequency - 2407) / 5)
    : w.frequency >= 5170 ? Math.round((w.frequency - 5000) / 5) : undefined;
  const openNet = !/WEP|WPA|SAE/i.test(w.capabilities);
  return {
    ssid: w.ssid || '(hidden)',
    bssid: w.bssid,
    rssi: w.level,
    channel: ch,
    encryption: openNet ? 'OPEN' : (w.capabilities.match(/WPA3|WPA2|WPA|WEP/)?.[0] ?? 'UNKNOWN'),
    suspicious: openNet || w.level > -30,
  };
};

export const androidCapabilities: Capabilities = {
  platform: 'android',
  supports: {
    realProcesses: true,
    killProcess: true,
    networkMonitor: true,
    wifiScan: true,
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
    const {connections} = await Shield.listConnections();
    return connections ?? [];
  },
  async scanWifi(): Promise<WifiScanResult[]> {
    const {results} = await Shield.scanWifi();
    return results.map(mapWifi);
  },
};
