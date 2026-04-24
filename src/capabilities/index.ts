import type {Capabilities} from './types';
import {webCapabilities} from './web';
import {tauriCapabilities} from './tauri';
import {androidCapabilities} from './android';

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
    __TAURI__?: unknown;
    Capacitor?: {
      isNativePlatform: () => boolean;
      getPlatform: () => string;
    };
  }
}

const detect = (): Capabilities => {
  if (typeof window === 'undefined') return webCapabilities;
  if (window.__TAURI_INTERNALS__ || window.__TAURI__) return tauriCapabilities;
  if (window.Capacitor?.isNativePlatform?.() && window.Capacitor.getPlatform() === 'android') {
    return androidCapabilities;
  }
  return webCapabilities;
};

export const capabilities = detect();
export type {Capabilities, ProcessEntry, NetworkConnection, WifiScanResult, KillResult, Platform} from './types';
