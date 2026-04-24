import React, { useState } from 'react';
import { BookOpen, Radio, Eye, Keyboard, Wifi, Lock, Smartphone, Shield } from 'lucide-react';
import { cn } from '../lib/utils';

interface Tactic {
  title: string;
  body: string;
  refs?: string[];
}

interface Section {
  id: string;
  title: string;
  icon: React.ReactNode;
  tactics: Tactic[];
}

const PLAYBOOK: Section[] = [
  {
    id: 'rf',
    title: 'RF & Tracker Countermeasures',
    icon: <Radio size={14} />,
    tactics: [
      {
        title: 'Run a passive SDR sweep',
        body:
          'Use an RTL-SDR ($30–$40) with software like Khanfar Spectrum Analyzer, CubicSDR, or GQRX to sweep 24MHz–1.7GHz. Repeat sweeps at different physical locations — hidden transmitters stay put while legitimate RF moves.',
        refs: ['RTL-SDR', 'CubicSDR'],
      },
      {
        title: 'Use phase-based direction finding',
        body:
          'KrakenSDR or a 4-antenna coherent receiver gives real bearings on an unknown emitter. Combine two bearings from different spots to triangulate (same math this app visualises).',
      },
      {
        title: 'Carry a Faraday sleeve for quarantine',
        body:
          'If you discover a tracker, drop it in a Faraday pouch rather than destroying it — it stops emissions while you preserve evidence and move out of its last reported cell.',
      },
      {
        title: 'Audit for AirTags / Tile / Bluetooth beacons',
        body:
          'iOS: Find My → Items → Identify Found Item. Android: AirGuard, Google "Unknown Tracker Alerts". Both identify unpaired BLE beacons that have been near you ≥10 minutes.',
      },
    ],
  },
  {
    id: 'imsi',
    title: 'IMSI Catcher / Cell-Site Surveillance',
    icon: <Wifi size={14} />,
    tactics: [
      {
        title: 'Deploy EFF Rayhunter',
        body:
          'Rayhunter runs on a $20 mobile hotspot and flags suspicious base-station behavior in real time: 2G downgrades, forced IMSI requests, anomalous cell changes.',
        refs: ['EFF Rayhunter'],
      },
      {
        title: 'Lock your modem to 4G/5G only',
        body:
          'Android Dialer: *#*#4636#*#* → Phone Info → set Preferred Network Type to LTE/NR Only. On iOS: Settings → Cellular → Data Mode → disable 2G/3G fallback where available.',
      },
      {
        title: 'Prefer signed messaging over SMS',
        body:
          'IMSI catchers trivially intercept SMS and 2G voice. Signal, iMessage, RCS E2E (beta) are immune to base-station MITM.',
      },
      {
        title: 'Watch for coverage anomalies',
        body:
          'Unexpected signal-strength jumps, new towers in static locations, and random "No Service" bursts are classic stingray signatures. Note them, move 200m, and retest.',
      },
    ],
  },
  {
    id: 'keylog',
    title: 'Keylogger / Input Capture',
    icon: <Keyboard size={14} />,
    tactics: [
      {
        title: 'Use a hardware security key for the big accounts',
        body:
          'YubiKey, Passkeys, or Titan mean a captured password is useless without the physical key. Phishing-resistant WebAuthn is the single biggest win against a keylogger.',
      },
      {
        title: 'Audit startup entries & accessibility services',
        body:
          'On macOS: Activity Monitor + Login Items. On Windows: Task Manager → Startup. On Android: Settings → Accessibility — any unknown service with keystroke access is a high-probability keylogger.',
      },
      {
        title: 'Run an anti-keylogger scanner',
        body:
          'GhostPress, KeyScrambler, SpyShelter encrypt keystrokes at the driver level. Malwarebytes and ESET both carry signatures for common commercial loggers (Ardamax, Spytector, Refog).',
      },
      {
        title: 'Watch for latency spikes',
        body:
          'User-mode keyloggers add 20–80ms to keydown→keyup latency. The Surveillance panel in this app measures exactly that.',
      },
    ],
  },
  {
    id: 'screen',
    title: 'Screen Mirror / Remote View',
    icon: <Eye size={14} />,
    tactics: [
      {
        title: 'Kill unwanted cast receivers',
        body:
          'macOS: System Settings → General → AirDrop & Handoff → AirPlay Receiver = Off. Windows: Settings → System → Projecting to this PC = Always Off. Android: Settings → Connected Devices → Cast — revoke.',
      },
      {
        title: 'Audit RMM & remote-support agents',
        body:
          'TeamViewer, AnyDesk, Splashtop, RustDesk all persist as background services. If you didn\'t install it, remove it — attackers frequently pre-install legit RMM tools as a backdoor.',
      },
      {
        title: 'Enforce per-app screen recording permission',
        body:
          'macOS Sonoma+: System Settings → Privacy & Security → Screen Recording. iOS 17+: Settings → Privacy → Screen Recording. Remove any app you don\'t actively use.',
      },
      {
        title: 'Watch for the green/orange dot',
        body:
          'iOS/macOS and newer Android show a persistent indicator when mic, camera, or screen capture is live. If it lights up when you\'re idle — something is watching.',
      },
    ],
  },
  {
    id: 'stalker',
    title: 'Stalkerware / Spyware',
    icon: <Smartphone size={14} />,
    tactics: [
      {
        title: 'Check for Device Admin / MDM profiles',
        body:
          'Android: Settings → Security → Device admin apps. iOS: Settings → General → VPN & Device Management. If an unknown profile grants full device control — it is almost always malicious.',
      },
      {
        title: 'Factory reset is the nuke from orbit',
        body:
          'Most commercial stalkerware (mSpy, FlexiSpy, Cocospy) can\'t survive a full factory reset + password rotation. Rotate every account password from a clean device afterward.',
      },
      {
        title: 'Enable Google Play Protect real-time scan',
        body:
          '2026 Play Protect runs on-device ML that flags stalkerware behavior even for sideloaded APKs. Keep "Scan apps with Play Protect" and "Improve harmful app detection" both on.',
      },
      {
        title: 'Use Lockdown / Advanced Protection Mode',
        body:
          'iOS Lockdown Mode and Android Advanced Protection disable the exact attack surfaces 0-click exploits use (message previews, USB data, webkit JIT, attachments).',
      },
    ],
  },
  {
    id: 'net',
    title: 'Network & Port Forwarding',
    icon: <Wifi size={14} />,
    tactics: [
      {
        title: 'Audit UPnP / NAT-PMP rules on your router',
        body:
          'UPnP lets malware silently open inbound ports. Log into your router, disable UPnP, and inspect "Port Forwarding" for entries you didn\'t create. The Network panel in this app surfaces that list.',
      },
      {
        title: 'Block outbound to known C2 ranges',
        body:
          'Use Pi-hole + firewall rules + DNS over HTTPS to a filtering resolver (NextDNS, Quad9). Block outbound on 4444, 5555, 6666, 31337 unless justified.',
      },
      {
        title: 'Run tailscale/wireguard instead of port-forwards',
        body:
          'Never expose a service with port forwarding when a zero-trust tunnel gives you the same reach with no listening port facing the internet.',
      },
    ],
  },
  {
    id: 'baseline',
    title: 'Baseline Hardening',
    icon: <Shield size={14} />,
    tactics: [
      {
        title: 'Full-disk encryption + strong login',
        body:
          'FileVault (macOS), BitLocker (Windows Pro), Android default, iOS default. Long passphrase, not a 4-digit PIN. Biometrics only on trusted secure-enclave hardware.',
      },
      {
        title: 'OS + firmware updates within 7 days',
        body:
          'Most in-the-wild spyware drops are patched in-cycle. A 30-day-old phone is already past most 0-day windows.',
      },
      {
        title: 'Separate identities for different threat levels',
        body:
          'Work profile, personal profile, burner profile — Android work profile or iOS Focus Filters give you hard separation of apps, accounts, notifications.',
      },
      {
        title: 'Hardware 2FA everywhere it matters',
        body:
          'Email, cloud, finance, code-signing. If you only put it on one account, put it on the email that resets everything else.',
      },
    ],
  },
];

interface Props {
  addLog?: (msg: string, level?: 'info' | 'warn' | 'error' | 'success', category?: string) => void;
}

export const DefensePlaybookPanel: React.FC<Props> = () => {
  const [openId, setOpenId] = useState<string>('rf');
  const section = PLAYBOOK.find(s => s.id === openId) || PLAYBOOK[0];

  return (
    <div className="space-y-6">
      <div className="bg-[#111] border border-[#00ff41] p-8">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Defense.Playbook</h2>
            <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">
              Vetted counter-surveillance tactics from EFF, NSA, CrowdStrike, Bitdefender & field research.
            </p>
          </div>
          <BookOpen size={32} className="text-[#00ff41]/20" />
        </div>

        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 md:col-span-4 space-y-1">
            {PLAYBOOK.map(s => (
              <button
                key={s.id}
                onClick={() => setOpenId(s.id)}
                className={cn(
                  'w-full flex items-center gap-2 p-3 text-left text-[11px] font-black uppercase tracking-widest border transition-all',
                  openId === s.id
                    ? 'bg-[#00ff41] text-black border-[#00ff41]'
                    : 'border-[#00ff41]/20 text-[#00ff41]/70 hover:border-[#00ff41]'
                )}
              >
                {s.icon}
                <span className="truncate">{s.title}</span>
              </button>
            ))}
          </div>
          <div className="col-span-12 md:col-span-8">
            <div className="bg-[#0a0a0a] border border-[#00ff41] p-6 h-full">
              <div className="flex items-center gap-3 mb-5 border-b border-[#00ff41]/30 pb-2">
                {section.icon}
                <h3 className="text-lg font-black tracking-tighter uppercase leading-none">{section.title}</h3>
              </div>
              <div className="space-y-5">
                {section.tactics.map((t, i) => (
                  <div key={i} className="border-l-2 border-[#00ff41] pl-4">
                    <div className="text-xs font-black uppercase tracking-wide mb-1">
                      {String(i + 1).padStart(2, '0')} · {t.title}
                    </div>
                    <p className="text-[11px] leading-relaxed opacity-80">{t.body}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-[#111] border border-[#00ff41] p-6">
        <div className="flex items-center gap-3 mb-4 border-b border-[#00ff41]/30 pb-2">
          <Lock size={14} />
          <h3 className="text-xs font-black uppercase tracking-[0.3em]">Canonical References</h3>
        </div>
        <ul className="space-y-2 text-[11px] opacity-80">
          <li>• NSA Mobile Device Best Practices — arcyber.army.mil</li>
          <li>• EFF Rayhunter (IMSI-catcher detector) — eff.org/deeplinks</li>
          <li>• EFF Street Level Surveillance — sls.eff.org</li>
          <li>• AV-Comparatives Stalkerware Test 2025 — av-comparatives.org</li>
          <li>• CrowdStrike, Fortinet, Bitdefender keylogger/stalkerware guidance</li>
          <li>• Khanfar / RTL-SDR community — khanfar-spectrum-analyzer.web.app</li>
        </ul>
      </div>
    </div>
  );
};

export default DefensePlaybookPanel;
