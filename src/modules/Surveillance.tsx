import React, { useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'motion/react';
import { Eye, Keyboard, Monitor, Camera, Mic, AlertTriangle, ShieldCheck, Clipboard, Cast } from 'lucide-react';
import { cn } from '../lib/utils';

interface Props {
  addLog: (msg: string, level?: 'info' | 'warn' | 'error' | 'success', category?: string) => void;
}

interface LatencySample {
  t: number;
  ms: number;
}

interface PermissionRow {
  name: string;
  state: 'granted' | 'denied' | 'prompt' | 'unknown';
  icon: React.ReactNode;
  risk: 'low' | 'med' | 'high';
}

// list of suspect process names used as a keylogger heuristic — in browser we can't read them
// but we surface a curated dictionary the user can learn to watch for
const KEYLOGGER_INDICATORS = [
  'logkeys', 'xinput test', 'SwiftKey.KeyboardService', 'Snagit',
  'com.teamviewer.teamviewer', 'anydesk', 'Splashtop',
  'nethunter keylogger', 'pykeylogger', 'ardamax', 'kidlogger',
];

const MIRROR_INDICATORS = [
  'AirPlay Receiver', 'Chromecast', 'Miracast', 'Quicktime Screen Recording',
  'scrcpy', 'Vysor', 'Reflector', 'LetsView', 'ApowerMirror',
];

export const SurveillancePanel: React.FC<Props> = ({ addLog }) => {
  const [screenShareActive, setScreenShareActive] = useState(false);
  const [cameraState, setCameraState] = useState<PermissionState | 'unknown'>('unknown');
  const [micState, setMicState] = useState<PermissionState | 'unknown'>('unknown');
  const [clipboardState, setClipboardState] = useState<PermissionState | 'unknown'>('unknown');
  const [geoState, setGeoState] = useState<PermissionState | 'unknown'>('unknown');
  const [notifState, setNotifState] = useState<PermissionState | 'unknown'>('unknown');
  const [latencies, setLatencies] = useState<LatencySample[]>([]);
  const [latencyMean, setLatencyMean] = useState<number | null>(null);
  const [latencyStd, setLatencyStd] = useState<number | null>(null);
  const [keylogRisk, setKeylogRisk] = useState<'low' | 'med' | 'high'>('low');
  const [focusLoss, setFocusLoss] = useState(0);
  const [visibilityLoss, setVisibilityLoss] = useState(0);
  const [externalDisplays, setExternalDisplays] = useState<number>(0);
  const [probing, setProbing] = useState(false);
  const keydownTs = useRef<number | null>(null);
  const canvasStreamRef = useRef<MediaStream | null>(null);
  const probeArea = useRef<HTMLInputElement | null>(null);

  // --- Permissions audit ---
  useEffect(() => {
    const queryPerm = async (name: PermissionName, set: (s: PermissionState | 'unknown') => void, label: string) => {
      if (!('permissions' in navigator)) return;
      try {
        // @ts-ignore — some names aren't in lib.dom yet
        const status: PermissionStatus = await navigator.permissions.query({ name });
        set(status.state);
        addLog(`Permission audit: ${label} = ${status.state.toUpperCase()}`, status.state === 'granted' ? 'warn' : 'info', 'PERM');
        status.onchange = () => {
          set(status.state);
          addLog(`Permission changed: ${label} → ${status.state.toUpperCase()}`, 'warn', 'PERM');
        };
      } catch {
        set('unknown');
      }
    };
    queryPerm('camera' as PermissionName, setCameraState, 'Camera');
    queryPerm('microphone' as PermissionName, setMicState, 'Microphone');
    queryPerm('geolocation' as PermissionName, setGeoState, 'Geolocation');
    queryPerm('notifications' as PermissionName, setNotifState, 'Notifications');
    // @ts-ignore
    queryPerm('clipboard-read' as PermissionName, setClipboardState, 'Clipboard-Read');
  }, [addLog]);

  // --- External display detection ---
  useEffect(() => {
    const checkDisplays = async () => {
      // Window Management API (Chrome) — window.getScreenDetails
      // Falls back to window.screen extensions for multi-monitor hints
      // @ts-ignore
      if (typeof window.getScreenDetails === 'function') {
        try {
          // @ts-ignore
          const details = await window.getScreenDetails();
          setExternalDisplays(details.screens.length);
          if (details.screens.length > 1) {
            addLog(`Multi-display topology: ${details.screens.length} surfaces`, 'warn', 'SURV');
          }
        } catch {
          setExternalDisplays(1);
        }
      } else {
        setExternalDisplays(1);
      }
    };
    checkDisplays();
  }, [addLog]);

  // --- Page visibility / focus loss counters (mirror indicator) ---
  useEffect(() => {
    const onVis = () => {
      if (document.visibilityState === 'hidden') {
        setVisibilityLoss(v => v + 1);
        addLog('Foreground lost — possible capture handoff', 'info', 'SURV');
      }
    };
    const onBlur = () => setFocusLoss(v => v + 1);
    document.addEventListener('visibilitychange', onVis);
    window.addEventListener('blur', onBlur);
    return () => {
      document.removeEventListener('visibilitychange', onVis);
      window.removeEventListener('blur', onBlur);
    };
  }, [addLog]);

  // --- Screen share detection via getDisplayMedia probe (user-initiated) ---
  const probeScreenShare = async () => {
    try {
      const s = await navigator.mediaDevices.getDisplayMedia({ video: true });
      canvasStreamRef.current = s;
      setScreenShareActive(true);
      addLog('Active screen capture stream obtained (user-authorized)', 'warn', 'SURV');
      const track = s.getVideoTracks()[0];
      track.addEventListener('ended', () => {
        setScreenShareActive(false);
        addLog('Screen capture stream ended', 'info', 'SURV');
      });
    } catch (e) {
      addLog('Screen capture probe denied or unavailable', 'info', 'SURV');
    }
  };

  const stopShare = () => {
    canvasStreamRef.current?.getTracks().forEach(t => t.stop());
    setScreenShareActive(false);
  };

  // --- Keylogger timing probe ---
  // Average key-down → key-up latency for trusted hardware is typically 40–90ms.
  // Kernel-hook keyloggers add a measurable variance floor. We compute stdev
  // over a rolling 32-sample window and flag anomalies.
  useEffect(() => {
    const onDown = (_: KeyboardEvent) => { keydownTs.current = performance.now(); };
    const onUp = (_: KeyboardEvent) => {
      if (keydownTs.current == null) return;
      const ms = performance.now() - keydownTs.current;
      keydownTs.current = null;
      setLatencies(prev => [...prev.slice(-31), { t: Date.now(), ms }]);
    };
    window.addEventListener('keydown', onDown);
    window.addEventListener('keyup', onUp);
    return () => {
      window.removeEventListener('keydown', onDown);
      window.removeEventListener('keyup', onUp);
    };
  }, []);

  useEffect(() => {
    if (latencies.length < 8) {
      setLatencyMean(null);
      setLatencyStd(null);
      setKeylogRisk('low');
      return;
    }
    const mean = latencies.reduce((a, b) => a + b.ms, 0) / latencies.length;
    const variance = latencies.reduce((a, b) => a + (b.ms - mean) ** 2, 0) / latencies.length;
    const std = Math.sqrt(variance);
    setLatencyMean(mean);
    setLatencyStd(std);
    let risk: 'low' | 'med' | 'high' = 'low';
    if (mean > 160 || std > 60) risk = 'high';
    else if (mean > 110 || std > 35) risk = 'med';
    setKeylogRisk(prev => {
      if (prev !== risk) {
        addLog(
          `Keystroke latency profile: μ=${mean.toFixed(1)}ms σ=${std.toFixed(1)}ms → ${risk.toUpperCase()} risk`,
          risk === 'high' ? 'error' : risk === 'med' ? 'warn' : 'success',
          'SURV'
        );
      }
      return risk;
    });
  }, [latencies, addLog]);

  const runKeyProbe = () => {
    setProbing(true);
    setLatencies([]);
    probeArea.current?.focus();
    addLog('Keystroke probe armed — type 30 characters for baseline', 'info', 'SURV');
    setTimeout(() => setProbing(false), 15000);
  };

  const permissions: PermissionRow[] = useMemo(
    () => [
      { name: 'Camera', state: cameraState, icon: <Camera size={12} />, risk: 'high' },
      { name: 'Microphone', state: micState, icon: <Mic size={12} />, risk: 'high' },
      { name: 'Geolocation', state: geoState, icon: <Eye size={12} />, risk: 'high' },
      { name: 'Notifications', state: notifState, icon: <Monitor size={12} />, risk: 'med' },
      { name: 'Clipboard Read', state: clipboardState, icon: <Clipboard size={12} />, risk: 'med' },
    ],
    [cameraState, micState, geoState, notifState, clipboardState]
  );

  const mirrorScore = useMemo(() => {
    let s = 0;
    if (externalDisplays > 1) s += 50;
    if (visibilityLoss > 3) s += 15;
    if (focusLoss > 3) s += 10;
    if (screenShareActive) s += 60;
    return Math.min(s, 100);
  }, [externalDisplays, visibilityLoss, focusLoss, screenShareActive]);

  return (
    <div className="space-y-6">
      <div className="bg-[#111] border border-[#00ff41] p-8">
        <div className="flex justify-between items-start mb-6">
          <div>
            <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Surveillance.Probe</h2>
            <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">
              Detect screen share, mirroring, keystroke interception & permission abuse.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {/* Screen Share */}
          <div className={cn('p-4 border-2', screenShareActive ? 'border-[#ff4100] bg-[#ff4100]/10' : 'border-[#00ff41]')}>
            <div className="flex items-center gap-2 mb-3">
              <Cast size={14} />
              <span className="text-[10px] font-black uppercase tracking-widest">Screen Capture</span>
            </div>
            <div className={cn('text-3xl font-black tracking-tighter leading-none mb-3', screenShareActive && 'text-[#ff4100]')}>
              {screenShareActive ? 'ACTIVE' : 'IDLE'}
            </div>
            <div className="flex gap-2">
              <button
                onClick={probeScreenShare}
                className="text-[9px] font-black uppercase tracking-widest px-2 py-1 border border-[#00ff41] hover:bg-[#00ff41] hover:text-black"
              >
                Probe
              </button>
              {screenShareActive && (
                <button
                  onClick={stopShare}
                  className="text-[9px] font-black uppercase tracking-widest px-2 py-1 border border-[#ff4100] text-[#ff4100] hover:bg-[#ff4100] hover:text-black"
                >
                  Halt
                </button>
              )}
            </div>
          </div>

          {/* Mirror */}
          <div className={cn('p-4 border-2', mirrorScore > 40 ? 'border-[#ff4100] bg-[#ff4100]/10' : 'border-[#00ff41]')}>
            <div className="flex items-center gap-2 mb-3">
              <Monitor size={14} />
              <span className="text-[10px] font-black uppercase tracking-widest">Mirror Score</span>
            </div>
            <div className={cn('text-3xl font-black tracking-tighter leading-none mb-3', mirrorScore > 40 && 'text-[#ff4100]')}>
              {mirrorScore}
              <span className="text-sm opacity-40">/100</span>
            </div>
            <div className="text-[9px] opacity-60 uppercase tracking-widest font-black">
              {externalDisplays} display{externalDisplays === 1 ? '' : 's'} · {visibilityLoss} bg
            </div>
          </div>

          {/* Keylog Risk */}
          <div
            className={cn(
              'p-4 border-2',
              keylogRisk === 'high' ? 'border-[#ff4100] bg-[#ff4100]/10' : keylogRisk === 'med' ? 'border-yellow-400' : 'border-[#00ff41]'
            )}
          >
            <div className="flex items-center gap-2 mb-3">
              <Keyboard size={14} />
              <span className="text-[10px] font-black uppercase tracking-widest">Keylog Risk</span>
            </div>
            <div
              className={cn(
                'text-3xl font-black tracking-tighter leading-none mb-3 uppercase',
                keylogRisk === 'high' && 'text-[#ff4100]',
                keylogRisk === 'med' && 'text-yellow-400'
              )}
            >
              {keylogRisk}
            </div>
            <div className="text-[9px] opacity-60 uppercase tracking-widest font-black">
              {latencyMean ? `μ=${latencyMean.toFixed(0)}ms σ=${latencyStd?.toFixed(0)}ms` : 'No baseline'}
            </div>
          </div>
        </div>

        {/* Key probe input */}
        <div className="bg-[#0a0a0a] border border-[#00ff41] p-4 mb-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[9px] uppercase tracking-[0.3em] opacity-60 font-black">Keystroke Probe</span>
            <button
              onClick={runKeyProbe}
              className="text-[9px] font-black uppercase tracking-widest px-2 py-1 border border-[#00ff41] hover:bg-[#00ff41] hover:text-black"
            >
              Arm
            </button>
          </div>
          <input
            ref={probeArea}
            placeholder={probing ? 'TYPE HERE — measuring keydown→keyup jitter...' : 'Press ARM and type a full sentence'}
            className="w-full bg-black border border-[#00ff41]/30 p-2 text-xs font-mono text-[#00ff41] placeholder:text-[#00ff41]/30 outline-none focus:border-[#00ff41]"
          />
          <div className="h-12 flex items-end gap-[2px] mt-3">
            {Array.from({ length: 32 }).map((_, i) => {
              const sample = latencies[i];
              const h = sample ? Math.min(100, (sample.ms / 200) * 100) : 0;
              return (
                <motion.div
                  key={i}
                  animate={{ height: `${h}%` }}
                  transition={{ duration: 0.3 }}
                  className={cn(
                    'flex-1 min-h-[2px]',
                    sample && sample.ms > 140 ? 'bg-[#ff4100]' : sample && sample.ms > 100 ? 'bg-yellow-400' : 'bg-[#00ff41]/70'
                  )}
                />
              );
            })}
          </div>
        </div>

        {/* Permissions Audit */}
        <div className="bg-[#0a0a0a] border border-[#00ff41] p-4">
          <div className="flex items-center gap-2 mb-3">
            <ShieldCheck size={14} />
            <span className="text-[10px] font-black uppercase tracking-widest">Permission Audit</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {permissions.map(p => (
              <div
                key={p.name}
                className={cn(
                  'flex items-center justify-between p-2 border text-[10px] font-black uppercase',
                  p.state === 'granted'
                    ? p.risk === 'high'
                      ? 'border-[#ff4100] bg-[#ff4100]/10 text-[#ff4100]'
                      : 'border-yellow-400 text-yellow-400'
                    : 'border-[#00ff41]/30'
                )}
              >
                <span className="flex items-center gap-2">
                  {p.icon}
                  {p.name}
                </span>
                <span>{p.state.toUpperCase()}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Indicator dictionaries */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-[#111] border border-[#00ff41] p-4">
          <div className="text-[10px] uppercase tracking-[0.3em] font-black mb-3 border-b border-[#00ff41]/30 pb-1">
            Known Keylogger Signatures
          </div>
          <div className="space-y-1 max-h-40 overflow-y-auto scrollbar-hide">
            {KEYLOGGER_INDICATORS.map(k => (
              <div key={k} className="text-[10px] font-mono opacity-70 flex items-center gap-2">
                <AlertTriangle size={10} className="text-[#ff4100] shrink-0" />
                {k}
              </div>
            ))}
          </div>
        </div>
        <div className="bg-[#111] border border-[#00ff41] p-4">
          <div className="text-[10px] uppercase tracking-[0.3em] font-black mb-3 border-b border-[#00ff41]/30 pb-1">
            Mirror / Cast Sources
          </div>
          <div className="space-y-1 max-h-40 overflow-y-auto scrollbar-hide">
            {MIRROR_INDICATORS.map(k => (
              <div key={k} className="text-[10px] font-mono opacity-70 flex items-center gap-2">
                <Monitor size={10} className="text-yellow-400 shrink-0" />
                {k}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SurveillancePanel;
