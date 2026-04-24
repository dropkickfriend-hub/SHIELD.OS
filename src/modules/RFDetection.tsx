import React, { useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'motion/react';
import { Radio, Crosshair, AlertTriangle, Zap, Signal, Ban } from 'lucide-react';
import { cn } from '../lib/utils';

export type RFThreatLevel = 'safe' | 'unknown' | 'hostile';

export interface RFDevice {
  id: string;
  label: string;
  band: string;
  freq: number;
  rssi: number;
  angle: number;
  distance: number;
  lastSeen: number;
  threat: RFThreatLevel;
  category: string;
}

const DEVICE_CATALOG: Array<{ label: string; band: string; freq: number; category: string; threat: RFThreatLevel }> = [
  { label: 'Apple AirTag', band: 'BLE', freq: 2.480, category: 'Tracker', threat: 'hostile' },
  { label: 'Tile Mate Beacon', band: 'BLE', freq: 2.402, category: 'Tracker', threat: 'hostile' },
  { label: 'GPS Asset Tag (LTE-M)', band: 'Cellular', freq: 1.900, category: 'Tracker', threat: 'hostile' },
  { label: 'Covert 2.4GHz Camera', band: 'ISM 2.4', freq: 2.440, category: 'Camera', threat: 'hostile' },
  { label: 'Audio Bug (FM bug)', band: 'FM', freq: 0.108, category: 'Mic', threat: 'hostile' },
  { label: 'WiFi Pineapple Clone', band: 'ISM 2.4', freq: 2.462, category: 'Rogue AP', threat: 'hostile' },
  { label: 'IMSI Catcher (Downgrade)', band: 'GSM 850', freq: 0.869, category: 'Cell Site Sim', threat: 'hostile' },
  { label: 'RFID Skimmer', band: 'HF', freq: 0.01356, category: 'Skimmer', threat: 'hostile' },
  { label: 'Unpaired Zigbee Node', band: 'ISM 2.4', freq: 2.405, category: 'IoT', threat: 'unknown' },
  { label: 'Consumer Wi-Fi Router', band: 'ISM 5.8', freq: 5.745, category: 'AP', threat: 'safe' },
  { label: 'Paired Bluetooth Earbud', band: 'BLE', freq: 2.408, category: 'Peripheral', threat: 'safe' },
  { label: 'Smart Thermostat', band: 'ISM 2.4', freq: 2.417, category: 'IoT', threat: 'safe' },
  { label: 'Drone Control Link', band: 'ISM 2.4', freq: 2.425, category: 'UAV', threat: 'unknown' },
];

function pickDevices(): RFDevice[] {
  const count = 5 + Math.floor(Math.random() * 4);
  const picks = [...DEVICE_CATALOG].sort(() => 0.5 - Math.random()).slice(0, count);
  return picks.map((d, i) => ({
    id: `${d.label}-${i}`,
    label: d.label,
    band: d.band,
    freq: d.freq,
    rssi: -30 - Math.floor(Math.random() * 70),
    angle: Math.floor(Math.random() * 360),
    distance: 0.2 + Math.random() * 0.8,
    lastSeen: Date.now(),
    threat: d.threat,
    category: d.category,
  }));
}

interface Props {
  addLog: (msg: string, level?: 'info' | 'warn' | 'error' | 'success', category?: string) => void;
}

export const RFDetectionPanel: React.FC<Props> = ({ addLog }) => {
  const [sweeping, setSweeping] = useState(true);
  const [devices, setDevices] = useState<RFDevice[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [spectrum, setSpectrum] = useState<number[]>(Array.from({ length: 64 }, () => 0));
  const seenRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (!sweeping) return;
    const t = setInterval(() => {
      const next = pickDevices();
      next.forEach(d => {
        const key = d.label;
        if (!seenRef.current.has(key)) {
          seenRef.current.add(key);
          if (d.threat === 'hostile') {
            addLog(`HOSTILE emitter acquired: ${d.label} @ ${d.freq.toFixed(3)}GHz (${d.rssi}dBm)`, 'error', 'RF');
          } else if (d.threat === 'unknown') {
            addLog(`Unidentified carrier: ${d.label} (${d.band})`, 'warn', 'RF');
          }
        }
      });
      setDevices(next);
      setSpectrum(prev => prev.map((_, i) => {
        const matched = next.some(d => Math.floor((d.freq % 6) * 10) === Math.floor(i * 0.9));
        return matched ? 50 + Math.random() * 50 : Math.random() * 25;
      }));
    }, 1400);
    return () => clearInterval(t);
  }, [sweeping, addLog]);

  const hostileCount = useMemo(() => devices.filter(d => d.threat === 'hostile').length, [devices]);
  const selectedDev = devices.find(d => d.id === selected);

  const triangulate = (dev: RFDevice) => {
    addLog(`Triangulating ${dev.label}: bearing ${dev.angle}°, est. ${(dev.distance * 15).toFixed(1)}m`, 'warn', 'RF');
    setSelected(dev.id);
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#111] border border-[#00ff41] p-8">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Spectral Audit</h2>
            <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">
              Passive RF sweep: BLE, ISM, Cellular, RFID — triangulate hidden emitters.
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setSweeping(s => !s)}
              className={cn(
                'px-4 py-2 font-black uppercase tracking-widest text-[10px] border-2 transition-all',
                sweeping
                  ? 'border-[#00ff41] bg-[#00ff41] text-black'
                  : 'border-[#00ff41] text-[#00ff41] hover:bg-[#00ff41] hover:text-black'
              )}
            >
              {sweeping ? 'SWEEP_ACTIVE' : 'SWEEP_PAUSED'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-12 gap-6">
          {/* Polar Map */}
          <div className="col-span-12 md:col-span-7">
            <div className="relative aspect-square w-full bg-[#0a0a0a] border border-[#00ff41] overflow-hidden">
              {/* concentric rings */}
              {[0.25, 0.5, 0.75, 1].map((r, i) => (
                <div
                  key={i}
                  className="absolute border border-[#00ff41]/20 rounded-full"
                  style={{
                    inset: `${(1 - r) * 50}%`,
                  }}
                />
              ))}
              {/* crosshair */}
              <div className="absolute left-0 right-0 top-1/2 h-px bg-[#00ff41]/15" />
              <div className="absolute top-0 bottom-0 left-1/2 w-px bg-[#00ff41]/15" />
              {/* bearing labels */}
              <div className="absolute top-1 left-1/2 -translate-x-1/2 text-[9px] font-black text-[#00ff41]/40">N</div>
              <div className="absolute bottom-1 left-1/2 -translate-x-1/2 text-[9px] font-black text-[#00ff41]/40">S</div>
              <div className="absolute top-1/2 left-1 -translate-y-1/2 text-[9px] font-black text-[#00ff41]/40">W</div>
              <div className="absolute top-1/2 right-1 -translate-y-1/2 text-[9px] font-black text-[#00ff41]/40">E</div>

              {/* rotating sweep */}
              {sweeping && (
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 4, ease: 'linear', repeat: Infinity }}
                  className="absolute inset-0 origin-center"
                  style={{
                    background:
                      'conic-gradient(from 0deg, rgba(0,255,65,0) 0deg, rgba(0,255,65,0) 300deg, rgba(0,255,65,0.35) 355deg, rgba(0,255,65,0.6) 360deg)',
                  }}
                />
              )}

              {/* devices */}
              {devices.map(d => {
                const rad = (d.angle * Math.PI) / 180;
                const x = 50 + Math.cos(rad) * d.distance * 45;
                const y = 50 + Math.sin(rad) * d.distance * 45;
                const color =
                  d.threat === 'hostile' ? '#ff4100' : d.threat === 'unknown' ? '#ffcc00' : '#00ff41';
                const isSel = selected === d.id;
                return (
                  <button
                    key={d.id}
                    onClick={() => triangulate(d)}
                    className="absolute -translate-x-1/2 -translate-y-1/2 group"
                    style={{ left: `${x}%`, top: `${y}%` }}
                    title={`${d.label} (${d.rssi}dBm)`}
                  >
                    <motion.div
                      animate={{ scale: [1, 1.6, 1], opacity: [0.9, 0.3, 0.9] }}
                      transition={{ duration: 1.8, repeat: Infinity }}
                      className="absolute inset-0 rounded-full"
                      style={{ background: color, width: 14, height: 14, left: -7, top: -7 }}
                    />
                    <div
                      className={cn(
                        'relative w-3 h-3 rounded-full border-2 border-black',
                        isSel && 'ring-2 ring-white'
                      )}
                      style={{ background: color }}
                    />
                  </button>
                );
              })}
            </div>
          </div>

          {/* Spectrum + Readout */}
          <div className="col-span-12 md:col-span-5 flex flex-col gap-4">
            <div className="bg-[#0a0a0a] border border-[#00ff41] p-4">
              <div className="flex justify-between items-center mb-2">
                <span className="text-[9px] uppercase tracking-[0.3em] opacity-60 font-black">Waterfall</span>
                <span className="text-[9px] uppercase tracking-widest font-black text-[#00ff41]/60">
                  0.01–5.9 GHz
                </span>
              </div>
              <div className="flex items-end gap-[2px] h-28">
                {spectrum.map((v, i) => (
                  <motion.div
                    key={i}
                    animate={{ height: `${Math.max(4, v)}%` }}
                    transition={{ duration: 0.4 }}
                    className={cn('flex-1', v > 60 ? 'bg-[#ff4100]' : 'bg-[#00ff41]/70')}
                  />
                ))}
              </div>
            </div>

            <div className="bg-[#0a0a0a] border border-[#00ff41] p-4 flex-1">
              <div className="flex justify-between items-center mb-3 border-b border-[#00ff41]/20 pb-1">
                <span className="text-[9px] uppercase tracking-[0.3em] opacity-60 font-black">Readout</span>
                <span
                  className={cn(
                    'text-[9px] uppercase tracking-widest font-black px-2 py-0.5',
                    hostileCount > 0 ? 'bg-[#ff4100] text-black' : 'bg-[#00ff41]/20 text-[#00ff41]'
                  )}
                >
                  {hostileCount} HOSTILE
                </span>
              </div>
              {selectedDev ? (
                <div className="space-y-2 text-[10px]">
                  <div className="text-2xl font-black tracking-tighter leading-none">{selectedDev.label}</div>
                  <div className="flex justify-between">
                    <span className="opacity-50">BAND</span>
                    <span className="font-black">{selectedDev.band}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="opacity-50">FREQ</span>
                    <span className="font-black">{selectedDev.freq.toFixed(3)} GHz</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="opacity-50">RSSI</span>
                    <span className={cn('font-black', selectedDev.rssi > -60 ? 'text-[#ff4100]' : '')}>
                      {selectedDev.rssi} dBm
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="opacity-50">BEARING</span>
                    <span className="font-black">{selectedDev.angle}°</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="opacity-50">EST. RANGE</span>
                    <span className="font-black">{(selectedDev.distance * 15).toFixed(1)} m</span>
                  </div>
                </div>
              ) : (
                <div className="text-[10px] opacity-40 uppercase tracking-widest font-black italic">
                  Tap a contact to triangulate
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Device List */}
      <div className="bg-[#111] border border-[#00ff41] p-6">
        <div className="flex items-center gap-3 mb-4 border-b border-[#00ff41]/30 pb-2">
          <Signal size={14} />
          <h3 className="text-xs font-black uppercase tracking-[0.3em]">Emitter.Table</h3>
        </div>
        <div className="grid grid-cols-12 gap-2 text-[8px] uppercase font-black opacity-40 mb-2">
          <div className="col-span-4">LABEL</div>
          <div className="col-span-2">BAND</div>
          <div className="col-span-2 text-center">FREQ</div>
          <div className="col-span-1 text-center">RSSI</div>
          <div className="col-span-2 text-center">BEARING</div>
          <div className="col-span-1 text-right">THREAT</div>
        </div>
        <div className="space-y-1 max-h-64 overflow-y-auto scrollbar-hide">
          {devices.map(d => (
            <button
              key={d.id}
              onClick={() => triangulate(d)}
              className={cn(
                'w-full grid grid-cols-12 gap-2 text-[10px] font-black p-2 border items-center text-left transition-colors',
                selected === d.id
                  ? 'border-[#00ff41] bg-[#00ff41]/10'
                  : 'border-[#00ff41]/10 bg-black/40 hover:border-[#00ff41]/40',
                d.threat === 'hostile' && 'text-[#ff4100]'
              )}
            >
              <div className="col-span-4 truncate flex items-center gap-2">
                {d.threat === 'hostile' ? (
                  <AlertTriangle size={10} className="text-[#ff4100]" />
                ) : d.threat === 'unknown' ? (
                  <Zap size={10} className="text-yellow-400" />
                ) : (
                  <Radio size={10} />
                )}
                {d.label}
              </div>
              <div className="col-span-2 opacity-70">{d.band}</div>
              <div className="col-span-2 text-center opacity-70">{d.freq.toFixed(3)}</div>
              <div className="col-span-1 text-center">{d.rssi}</div>
              <div className="col-span-2 text-center">
                <Crosshair size={10} className="inline mr-1 opacity-50" />
                {d.angle}°
              </div>
              <div className="col-span-1 text-right uppercase">
                {d.threat === 'hostile' ? 'HOT' : d.threat === 'unknown' ? 'UNK' : 'OK'}
              </div>
            </button>
          ))}
          {devices.length === 0 && (
            <div className="text-[10px] opacity-40 py-6 text-center uppercase tracking-widest font-black italic">
              Sweeping...
            </div>
          )}
        </div>
      </div>

      {hostileCount > 0 && (
        <div className="p-4 bg-[#ff4100] text-black border-2 border-black flex gap-3">
          <Ban className="shrink-0" size={20} strokeWidth={3} />
          <div>
            <h4 className="text-xs font-black uppercase tracking-widest mb-1">RF Threat Advisory</h4>
            <p className="text-[10px] leading-tight font-black uppercase">
              {hostileCount} hostile emitter(s) within range. Recommended actions: move 10m+, enter a faraday
              enclosure, disable BT/Wi-Fi, and rerun sweep to fix bearing.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default RFDetectionPanel;
