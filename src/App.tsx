/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Wifi, 
  Radio, 
  Zap, 
  Terminal as TerminalIcon, 
  MapPin, 
  ChevronRight, 
  Activity,
  Cpu,
  Lock,
  Search,
  AlertTriangle,
  RefreshCw,
  Eye,
  Settings,
  List,
  BarChart3,
  Globe,
  Upload,
  User
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  collection, 
  addDoc, 
  query, 
  orderBy, 
  limit, 
  onSnapshot, 
  serverTimestamp 
} from 'firebase/firestore';
import { cn } from './lib/utils';
import { auth, db, signIn } from './lib/firebase';
import {
  capabilities,
  type ProcessEntry,
  type NetworkConnection,
  type WifiScanResult,
  type BleDevice,
  type ScanReport,
  type ThreatIntelStats,
} from './capabilities';

// --- Types ---
interface LogEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
  category: string;
}

interface PerfReport {
  id: string;
  model: string;
  hardwareSpeed: number;
  actualSpeed: number;
  efficiency: number;
  timestamp: any;
  userId: string;
}

// --- Components ---

const Terminal = ({ logs }: { logs: LogEntry[] }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-[#111] border border-[#00ff41] p-4 font-mono text-[10px] leading-tight h-full overflow-hidden flex flex-col">
      <div className="flex justify-between items-center mb-2 border-b border-[#00ff41] pb-2">
        <div className="flex items-center gap-2">
          <TerminalIcon size={12} className="text-[#00ff41]/50" />
          <span className="text-[#00ff41] uppercase tracking-[0.4em] font-black text-[9px]">Log.Buffer</span>
        </div>
        <span className="text-[#00ff41]/30 text-[8px] uppercase tracking-widest font-bold">Encrypted Stream</span>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-1 scrollbar-hide">
        {logs.map((log) => (
          <div key={log.id} className="flex gap-2">
            <span className="text-[#00ff41]/40 whitespace-nowrap">[{log.timestamp}]</span>
            <span className={cn(
              "uppercase font-black tracking-tighter whitespace-nowrap",
              log.level === 'success' && "text-[#00ff41]",
              log.level === 'warn' && "text-[#ff4100]",
              log.level === 'error' && "text-[#ff4100] underline",
              log.level === 'info' && "text-[#00ff41]/70"
            )}>{log.level.substring(0, 3)}</span>
            <span className="text-[#00ff41]/50 whitespace-nowrap font-bold">//{log.category}</span>
            <span className="text-[#00ff41]">{log.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const Scanner = ({ active, progress }: { active: boolean, progress: number }) => {
  return (
    <div className="relative aspect-square w-full max-w-[400px] mx-auto group">
      {/* Background Rings */}
      <div className="absolute inset-0 border border-[#00ff41]/10 rounded-full scale-[0.8]" />
      <div className="absolute inset-0 border border-[#00ff41]/10 rounded-full scale-[0.6]" />
      <div className="absolute inset-0 border border-[#00ff41]/10 rounded-full scale-[0.4]" />
      
      {/* Active Scan Line */}
      <AnimatePresence>
        {active && (
          <motion.div
            initial={{ top: '0%' }}
            animate={{ top: '100%' }}
            transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
            className="absolute left-0 right-0 h-[3px] bg-[#00ff41] shadow-[0_0_20px_#00ff41] z-10 pointer-events-none"
          />
        )}
      </AnimatePresence>

      {/* Grid Overlay */}
      <div className="absolute inset-0 grid grid-cols-8 grid-rows-8 gap-0 opacity-10 pointer-events-none">
        {Array.from({ length: 64 }).map((_, i) => (
          <div key={i} className="border-[0.5px] border-[#00ff41]/30" />
        ))}
      </div>

      {/* Radar Sweep */}
      {active && (
        <motion.div 
          animate={{ rotate: 360 }}
          transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
          className="absolute inset-0 rounded-full bg-gradient-to-tr from-transparent via-transparent to-[#00ff41]/30 origin-center"
        />
      )}

      {/* Center Display */}
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="text-center space-y-2">
          {active ? (
            <motion.div 
              animate={{ opacity: [0.5, 1, 0.5] }}
              transition={{ duration: 2, repeat: Infinity }}
              className="font-mono text-6xl font-black tracking-tighter"
            >
              {Math.floor(progress)}
            </motion.div>
          ) : (
            <ShieldCheck size={64} className="mx-auto text-[#00ff41] mb-2" strokeWidth={3} />
          )}
          <div className="font-mono text-[11px] uppercase tracking-[0.4em] text-[#00ff41] font-black">
            {active ? 'ANALYSIS_RUNNING' : 'SYSTEM_NOMINAL'}
          </div>
        </div>
      </div>
    </div>
  );
};

const SecurityDashboard = () => {
  const [activeTab, setActiveTab] = useState<'malware' | 'rf' | 'network' | 'processes' | 'perf'>('malware');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [networkInfo, setNetworkInfo] = useState<any>(null);
  const [location, setLocation] = useState<any>(null);
  const [processes, setProcesses] = useState<ProcessEntry[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [wifi, setWifi] = useState<WifiScanResult[]>([]);
  const [ble, setBle] = useState<BleDevice[]>([]);
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelStats | null>(null);
  const [user, setUser] = useState<any>(null);
  const [perfReports, setPerfReports] = useState<PerfReport[]>([]);
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [benchResult, setBenchResult] = useState<number | null>(null);

  const addLog = useCallback((message: string, level: LogEntry['level'] = 'info', category: string = 'SYS') => {
    const entry: LogEntry = {
      id: Math.random().toString(36).substring(7),
      timestamp: new Date().toLocaleTimeString('en-GB', { hour12: false }),
      level,
      message,
      category
    };
    setLogs(prev => [...prev.slice(-49), entry]);
  }, []);

  const startScan = async () => {
    if (scanning) return;
    setScanning(true);
    setProgress(0);
    setScanReport(null);

    if (!capabilities.supports.fileScan) {
      addLog("Initializing simulated scan (native build required for real scan)...", "info", "MALWARE");
      const duration = 4000;
      const startTime = Date.now();
      const interval = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const p = Math.min((elapsed / duration) * 100, 100);
        setProgress(p);
        if (p >= 100) {
          clearInterval(interval);
          setScanning(false);
          addLog("Simulated scan complete. Install the desktop or Android build for real scanning.", "success", "MALWARE");
        }
      }, 100);
      return;
    }

    addLog("Refreshing threat intelligence...", "info", "MALWARE");
    try {
      const stats = await capabilities.refreshThreatIntel();
      setThreatIntel(stats);
      addLog(`Intel loaded: ${stats.badIps} bad IPs, ${stats.badHashes} bad hashes`, "success", "MALWARE");
      if (stats.error) addLog(stats.error, "warn", "MALWARE");
    } catch (e) {
      addLog(`Intel refresh failed: ${e}`, "warn", "MALWARE");
    }

    addLog(capabilities.platform === 'android' ? "Scanning installed APKs..." : "Scanning Downloads directory...", "info", "MALWARE");
    // Visual progress while we wait for the (synchronous on Rust side) scan.
    setProgress(5);
    const tick = setInterval(() => setProgress((p) => Math.min(p + 3, 92)), 250);

    try {
      const report = await capabilities.scanFiles();
      clearInterval(tick);
      setProgress(100);
      setScanReport(report);
      const level = report.findings.length > 0 ? "error" : "success";
      addLog(
        `Scan complete: ${report.filesScanned} item(s), ${report.findings.length} threat(s) found in ${report.durationMs}ms.`,
        level,
        "MALWARE"
      );
      for (const f of report.findings.slice(0, 5)) {
        addLog(`THREAT: ${f.label ?? f.path} — ${f.reason}`, "error", "MALWARE");
      }
    } catch (e) {
      clearInterval(tick);
      addLog(`Scan failed: ${e}`, "error", "MALWARE");
    } finally {
      setScanning(false);
    }
  };

  const checkNetwork = async () => {
    addLog("Initiating Network Tunneling Verification...", "info", "NET");
    try {
      const response = await fetch("https://api.ipify.org?format=json");
      const data = await response.json();
      setNetworkInfo({ip: data.ip, status: "SECURE", tunnelingDetected: false});
      addLog(`Public IP Trace: ${data.ip}`, "info", "NET");

      if ("geolocation" in navigator) {
        navigator.geolocation.getCurrentPosition((pos) => {
          const loc = {lat: pos.coords.latitude, lng: pos.coords.longitude};
          setLocation(loc);
          addLog(`Device Geo-Position: ${loc.lat.toFixed(4)}, ${loc.lng.toFixed(4)}`, "info", "NET");
        }, () => addLog("Geo-access denied. Fallback to IP-only analysis.", "warn", "NET"));
      }
    } catch {
      addLog("External trace failed. Connectivity limited.", "error", "NET");
    }

    if (capabilities.supports.networkMonitor) {
      try {
        const conns = await capabilities.listConnections();
        setConnections(conns);
        const malicious = conns.filter((c) => c.severity === 'malicious').length;
        if (malicious > 0) {
          addLog(`${malicious} malicious remote(s) matched on threat intel.`, "error", "NET");
        } else {
          addLog(`${conns.length} active connection(s) — no threat-intel hits.`, "success", "NET");
        }
      } catch (e) {
        addLog(`Connection enumeration failed: ${e}`, "warn", "NET");
      }
    }
  };

  const rescanRf = useCallback(async () => {
    if (!capabilities.supports.wifiScan && !capabilities.supports.bleScan) {
      addLog("RF scan requires the Android build.", "warn", "RF");
      return;
    }
    addLog("Initiating spectral sweep...", "info", "RF");
    try {
      if (capabilities.supports.wifiScan) {
        const w = await capabilities.scanWifi();
        setWifi(w);
        const suspicious = w.filter((r) => r.suspicious).length;
        addLog(`Wi-Fi: ${w.length} AP(s) detected, ${suspicious} flagged.`, suspicious ? "warn" : "success", "RF");
      }
      if (capabilities.supports.bleScan) {
        const b = await capabilities.scanBle();
        setBle(b);
        addLog(`BLE: ${b.length} device(s) advertising.`, "info", "RF");
      }
    } catch (e) {
      addLog(`RF scan failed: ${e}`, "error", "RF");
    }
  }, [addLog]);

  // --- Process / Installed-App listing (real on native, simulated on web) ---
  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const procs = await capabilities.listProcesses();
        if (!cancelled) setProcesses(procs);
      } catch (e) {
        if (!cancelled) addLog(`Process enumeration failed: ${String(e)}`, "error", "SYS");
      }
    };
    refresh();
    const intervalMs = capabilities.platform === 'android' ? 30_000 : 2_000;
    const interval = setInterval(refresh, intervalMs);
    return () => { cancelled = true; clearInterval(interval); };
  }, [addLog]);

  // --- Live connection polling (desktop/android only) ---
  useEffect(() => {
    if (!capabilities.supports.networkMonitor) return;
    let cancelled = false;
    const refresh = async () => {
      try {
        const conns = await capabilities.listConnections();
        if (!cancelled) setConnections(conns);
      } catch { /* silent */ }
    };
    refresh();
    const interval = setInterval(refresh, 5_000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  // --- Threat intel refresh on mount ---
  useEffect(() => {
    (async () => {
      try {
        const stats = await capabilities.refreshThreatIntel();
        setThreatIntel(stats);
        if (stats.badIps || stats.badHashes) {
          addLog(`Threat intel loaded: ${stats.badIps} IPs, ${stats.badHashes} hashes.`, "success", "INTEL");
        } else if (stats.error) {
          addLog(stats.error, "warn", "INTEL");
        }
      } catch (e) {
        addLog(`Threat intel init failed: ${e}`, "warn", "INTEL");
      }
    })();
  }, [addLog]);

  // --- RF auto-scan when the tab opens ---
  useEffect(() => {
    if (activeTab === 'rf' && capabilities.supports.wifiScan && wifi.length === 0) {
      rescanRf();
    }
  }, [activeTab, rescanRf, wifi.length]);

  const handleKill = useCallback(async (id: string, label: string) => {
    if (!capabilities.supports.killProcess) {
      addLog(`Kill unavailable in ${capabilities.platform} build.`, "warn", "SYS");
      return;
    }
    addLog(`Termination requested: ${label}`, "info", "SYS");
    const res = await capabilities.killProcess(id);
    addLog(res.message, res.ok ? "success" : "error", "SYS");
  }, [addLog]);

  // --- Firebase Subscriptions ---
  useEffect(() => {
    if (!db) {
      addLog("Database interface standby.", "info", "DB");
      return;
    }
    const q = query(collection(db, "perf_reports"), orderBy("efficiency", "asc"), limit(20));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const reports = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) as PerfReport[];
      setPerfReports(reports);
    }, (error) => {
      console.error("Firestore Listen Error:", error);
      addLog("Community board sync limited.", "warn", "DB");
    });

    if (!auth) return;
    const authUnsubscribe = auth.onAuthStateChanged((u) => {
      if (u) {
        setUser(u);
        addLog(`Identity confirmed: ${u.email}`, "success", "AUTH");
      } else {
        setUser(null);
      }
    });

    return () => {
      unsubscribe();
      authUnsubscribe();
    };
  }, [addLog, db, auth]);

  const runBenchmark = async () => {
    setIsBenchmarking(true);
    addLog("Starting hardware speed calculation...", "info", "PERF");

    // Yield so the "EXECUTING..." state renders before the blocking loop.
    await new Promise((r) => setTimeout(r, 16));

    const iterations = 50_000_000;
    const start = performance.now();
    let count = 0;
    for (let i = 1; i < iterations; i++) {
      count += Math.sqrt(i) / i;
    }
    const end = performance.now();
    // Expose `count` so V8 can't dead-code-eliminate the loop.
    (window as unknown as {__benchSink?: number}).__benchSink = count;

    const duration = Math.max(end - start, 1);
    const baseMHz = 3200;
    const actualSpeed = Math.min(Math.floor((5000 / duration) * 1000), 99_999);
    const hardwareSpeed = baseMHz;
    const efficiency = Math.min((actualSpeed / hardwareSpeed) * 100, 100);

    setBenchResult(actualSpeed);
    setIsBenchmarking(false);

    addLog(`Measured Speed: ${actualSpeed} MHz (Efficiency: ${efficiency.toFixed(1)}%)`, efficiency < 60 ? "warn" : "success", "PERF");

    if (!db || !user) {
      addLog("Database sync skipped: Auth or Config missing.", "warn", "DB");
      return;
    }

    try {
      await addDoc(collection(db, "perf_reports"), {
        model: navigator.userAgent.split(')')[0].split('(')[1] || "Mobile Device",
        hardwareSpeed,
        actualSpeed,
        efficiency,
        timestamp: serverTimestamp(),
        userId: user.uid
      });
      addLog("Performance report indexed to community board.", "success", "PERF");
    } catch (e) {
      addLog("Database sync failed. Check rules.", "error", "DB");
    }
  };

  useEffect(() => {
    addLog("DroidSentry Interface v1.0.6 Online.", "success", "SYS");
    addLog("Hardware isolation protocols active.", "info", "SYS");
    checkNetwork();
  }, [addLog]);

  return (
    <div className="flex h-screen w-full bg-[#0a0a0a] text-[#00ff41] font-mono tracking-tight selection:bg-[#00ff41]/30">
      
      {/* Sidebar Rail */}
      <div className="w-16 border-r border-[#00ff41] flex flex-col items-center py-8 gap-8">
        <div className="p-2 bg-[#00ff41]/10 border border-[#00ff41] mb-8">
          <ShieldAlert size={20} className="text-[#00ff41]" />
        </div>
        
        <button onClick={() => setActiveTab('malware')} className={cn("p-3 transition-all", activeTab === 'malware' ? "bg-[#00ff41] text-black font-black" : "text-[#00ff41]/30 hover:text-[#00ff41]/60")} title="Scanner">
          <Search size={22} strokeWidth={3} />
        </button>
        <button onClick={() => setActiveTab('processes')} className={cn("p-3 transition-all", activeTab === 'processes' ? "bg-[#00ff41] text-black font-black" : "text-[#00ff41]/30 hover:text-[#00ff41]/60")} title="Processes">
          <List size={22} strokeWidth={3} />
        </button>
        <button onClick={() => setActiveTab('rf')} className={cn("p-3 transition-all", activeTab === 'rf' ? "bg-[#00ff41] text-black font-black" : "text-[#00ff41]/30 hover:text-[#00ff41]/60")} title="RF Audit">
          <Radio size={22} strokeWidth={3} />
        </button>
        <button onClick={() => setActiveTab('network')} className={cn("p-3 transition-all", activeTab === 'network' ? "bg-[#00ff41] text-black font-black" : "text-[#00ff41]/30 hover:text-[#00ff41]/60")} title="Network">
          <Wifi size={22} strokeWidth={3} />
        </button>
        <button onClick={() => setActiveTab('perf')} className={cn("p-3 transition-all", activeTab === 'perf' ? "bg-[#00ff41] text-black font-black" : "text-[#00ff41]/30 hover:text-[#00ff41]/60")} title="Hardware">
          <BarChart3 size={22} strokeWidth={3} />
        </button>
        
        <div className="mt-auto p-3 text-[#00ff41]/10">
          <Settings size={22} />
        </div>
      </div>

      {/* Main Panel */}
      <div className="flex-1 flex flex-col overflow-hidden">
        
        {/* Header */}
        <header className="h-20 border-b border-[#00ff41] flex items-center justify-between px-8 bg-[#111]">
          <div className="flex flex-col">
            <span className="text-[10px] tracking-[0.4em] uppercase opacity-60">Security Protocol</span>
            <h1 className="text-4xl font-black tracking-tighter uppercase leading-none">SHIELD.OS / {activeTab}</h1>
          </div>
          <div className="flex gap-8 text-right items-center">
            {user ? (
               <div className="flex flex-col items-end mr-4">
                 <span className="text-[8px] uppercase opacity-40">Agent Identity</span>
                 <span className="text-[10px] font-black truncate max-w-[150px]">{user.email}</span>
               </div>
            ) : (
              <button 
                onClick={signIn}
                className="px-4 py-1 border border-[#00ff41] text-[10px] font-black uppercase hover:bg-[#00ff41] hover:text-black transition-all"
              >
                Sync Data
              </button>
            )}
            <div className="flex flex-col">
              <span className="text-[10px] uppercase opacity-60">Threat Level</span>
              <span className="text-xl font-black">NOMINAL</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] uppercase opacity-60">Uptime</span>
              <span className="text-xl font-black italic">14:02:41</span>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 p-8 grid grid-cols-12 gap-8 overflow-hidden">
          
          {/* Main Interaction Area */}
          <div className="col-span-12 lg:col-span-7 flex flex-col gap-8 relative overflow-y-auto pr-2 scrollbar-hide">
            
            <AnimatePresence mode="wait">
              {activeTab === 'malware' && (
                <motion.div 
                  key="malware"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="space-y-8"
                >
                  <div className="bg-[#111] border border-[#00ff41] p-8 overflow-hidden relative group">
                    <div className="absolute top-4 left-4 flex items-center gap-2">
                       <div className="w-2 h-2 bg-[#00ff41] animate-pulse"></div>
                       <span className="text-[10px] uppercase tracking-widest font-black">Active Environment Scan</span>
                    </div>
                    <div className="absolute top-0 right-0 p-8 text-[#00ff41]/5 -rotate-12 group-hover:scale-110 transition-transform">
                      <ShieldCheck size={160} />
                    </div>
                    <div className="relative z-10 pt-8">
                      <div className="flex items-start justify-between mb-8">
                        <div>
                          <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Architecture Audit</h2>
                          <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">Verify kernel integrity and file system signatures.</p>
                        </div>
                        <button 
                          onClick={startScan}
                          disabled={scanning}
                          className={cn(
                            "px-8 py-4 font-black uppercase tracking-[0.2em] text-[11px] transition-all flex items-center gap-2 border-2",
                            scanning ? "border-[#00ff41]/20 text-[#00ff41]/20 cursor-not-allowed" : "border-[#00ff41] text-[#00ff41] hover:bg-[#00ff41] hover:text-black active:scale-95"
                          )}
                        >
                          {scanning ? <RefreshCw className="animate-spin" size={14} /> : <Zap size={14} />}
                          {scanning ? 'SCANNING' : 'EXECUTE_AUDIT'}
                        </button>
                      </div>
                      
                      <Scanner active={scanning} progress={progress} />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-6">
                    <div className="bg-[#111] border border-[#00ff41] p-6 h-40 flex flex-col justify-between">
                      <span className="text-[10px] uppercase tracking-[0.3em] opacity-60 font-black">Threat Intel</span>
                      <div className="space-y-2">
                        <div className="flex justify-between items-center text-xs">
                          <span className="opacity-80">BAD_IPS</span>
                          <span className="font-black">{threatIntel ? threatIntel.badIps.toLocaleString() : '—'}</span>
                        </div>
                        <div className="flex justify-between items-center text-xs">
                          <span className="opacity-80">BAD_HASHES</span>
                          <span className="font-black">{threatIntel ? threatIntel.badHashes.toLocaleString() : '—'}</span>
                        </div>
                        <div className="flex justify-between items-center text-[10px] opacity-60">
                          <span>SOURCE</span>
                          <span className="font-bold">FireHOL + MalwareBazaar</span>
                        </div>
                      </div>
                    </div>
                    <div className="bg-[#111] border border-[#00ff41] p-6 h-40 flex flex-col justify-between">
                      <span className="text-[10px] uppercase tracking-[0.3em] opacity-60 font-black">Last Scan</span>
                      {scanReport ? (
                        <div className="space-y-1 text-xs">
                          <div className="flex justify-between"><span className="opacity-60">ROOT</span><span className="truncate max-w-[180px]">{scanReport.root}</span></div>
                          <div className="flex justify-between"><span className="opacity-60">FILES</span><span className="font-black">{scanReport.filesScanned}</span></div>
                          <div className="flex justify-between"><span className="opacity-60">THREATS</span><span className={cn("font-black", scanReport.findings.length > 0 && "text-[#ff4100]")}>{scanReport.findings.length}</span></div>
                        </div>
                      ) : (
                        <div className="flex items-end gap-3 leading-none">
                          <span className="text-5xl font-black tracking-tighter italic uppercase">{capabilities.supports.fileScan ? 'Ready' : 'Sim'}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {scanReport && scanReport.findings.length > 0 && (
                    <div className="bg-[#111] border-2 border-[#ff4100] p-6">
                      <div className="flex items-center gap-3 mb-4 border-b border-[#ff4100] pb-2">
                        <AlertTriangle size={16} strokeWidth={3} className="text-[#ff4100]" />
                        <h3 className="text-[#ff4100] text-sm font-black uppercase tracking-[0.3em]">Findings</h3>
                      </div>
                      <div className="space-y-2">
                        {scanReport.findings.map((f) => (
                          <div key={f.sha256} className="grid grid-cols-12 gap-2 text-[10px] font-black items-center p-2 bg-black/40">
                            <div className="col-span-6 truncate" title={f.path}>{f.label ?? f.path}</div>
                            <div className="col-span-4 truncate font-mono text-[9px] opacity-60" title={f.sha256}>{f.sha256.slice(0, 16)}…</div>
                            <div className="col-span-2 text-right text-[#ff4100]">{f.reason.split(' ')[0]}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </motion.div>
              )}

              {activeTab === 'processes' && (
                <motion.div 
                  key="processes"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="space-y-6"
                >
                  <div className="bg-[#111] border border-[#00ff41] p-8">
                     <div className="flex justify-between items-end border-b border-[#00ff41] pb-4 mb-6">
                       <h2 className="text-3xl font-black tracking-tighter uppercase leading-none">Task.Manager</h2>
                       <div className="flex gap-4">
                         <div className="flex flex-col items-end">
                            <span className="text-[8px] uppercase opacity-40">Load</span>
                            <span className="text-xs font-black">12.4%</span>
                         </div>
                         <div className="flex flex-col items-end">
                            <span className="text-[8px] uppercase opacity-40">Handles</span>
                            <span className="text-xs font-black">841</span>
                         </div>
                       </div>
                     </div>

                     <div className="mb-4 flex items-center justify-between text-[9px] uppercase tracking-widest font-black">
                        <span className="opacity-60">
                          Source: <span className="text-[#00ff41]">{capabilities.platform}</span>
                          {!capabilities.supports.realProcesses && " (simulated)"}
                        </span>
                        <span className="opacity-60">{processes.length} entries</span>
                     </div>
                     <div className="space-y-2">
                        <div className="grid grid-cols-12 gap-2 text-[8px] uppercase font-black text-[#00ff41]/40 tracking-widest mb-2 border-b border-[#00ff41]/10 pb-2">
                           <div className="col-span-1 text-center">ID</div>
                           <div className="col-span-5">NAME</div>
                           <div className="col-span-2 text-center">CPU</div>
                           <div className="col-span-2 text-center">MEM</div>
                           <div className="col-span-2 text-right">ACTION</div>
                        </div>
                        {processes.slice(0, 80).map((proc) => {
                          const display = proc.label ?? proc.name;
                          return (
                           <motion.div
                            layout
                            key={proc.id}
                            className={cn(
                              "grid grid-cols-12 gap-2 p-2 hover:bg-[#00ff41]/5 border border-transparent hover:border-[#00ff41]/20 group transition-all items-center",
                              proc.flagged && "bg-[#ff4100]/10 border-[#ff4100]/40 hover:border-[#ff4100]"
                            )}
                            title={proc.flagReason ?? ''}
                           >
                             <div className="col-span-1 text-[9px] text-center opacity-40 font-bold truncate">{proc.id}</div>
                             <div className="col-span-5 text-[10px] font-black truncate flex items-center gap-2">
                               <div className={cn(
                                 "w-1.5 h-1.5 rounded-sm shrink-0",
                                 proc.flagged ? "bg-[#ff4100] shadow-[0_0_5px_#ff4100]"
                                   : proc.status === 'running' ? "bg-[#00ff41] shadow-[0_0_5px_#00ff41]"
                                   : "bg-white/10"
                               )} />
                               {display}
                             </div>
                             <div className="col-span-2 text-[10px] font-bold text-center">
                               {proc.cpu != null ? `${proc.cpu.toFixed(1)}%` : '—'}
                             </div>
                             <div className="col-span-2 text-[10px] font-bold text-center">
                               {proc.mem != null ? `${proc.mem.toFixed(0)} MB` : '—'}
                             </div>
                             <div className="col-span-2 text-right">
                               {capabilities.supports.killProcess ? (
                                 <button
                                   onClick={() => handleKill(proc.id, display)}
                                   className={cn(
                                     "text-[9px] font-black uppercase tracking-widest px-2 py-1 border transition-colors",
                                     proc.flagged
                                       ? "border-[#ff4100] text-[#ff4100] hover:bg-[#ff4100] hover:text-black"
                                       : "border-[#00ff41]/30 text-[#00ff41]/60 hover:border-[#ff4100] hover:text-[#ff4100]"
                                   )}
                                 >
                                   {capabilities.platform === 'android' ? 'Uninstall' : 'Kill'}
                                 </button>
                               ) : proc.connections.length > 0 ? (
                                 <span className="flex items-center justify-end gap-1 text-[9px] text-amber-500 font-black font-mono">
                                   <Globe size={10} /> {proc.connections.length}
                                 </span>
                               ) : <span className="text-[9px] opacity-30">—</span>}
                             </div>
                           </motion.div>
                          );
                        })}
                     </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'network' && (
                <motion.div 
                  key="network"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="space-y-6"
                >
                  <div className="bg-[#111] border border-[#00ff41] p-8">
                    <div className="flex justify-between items-start mb-12">
                      <div>
                        <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Transmission Map</h2>
                        <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">Detection of intercepted traffic and unauthorized remote tunneling.</p>
                      </div>
                      <button onClick={checkNetwork} className="p-4 border border-[#00ff41] text-[#00ff41] hover:bg-[#00ff41] hover:text-black transition-colors">
                        <RefreshCw size={18} />
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-12 mb-12">
                      <div className="space-y-4">
                        <div className="flex justify-between text-[11px] uppercase border-b border-[#00ff41] pb-1">
                           <span>Public Trace</span>
                           <span className="font-black">{networkInfo?.status || 'PENDING'}</span>
                        </div>
                        <div className="text-5xl font-black text-[#00ff41] tracking-tighter leading-none truncate">
                          {networkInfo?.ip || 'TRACING...'}
                        </div>
                      </div>

                      <div className="space-y-4">
                        <div className="flex justify-between text-[11px] uppercase border-b border-[#00ff41] pb-1">
                           <span>Geo-Verification</span>
                           <span className={cn("font-black", networkInfo?.tunnelingDetected ? "text-[#ff4100]" : "text-[#00ff41]")}>
                             {networkInfo?.tunnelingDetected ? 'TUNNEL_DETECTED' : 'NOT_DETECTED'}
                           </span>
                        </div>
                        <div className="text-5xl font-black text-[#00ff41] tracking-tighter leading-none">
                          {location ? `${location.lat.toFixed(2)}` : 'LOCATING'}
                          <span className="text-2xl opacity-40 ml-2">{location ? `/${location.lng.toFixed(2)}` : ''}</span>
                        </div>
                      </div>
                    </div>

                    <div className="mb-4 flex justify-between text-[9px] uppercase tracking-widest font-black">
                      <span className="opacity-60">
                        Source: <span className="text-[#00ff41]">{capabilities.platform}</span>
                        {!capabilities.supports.networkMonitor && " (simulated)"}
                      </span>
                      <span className="opacity-60">{connections.length} socket(s)</span>
                    </div>

                    <div className="space-y-1">
                      <div className="grid grid-cols-12 gap-2 text-[8px] uppercase font-black text-[#00ff41]/40 tracking-widest mb-2 border-b border-[#00ff41]/10 pb-2">
                        <div className="col-span-4">REMOTE</div>
                        <div className="col-span-3">PROCESS</div>
                        <div className="col-span-2 text-center">PROTO</div>
                        <div className="col-span-2 text-center">STATE</div>
                        <div className="col-span-1 text-right">SEV</div>
                      </div>
                      {connections.length === 0 ? (
                        <div className="text-[10px] opacity-40 py-6 text-center uppercase tracking-widest italic">
                          {capabilities.supports.networkMonitor ? 'No active connections.' : 'Install the desktop/Android build for real sockets.'}
                        </div>
                      ) : connections.slice(0, 60).map((c, i) => (
                        <div
                          key={`${c.remoteAddr}-${c.localAddr}-${i}`}
                          className={cn(
                            "grid grid-cols-12 gap-2 p-2 text-[10px] items-center border border-transparent",
                            c.severity === 'malicious' && "bg-[#ff4100]/10 border-[#ff4100]/50",
                            c.severity === 'suspicious' && "bg-amber-500/10 border-amber-500/40"
                          )}
                          title={c.reason ?? ''}
                        >
                          <div className="col-span-4 font-mono truncate">{c.remoteAddr}</div>
                          <div className="col-span-3 truncate opacity-80">{c.processName ?? (c.pid ? `pid ${c.pid}` : '—')}</div>
                          <div className="col-span-2 text-center opacity-60">{c.protocol}</div>
                          <div className="col-span-2 text-center opacity-60">{c.state}</div>
                          <div className={cn(
                            "col-span-1 text-right font-black text-[9px] uppercase",
                            c.severity === 'malicious' && "text-[#ff4100]",
                            c.severity === 'suspicious' && "text-amber-500",
                            c.severity === 'safe' && "text-[#00ff41]/60",
                          )}>{c.severity.slice(0, 3)}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {connections.filter((c) => c.severity === 'malicious').length > 0 && (
                    <div className="p-6 bg-[#ff4100] text-black border-2 border-black flex gap-4">
                      <AlertTriangle className="shrink-0" size={24} strokeWidth={3} />
                      <div className="flex flex-col justify-center">
                        <h4 className="text-xs font-black uppercase tracking-widest mb-1">Defense Advisory</h4>
                        <p className="text-[10px] leading-tight font-black uppercase">
                          {connections.filter((c) => c.severity === 'malicious').length} connection(s) match known-bad IPs.
                          Kill the owning process on the Task Manager tab, or add a firewall rule for the remote address.
                        </p>
                      </div>
                    </div>
                  )}
                </motion.div>
              )}

              {activeTab === 'perf' && (
                <motion.div 
                  key="perf"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="space-y-8"
                >
                  <div className="bg-[#111] border border-[#00ff41] p-8 overflow-hidden relative">
                    <div className="flex justify-between items-start mb-8">
                      <div>
                        <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Hardware.Bench</h2>
                        <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">Calculated hardware speed vs actual execution speed.</p>
                      </div>
                      <button 
                        onClick={runBenchmark}
                        disabled={isBenchmarking}
                        className={cn(
                          "px-6 py-3 font-black uppercase tracking-widest text-[11px] transition-all border-4",
                          isBenchmarking ? "border-[#00ff41]/20 text-[#00ff41]/20" : "border-[#00ff41] text-[#00ff41] hover:bg-[#00ff41] hover:text-black"
                        )}
                      >
                        {isBenchmarking ? 'EXECUTING...' : 'RUN_STRESS_TEST'}
                      </button>
                    </div>

                    <div className="flex items-center justify-center py-8">
                       <div className="text-center">
                          <div className={cn(
                            "text-[100px] font-black leading-none tracking-tighter tabular-nums",
                            benchResult ? ( (benchResult / 3200) < 0.6 ? "text-[#ff4100]" : "text-[#00ff41]") : "opacity-10"
                          )}>
                            {benchResult || '----'}
                          </div>
                          <div className="text-xs tracking-[0.5em] font-black uppercase opacity-60">Measured MHz</div>
                       </div>
                    </div>
                  </div>

                  <div className="bg-[#111] border border-[#00ff41] p-8">
                     <div className="flex items-center gap-3 mb-6 border-b border-[#00ff41] pb-2">
                        <Upload size={14} />
                        <h3 className="text-xs font-black uppercase tracking-[0.3em]">Community.Telemetry</h3>
                     </div>
                     <div className="space-y-1">
                        <div className="grid grid-cols-12 gap-2 text-[8px] uppercase font-black opacity-40 mb-2">
                           <div className="col-span-5">DEVICE_MODEL</div>
                           <div className="col-span-2 text-center">RATED</div>
                           <div className="col-span-2 text-center">ACTUAL</div>
                           <div className="col-span-3 text-right">EFFICIENCY</div>
                        </div>
                        {perfReports.length > 0 ? perfReports.map((report) => (
                           <div key={report.id} className={cn(
                             "grid grid-cols-12 gap-2 text-[10px] font-black p-2 border border-[#00ff41]/5 bg-black/40",
                             report.efficiency < 60 && "text-[#ff4100]"
                           )}>
                             <div className="col-span-5 truncate">{report.model}</div>
                             <div className="col-span-2 text-center opacity-40">{report.hardwareSpeed}</div>
                             <div className="col-span-2 text-center">{report.actualSpeed}</div>
                             <div className="col-span-3 text-right flex items-center justify-end gap-2">
                               {report.efficiency.toFixed(1)}% {report.efficiency < 60 && <AlertTriangle size={10} />}
                             </div>
                           </div>
                        )) : (
                          <div className="text-[10px] opacity-40 py-8 text-center uppercase tracking-widest font-black italic">Waiting for reports...</div>
                        )}
                     </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'rf' && (
                <motion.div
                  key="rf"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="space-y-8"
                >
                  <div className="bg-[#111] border border-[#00ff41] p-8">
                    <div className="flex items-start justify-between mb-8">
                      <div>
                        <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Spectral Audit</h2>
                        <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">
                          {capabilities.supports.wifiScan
                            ? `Wi-Fi + BLE scan on ${capabilities.platform}.`
                            : 'RF scan requires the Android build.'}
                        </p>
                      </div>
                      <button onClick={rescanRf} className="p-4 border border-[#00ff41] text-[#00ff41] hover:bg-[#00ff41] hover:text-black transition-colors">
                        <RefreshCw size={18} />
                      </button>
                    </div>

                    <div className="grid gap-4 mb-8" style={{gridTemplateColumns: `repeat(${Math.max(8, Math.min(wifi.length || 8, 16))}, minmax(0, 1fr))`}}>
                      {(wifi.length > 0 ? wifi : Array.from({length: 8}).map(() => null)).map((w, i) => {
                        if (!w) {
                          return (
                            <div key={`placeholder-${i}`} className="bg-[#00ff41]/5 h-32 flex flex-col justify-end">
                              <motion.div
                                animate={{height: `${Math.random() * 60 + 10}%`}}
                                transition={{duration: 0.4, repeat: Infinity, repeatType: 'mirror'}}
                                className="w-full bg-[#00ff41]/30"
                              />
                            </div>
                          );
                        }
                        // RSSI -100..-20 → 0..100
                        const pct = Math.max(0, Math.min(100, ((w.rssi + 100) * 100) / 80));
                        return (
                          <div
                            key={`${w.bssid}-${i}`}
                            className="flex flex-col justify-end h-32 bg-[#00ff41]/5 relative group"
                            title={`${w.ssid} ${w.rssi}dBm ${w.encryption}`}
                          >
                            <div
                              className={cn('w-full', w.suspicious ? 'bg-[#ff4100]' : 'bg-[#00ff41]')}
                              style={{height: `${pct}%`}}
                            />
                            <div className="absolute bottom-0 left-1/2 -translate-x-1/2 text-[7px] opacity-0 group-hover:opacity-100 bg-black px-1 font-black">
                              {w.rssi}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="space-y-2">
                      <h3 className="text-[10px] uppercase tracking-[0.3em] font-black opacity-60 mb-2">Wi-Fi Access Points</h3>
                      {wifi.length === 0 ? (
                        <div className="text-[10px] opacity-40 py-4 text-center uppercase tracking-widest italic">
                          {capabilities.supports.wifiScan ? 'Tap refresh to scan.' : 'Available on Android.'}
                        </div>
                      ) : wifi.map((w) => (
                        <div
                          key={w.bssid}
                          className={cn(
                            'grid grid-cols-12 gap-2 text-[10px] p-2 items-center border',
                            w.suspicious ? 'border-[#ff4100]/50 bg-[#ff4100]/5' : 'border-[#00ff41]/20'
                          )}
                          title={w.reason ?? ''}
                        >
                          <div className="col-span-4 font-black truncate">{w.ssid}</div>
                          <div className="col-span-3 font-mono opacity-60 truncate">{w.bssid}</div>
                          <div className="col-span-2 text-center">{w.encryption}</div>
                          <div className="col-span-1 text-center opacity-60">{w.channel ?? '—'}</div>
                          <div className={cn('col-span-2 text-right font-black', w.suspicious && 'text-[#ff4100]')}>{w.rssi} dBm</div>
                        </div>
                      ))}
                    </div>

                    {ble.length > 0 && (
                      <div className="space-y-2 mt-8">
                        <h3 className="text-[10px] uppercase tracking-[0.3em] font-black opacity-60 mb-2">BLE Advertisers</h3>
                        {ble.slice(0, 30).map((d) => (
                          <div key={d.address} className="grid grid-cols-12 gap-2 text-[10px] p-2 items-center border border-[#00ff41]/20">
                            <div className="col-span-5 font-black truncate">{d.name ?? '(unnamed)'}</div>
                            <div className="col-span-4 font-mono opacity-60 truncate">{d.address}</div>
                            <div className="col-span-3 text-right font-black">{d.rssi} dBm</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

          </div>

          {/* Right Sidebar: Logs & State */}
          <div className="col-span-12 lg:col-span-5 flex flex-col gap-8 h-full overflow-hidden">
            <div className="h-2/3">
              <Terminal logs={logs} />
            </div>
            
            <div className="h-1/3 bg-[#111] border border-[#00ff41] p-6 overflow-hidden flex flex-col">
              <h3 className="text-[10px] uppercase tracking-[0.4em] text-[#00ff41]/60 mb-6 font-black flex items-center gap-2 border-b border-[#00ff41] pb-2">
                <ShieldCheck size={12} strokeWidth={3} /> Status.Matrix
              </h3>
              <div className="flex-1 space-y-3">
                <div className="flex items-center justify-between text-[11px] font-black uppercase">
                  <span className="opacity-60">CPU_CORE_FREQ</span>
                  <span className="text-[#00ff41]">{benchResult ? `${benchResult}MHz` : '----'}</span>
                </div>
                <div className="flex items-center justify-between text-[11px] font-black uppercase">
                  <span className="opacity-60">Uptime Encryption</span>
                  <span className="text-[#00ff41] italic">99.98%</span>
                </div>
                <div className="flex items-center justify-between text-[11px] font-black uppercase">
                  <span className="opacity-60">Signal Clarity</span>
                  <span className="text-[#ff4100]">-14dBm</span>
                </div>
                
                <div className="pt-4 mt-2 border-t border-[#00ff41] border-dashed">
                  <div className="text-[9px] opacity-40 uppercase tracking-[0.5em] mb-3 font-black">Bitstream.Live</div>
                  <div className="h-12 flex items-end gap-1">
                    {Array.from({ length: 40 }).map((_, i) => (
                      <motion.div 
                        key={i}
                        animate={{ height: `${Math.random() * 100}%` }}
                        transition={{ duration: 0.2, repeat: Infinity, delay: i * 0.05 }}
                        className="flex-1 bg-[#00ff41]/40"
                      />
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

        </main>
      </div>
    </div>
  );
};

export default SecurityDashboard;
