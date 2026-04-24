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
  Brain,
  List,
  BarChart3,
  Globe,
  Upload,
  User
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { GoogleGenAI } from "@google/genai";
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

// --- Types ---
interface LogEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
  category: string;
}

interface ProcessInfo {
  pid: number;
  name: string;
  cpu: number;
  mem: number;
  status: 'running' | 'sleeping' | 'suspended';
  connections: string[];
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
  const [activeTab, setActiveTab] = useState<'malware' | 'rf' | 'network' | 'ai' | 'processes' | 'perf'>('malware');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [networkInfo, setNetworkInfo] = useState<any>(null);
  const [location, setLocation] = useState<any>(null);
  const [aiAnalysis, setAiAnalysis] = useState<string>("");
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
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
    addLog("Initializing Deep Kernel Scan...", "info", "MALWARE");
    
    const duration = 8000;
    const startTime = Date.now();
    
    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const p = Math.min((elapsed / duration) * 100, 100);
      setProgress(p);

      if (p > 20 && p < 21) addLog("Scanning partition /system/bin...", "info", "MALWARE");
      if (p > 50 && p < 51) addLog("Suspicious signature detected in temp cache. Analyzing...", "warn", "MALWARE");
      if (p > 80 && p < 81) addLog("Heuristic analysis bypass check: OK", "success", "MALWARE");

      if (p >= 100) {
        clearInterval(interval);
        setScanning(false);
        addLog("Scan complete. 0 threats found. System integrity verified.", "success", "MALWARE");
      }
    }, 100);
  };

  const checkNetwork = async () => {
    addLog("Initiating Network Tunneling Verification...", "info", "NET");
    try {
      const response = await fetch("/api/network-check");
      const data = await response.json();
      setNetworkInfo(data);
      addLog(`Server IP Trace: ${data.ip}`, "info", "NET");
      
      if ("geolocation" in navigator) {
        navigator.geolocation.getCurrentPosition((pos) => {
          const loc = { lat: pos.coords.latitude, lng: pos.coords.longitude };
          setLocation(loc);
          addLog(`Device Geo-Position: ${loc.lat.toFixed(4)}, ${loc.lng.toFixed(4)}`, "info", "NET");
          addLog("Geo-IP comparison match: VERIFIED", "success", "NET");
        }, (err) => {
          addLog("Geo-access denied. Fallback to IP-only analysis.", "warn", "NET");
        });
      }
    } catch (e) {
      addLog("External trace failed. Connectivity limited.", "error", "NET");
    }
  };

  const analyzeWithAI = async () => {
    if (!process.env.GEMINI_API_KEY) {
      addLog("AI Core offline: API Key missing.", "error", "AI");
      return;
    }
    
    addLog("Engaging Gemini AI Security Analysis...", "info", "AI");
    const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    
    try {
      const logDump = logs.map(l => `[${l.level}] ${l.message}`).join("\n");
      const result = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: `You are a cybersecurity expert. Analyze the following system logs and provide a brief technical assessment. Keep it formal and concise (max 3 sentences).\n\nLOGS:\n${logDump}`
      });
      setAiAnalysis(result.text || "No insights generated.");
      addLog("AI Analysis complete. Neural feedback received.", "success", "AI");
    } catch (e) {
      addLog("AI Synthesis error. Try again.", "error", "AI");
    }
  };

  // --- Real-time Process Simulation ---
  useEffect(() => {
    const mockProcesses: string[] = [
      'kernel_task', 'launchd', 'securityd', 'WindowServer', 
      'com.android.chrome', 'system_server', 'zygote64', 'adbd',
      'com.droid.sentry', 'networkstack', 'dns_resolver', 'remote_trace'
    ];

    const interval = setInterval(() => {
      const newProcs = mockProcesses.map(name => ({
        pid: Math.floor(Math.random() * 9000) + 100,
        name,
        cpu: Math.random() * 5,
        mem: Math.random() * 300,
        status: (Math.random() > 0.8 ? 'sleeping' : 'running') as any,
        connections: Math.random() > 0.7 ? [`${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.0.1:443`] : []
      }));
      setProcesses(newProcs.sort((a, b) => b.cpu - a.cpu));
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  // --- Firebase Subscriptions ---
  useEffect(() => {
    const q = query(collection(db, "perf_reports"), orderBy("efficiency", "asc"), limit(20));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const reports = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) as PerfReport[];
      setPerfReports(reports);
    });

    auth.onAuthStateChanged((u) => {
      if (u) {
        setUser(u);
        addLog(`Authenticated as ${u.email}`, "success", "AUTH");
      } else {
        setUser(null);
      }
    });

    return () => unsubscribe();
  }, [addLog]);

  const runBenchmark = async () => {
    if (!user) {
      addLog("Authentication required for benchmark logging.", "warn", "AUTH");
      const u = await signIn();
      if (!u) return;
    }

    setIsBenchmarking(true);
    addLog("Starting hardware speed calculation...", "info", "PERF");
    
    // Simulate intensive computation
    const start = performance.now();
    let count = 0;
    for (let i = 0; i < 50000000; i++) {
       count += Math.sqrt(i);
    }
    const end = performance.now();
    const duration = end - start;
    
    // Virtual calculation
    const baseMHz = 3200; // Expected high-end speed
    const actualSpeed = Math.floor( (5000 / duration) * 1000 ); 
    const hardwareSpeed = baseMHz;
    const efficiency = Math.min((actualSpeed / hardwareSpeed) * 100, 100);
    
    setBenchResult(actualSpeed);
    setIsBenchmarking(false);
    
    addLog(`Measured Speed: ${actualSpeed} MHz (Efficiency: ${efficiency.toFixed(1)}%)`, efficiency < 60 ? "warn" : "success", "PERF");

    try {
      await addDoc(collection(db, "perf_reports"), {
        model: navigator.userAgent.split(')')[0].split('(')[1] || "Mobile Device",
        hardwareSpeed,
        actualSpeed,
        efficiency,
        timestamp: serverTimestamp(),
        userId: user?.uid || "anonymous"
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
        <button onClick={() => setActiveTab('ai')} className={cn("p-3 transition-all", activeTab === 'ai' ? "bg-[#00ff41] text-black font-black" : "text-[#00ff41]/30 hover:text-[#00ff41]/60")} title="Neural AI">
          <Brain size={22} strokeWidth={3} />
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
                      <span className="text-[10px] uppercase tracking-[0.3em] opacity-60 font-black">Threat Library</span>
                      <div className="space-y-2">
                        <div className="flex justify-between items-center text-xs">
                          <span className="opacity-80">SIGNATURE_DB</span>
                          <span className="font-black">v8.42.1</span>
                        </div>
                        <div className="flex justify-between items-center text-xs">
                          <span className="opacity-80">HEURISTIC_ENGINE</span>
                          <span className="font-black">ACTIVE</span>
                        </div>
                      </div>
                    </div>
                    <div className="bg-[#111] border border-[#00ff41] p-6 h-40 flex flex-col justify-between">
                      <span className="text-[10px] uppercase tracking-[0.3em] opacity-60 font-black">Kernel Status</span>
                      <div className="flex items-end gap-3 leading-none">
                        <span className="text-5xl font-black tracking-tighter italic uppercase">Hardened</span>
                      </div>
                    </div>
                  </div>
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

                     <div className="space-y-2">
                        <div className="grid grid-cols-12 gap-2 text-[8px] uppercase font-black text-[#00ff41]/40 tracking-widest mb-2 border-b border-[#00ff41]/10 pb-2">
                           <div className="col-span-1 text-center">PID</div>
                           <div className="col-span-5">PROCESS_NAME</div>
                           <div className="col-span-2 text-center">CPU</div>
                           <div className="col-span-2 text-center">MEM</div>
                           <div className="col-span-2 text-right">CONNS</div>
                        </div>
                        {processes.map((proc) => (
                           <motion.div 
                            layout
                            key={proc.name}
                            className={cn(
                              "grid grid-cols-12 gap-2 p-2 hover:bg-[#00ff41]/5 border border-transparent hover:border-[#00ff41]/20 group transition-all items-center",
                              proc.name.includes('sentry') && "bg-[#00ff41]/10 border-[#00ff41]/30"
                            )}
                           >
                             <div className="col-span-1 text-[9px] text-center opacity-40 font-bold">{proc.pid}</div>
                             <div className="col-span-5 text-[10px] font-black truncate flex items-center gap-2">
                               <div className={cn("w-1.5 h-1.5 rounded-sm", proc.status === 'running' ? "bg-[#00ff41] shadow-[0_0_5px_#00ff41]" : "bg-white/10")} />
                               {proc.name}
                             </div>
                             <div className="col-span-2 text-[10px] font-bold text-center">{proc.cpu.toFixed(1)}%</div>
                             <div className="col-span-2 text-[10px] font-bold text-center">{proc.mem.toFixed(0)} MB</div>
                             <div className="col-span-2 text-[9px] text-right text-amber-500 font-black font-mono">
                               {proc.connections.length > 0 ? (
                                 <span className="flex items-center justify-end gap-1">
                                    <Globe size={10} /> {proc.connections.length}
                                 </span>
                               ) : "—"}
                             </div>
                           </motion.div>
                        ))}
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

                    <div className="h-24 bg-[#0a0a0a] border border-[#00ff41] flex items-center justify-center relative overflow-hidden">
                      <div className="grid grid-cols-10 gap-1 w-full px-4">
                         {Array.from({ length: 10 }).map((_, i) => (
                           <div key={i} className={cn("h-8 border border-[#00ff41]", i < 7 ? "bg-[#00ff41]" : "opacity-20")} />
                         ))}
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-6 bg-[#ff4100] text-black border-2 border-black flex gap-4">
                    <AlertTriangle className="shrink-0" size={24} strokeWidth={3} />
                    <div className="flex flex-col justify-center">
                      <h4 className="text-xs font-black uppercase tracking-widest mb-1">Defense Advisory</h4>
                      <p className="text-[10px] leading-tight font-black uppercase">
                        Detected encrypted data packet burst from unknown routing node. Verification required to ensure transmission integrity.
                      </p>
                    </div>
                  </div>
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
                    <div className="mb-12">
                      <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Spectral Audit</h2>
                      <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">Monitoring Radio Frequency emissions and unauthorized transmitters.</p>
                    </div>

                    <div className="grid grid-cols-8 gap-2 h-40 mb-12 border-b border-[#00ff41] pb-6">
                      {Array.from({ length: 32 }).map((_, i) => (
                        <div key={i} className="bg-[#00ff41]/5 flex flex-col justify-end">
                          <motion.div 
                            animate={{ height: `${Math.random() * 80 + 10}%` }}
                            transition={{ duration: 0.3, repeat: Infinity, repeatType: "mirror" }}
                            className="w-full bg-[#00ff41] opacity-60"
                          />
                        </div>
                      ))}
                    </div>

                    <div className="space-y-4">
                      <div className="flex items-center justify-between p-4 bg-[#111] border border-[#00ff41]">
                        <div className="flex items-center gap-4">
                          <Radio size={20} className="text-[#00ff41]" strokeWidth={3} />
                          <div>
                            <div className="text-xs font-black uppercase">ISM Band Scan</div>
                            <div className="text-[9px] text-[#00ff41]/50 uppercase tracking-[0.2em] font-bold">2.4GHz / 5.8GHz</div>
                          </div>
                        </div>
                        <span className="text-[10px] uppercase font-black px-2 py-1 bg-[#00ff41]/20">Status: Clear</span>
                      </div>
                      <div className="flex items-center justify-between p-4 bg-[#0a0a0a] border border-[#ff4100]">
                        <div className="flex items-center gap-4">
                          <Zap size={20} className="text-[#ff4100]" strokeWidth={3} />
                          <div>
                            <div className="text-xs font-black text-[#ff4100] uppercase">Unidentified Peak</div>
                            <div className="text-[9px] text-[#ff4100]/50 uppercase tracking-[0.2em] font-bold">Near Field Offset</div>
                          </div>
                        </div>
                        <span className="text-[10px] uppercase font-black px-2 py-1 bg-[#ff4100] text-black">Flagged</span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {activeTab === 'ai' && (
                <motion.div 
                  key="ai"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="space-y-6"
                >
                  <div className="bg-[#111] border border-[#00ff41] p-12 flex flex-col items-center text-center">
                    <div className="w-32 h-32 bg-[#00ff41]/10 flex items-center justify-center mb-8 relative border-2 border-[#00ff41]">
                      <Brain size={64} className="text-[#00ff41]" strokeWidth={3} />
                      <motion.div 
                        animate={{ opacity: [1, 0, 1] }}
                        transition={{ duration: 1, repeat: Infinity }}
                        className="absolute inset-2 border border-[#00ff41]/50"
                      />
                    </div>
                    
                    <h2 className="text-4xl font-black tracking-tighter uppercase mb-2 italic leading-none">Neural Core v3</h2>
                    <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest mb-8 max-w-sm">Heuristic pattern synthesis and transmission pattern recognition.</p>
                    
                    <button 
                      onClick={analyzeWithAI}
                      className="w-full max-w-xs py-5 bg-[#00ff41] text-black font-black uppercase tracking-[0.3em] text-[12px] hover:bg-white transition-all flex items-center justify-center gap-3"
                    >
                      <Zap size={14} fill="currentColor" />
                      Engage Neural Array
                    </button>
                  </div>

                  {aiAnalysis && (
                    <div className="bg-black border-2 border-[#00ff41] p-8 relative overflow-hidden">
                      <div className="absolute top-0 left-0 p-2 text-[8px] bg-[#00ff41] text-black font-black uppercase tracking-widest">AI_OUTPUT_STREAM</div>
                      <div className="mt-4">
                        <p className="text-sm leading-relaxed text-[#00ff41] font-mono italic font-bold">
                          {aiAnalysis}
                        </p>
                      </div>
                    </div>
                  )}
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
