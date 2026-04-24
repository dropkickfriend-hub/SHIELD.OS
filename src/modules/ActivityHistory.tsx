import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'motion/react';
import { Clock, LogIn, LogOut, Camera, Mic, MapPin, Clipboard, Monitor, Eye, Activity as ActivityIcon } from 'lucide-react';
import { cn } from '../lib/utils';

export type ActivityKind =
  | 'login'
  | 'logout'
  | 'tab_open'
  | 'tab_close'
  | 'permission_granted'
  | 'permission_denied'
  | 'permission_used'
  | 'action'
  | 'system';

export interface ActivityEvent {
  id: string;
  ts: number;
  kind: ActivityKind;
  subject: string;
  detail?: string;
  tab?: string;
}

export interface TabUsage {
  tab: string;
  seconds: number;
  lastOpened: number;
  opens: number;
}

interface Props {
  events: ActivityEvent[];
  tabUsage: TabUsage[];
  currentUser: any;
}

const KIND_META: Record<ActivityKind, { label: string; color: string; icon: React.ReactNode }> = {
  login: { label: 'LOGIN', color: 'text-[#00ff41]', icon: <LogIn size={11} /> },
  logout: { label: 'LOGOUT', color: 'text-yellow-400', icon: <LogOut size={11} /> },
  tab_open: { label: 'TAB.OPEN', color: 'text-[#00ff41]/80', icon: <Eye size={11} /> },
  tab_close: { label: 'TAB.CLOSE', color: 'text-[#00ff41]/50', icon: <Monitor size={11} /> },
  permission_granted: { label: 'PERM.GRANT', color: 'text-[#ff4100]', icon: <Camera size={11} /> },
  permission_denied: { label: 'PERM.DENY', color: 'text-[#00ff41]', icon: <Camera size={11} /> },
  permission_used: { label: 'PERM.USE', color: 'text-[#ff4100]', icon: <Mic size={11} /> },
  action: { label: 'ACTION', color: 'text-[#00ff41]/80', icon: <ActivityIcon size={11} /> },
  system: { label: 'SYS', color: 'text-[#00ff41]/60', icon: <Clock size={11} /> },
};

function iconForSubject(subject: string): React.ReactNode {
  const s = subject.toLowerCase();
  if (s.includes('cam')) return <Camera size={11} />;
  if (s.includes('mic')) return <Mic size={11} />;
  if (s.includes('geo') || s.includes('loc')) return <MapPin size={11} />;
  if (s.includes('clip')) return <Clipboard size={11} />;
  if (s.includes('notif') || s.includes('display')) return <Monitor size={11} />;
  return <ActivityIcon size={11} />;
}

export const ActivityHistoryPanel: React.FC<Props> = ({ events, tabUsage, currentUser }) => {
  const [filter, setFilter] = useState<'all' | 'login' | 'perm' | 'tab' | 'action'>('all');
  const [, force] = useState(0);

  useEffect(() => {
    const id = setInterval(() => force(x => x + 1), 1000);
    return () => clearInterval(id);
  }, []);

  const filtered = useMemo(() => {
    if (filter === 'all') return events;
    if (filter === 'login') return events.filter(e => e.kind === 'login' || e.kind === 'logout');
    if (filter === 'perm') return events.filter(e => e.kind.startsWith('permission'));
    if (filter === 'tab') return events.filter(e => e.kind === 'tab_open' || e.kind === 'tab_close');
    if (filter === 'action') return events.filter(e => e.kind === 'action');
    return events;
  }, [events, filter]);

  const totalSeconds = tabUsage.reduce((a, b) => a + b.seconds, 0) || 1;
  const maxSeconds = Math.max(1, ...tabUsage.map(t => t.seconds));

  const loginEvents = events.filter(e => e.kind === 'login' || e.kind === 'logout');
  const permEvents = events.filter(e => e.kind.startsWith('permission'));

  return (
    <div className="space-y-6">
      <div className="bg-[#111] border border-[#00ff41] p-8">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="text-3xl font-black tracking-tighter uppercase leading-none mb-1">Activity.Ledger</h2>
            <p className="text-[#00ff41]/60 text-[10px] uppercase tracking-widest">
              Persistent audit trail: sessions, tab usage, permission grants & uses.
            </p>
          </div>
          <div className="flex flex-col items-end">
            <span className="text-[9px] uppercase tracking-widest opacity-40">Agent</span>
            <span className="text-[11px] font-black truncate max-w-[220px]">
              {currentUser?.email || 'ANONYMOUS SESSION'}
            </span>
          </div>
        </div>

        {/* Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          <div className="bg-[#0a0a0a] border border-[#00ff41] p-4">
            <div className="text-[9px] uppercase tracking-[0.3em] opacity-60 font-black mb-1">Events</div>
            <div className="text-3xl font-black tracking-tighter leading-none">{events.length}</div>
          </div>
          <div className="bg-[#0a0a0a] border border-[#00ff41] p-4">
            <div className="text-[9px] uppercase tracking-[0.3em] opacity-60 font-black mb-1">Logins</div>
            <div className="text-3xl font-black tracking-tighter leading-none">{loginEvents.length}</div>
          </div>
          <div className="bg-[#0a0a0a] border border-[#00ff41] p-4">
            <div className="text-[9px] uppercase tracking-[0.3em] opacity-60 font-black mb-1">Perm Events</div>
            <div className="text-3xl font-black tracking-tighter leading-none text-[#ff4100]">{permEvents.length}</div>
          </div>
          <div className="bg-[#0a0a0a] border border-[#00ff41] p-4">
            <div className="text-[9px] uppercase tracking-[0.3em] opacity-60 font-black mb-1">Session</div>
            <div className="text-3xl font-black tracking-tighter leading-none">
              {Math.floor(totalSeconds / 60)}m
            </div>
          </div>
        </div>

        {/* Tab usage */}
        <div className="bg-[#0a0a0a] border border-[#00ff41] p-4 mb-6">
          <div className="flex items-center justify-between mb-3 border-b border-[#00ff41]/20 pb-1">
            <span className="text-[9px] uppercase tracking-[0.3em] opacity-60 font-black">App Usage</span>
            <span className="text-[9px] uppercase tracking-widest font-black opacity-40">
              {totalSeconds}s tracked
            </span>
          </div>
          <div className="space-y-2">
            {tabUsage.map(t => (
              <div key={t.tab} className="flex items-center gap-2 text-[10px] font-black">
                <div className="w-24 uppercase truncate">{t.tab}</div>
                <div className="flex-1 h-3 bg-[#111] relative overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(t.seconds / maxSeconds) * 100}%` }}
                    className="h-full bg-[#00ff41]"
                  />
                </div>
                <div className="w-14 text-right tabular-nums">
                  {t.seconds < 60 ? `${t.seconds}s` : `${Math.floor(t.seconds / 60)}m${t.seconds % 60}s`}
                </div>
                <div className="w-8 text-right opacity-50">×{t.opens}</div>
              </div>
            ))}
            {tabUsage.length === 0 && (
              <div className="text-[10px] opacity-40 py-4 text-center uppercase tracking-widest font-black italic">
                No usage yet
              </div>
            )}
          </div>
        </div>

        {/* Filter pills */}
        <div className="flex gap-2 mb-3 flex-wrap">
          {(['all', 'login', 'perm', 'tab', 'action'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                'px-3 py-1 text-[9px] font-black uppercase tracking-widest border',
                filter === f
                  ? 'bg-[#00ff41] text-black border-[#00ff41]'
                  : 'border-[#00ff41]/30 text-[#00ff41]/60 hover:border-[#00ff41]'
              )}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Event list */}
        <div className="bg-[#0a0a0a] border border-[#00ff41] max-h-96 overflow-y-auto scrollbar-hide">
          <div className="grid grid-cols-12 gap-2 text-[8px] uppercase font-black opacity-40 p-2 border-b border-[#00ff41]/20 sticky top-0 bg-[#0a0a0a]">
            <div className="col-span-2">TIME</div>
            <div className="col-span-2">KIND</div>
            <div className="col-span-3">SUBJECT</div>
            <div className="col-span-5">DETAIL</div>
          </div>
          {filtered.length === 0 ? (
            <div className="text-[10px] opacity-40 py-8 text-center uppercase tracking-widest font-black italic">
              No events match filter
            </div>
          ) : (
            [...filtered].reverse().map(ev => {
              const meta = KIND_META[ev.kind];
              const age = Math.max(0, Math.floor((Date.now() - ev.ts) / 1000));
              const ageLabel =
                age < 60 ? `${age}s` : age < 3600 ? `${Math.floor(age / 60)}m` : `${Math.floor(age / 3600)}h`;
              return (
                <div
                  key={ev.id}
                  className="grid grid-cols-12 gap-2 p-2 text-[10px] font-mono border-b border-[#00ff41]/5 hover:bg-[#00ff41]/5"
                >
                  <div className="col-span-2 opacity-60 tabular-nums">
                    {new Date(ev.ts).toLocaleTimeString('en-GB', { hour12: false })} · {ageLabel}
                  </div>
                  <div className={cn('col-span-2 font-black flex items-center gap-1', meta.color)}>
                    {meta.icon}
                    {meta.label}
                  </div>
                  <div className="col-span-3 flex items-center gap-1 font-black">
                    {iconForSubject(ev.subject)}
                    <span className="truncate">{ev.subject}</span>
                  </div>
                  <div className="col-span-5 opacity-80 truncate">{ev.detail || ''}</div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

export default ActivityHistoryPanel;
