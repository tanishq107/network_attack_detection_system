import React, { useEffect, useMemo, useState } from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';
import RulesView from './RulesView.jsx';
import LiveView from './LiveView.jsx';
import useTheme from './useTheme.js';

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

const SEV_COLORS = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#d97706',
  low:      '#16a34a',
};

const SEV_BADGE = {
  critical: 'bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300',
  high:     'bg-orange-100 text-orange-700 dark:bg-orange-500/15 dark:text-orange-300',
  medium:   'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300',
  low:      'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300',
};

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const [tab, setTab] = useState('dashboard');
  const [uploads, setUploads] = useState([]);
  const [selected, setSelected] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const [err, setErr] = useState('');
  const [suricataMsg, setSuricataMsg] = useState('');

  // Push theme into Chart.js defaults so axes / legends are readable on dark.
  useEffect(() => {
    const isDark = theme === 'dark';
    ChartJS.defaults.color = isDark ? '#cbd5e1' : '#475569';
    ChartJS.defaults.borderColor = isDark ? 'rgba(148,163,184,0.15)' : 'rgba(148,163,184,0.25)';
    ChartJS.defaults.font.family =
      "'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif";
  }, [theme]);

  const loadUploads = async () => {
    const r = await fetch(`/api/uploads?_=${Date.now()}`, { cache: 'no-store' });
    const data = await r.json();
    setUploads(data);
    if (!selected && data.length) setSelected(data[0].id);
  };

  useEffect(() => { loadUploads(); }, []);

  const reloadSelected = async () => {
    if (selected == null) return;
    const [a, s, t] = await Promise.all([
      fetch(`/api/alerts?upload_id=${selected}&_=${Date.now()}`, { cache: 'no-store' }).then(r => r.json()),
      fetch(`/api/summary?upload_id=${selected}&_=${Date.now()}`, { cache: 'no-store' }).then(r => r.json()),
      fetch(`/api/timeline?upload_id=${selected}&buckets=40&_=${Date.now()}`, { cache: 'no-store' }).then(r => r.json()),
    ]);
    setAlerts(a);
    setSummary(s);
    setTimeline(t);
  };

  const refreshDashboard = async () => {
    setRefreshing(true); setErr('');
    try {
      await loadUploads();
      await reloadSelected();
      setLastRefreshed(Date.now());
    } catch (ex) { setErr(String(ex)); }
    finally { setRefreshing(false); }
  };

  useEffect(() => { reloadSelected(); }, [selected]);

  const onUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setErr('');
    try {
      const fd = new FormData();
      fd.append('file', file);
      const r = await fetch('/api/upload', { method: 'POST', body: fd });
      if (!r.ok) throw new Error(await r.text());
      const data = await r.json();
      await loadUploads();
      setSelected(data.upload.id);
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
      e.target.value = '';
    }
  };

  const runSuricata = async () => {
    if (selected == null) return;
    setBusy(true); setSuricataMsg('');
    try {
      const r = await fetch(`/api/rules/run/${selected}`, { method: 'POST' });
      const data = await r.json();
      setSuricataMsg(
        `Engine: ${data.engine} · rules: ${data.rules ?? data.rules_total ?? '?'} · alerts: ${data.alerts}` +
        (typeof data.cleared === 'number' ? ` · cleared ${data.cleared} prior` : '')
      );
      await reloadSelected();
    } catch (ex) {
      setSuricataMsg(`Error: ${ex}`);
    } finally {
      setBusy(false);
    }
  };

  const deleteSelected = async () => {
    if (selected == null) return;
    const u = uploads.find(x => x.id === selected);
    const label = u ? `#${u.id} ${u.filename}` : `#${selected}`;
    if (!window.confirm(`Delete upload ${label}?\nThis removes its packets, flows, alerts, the stored PCAP, and any cached report.`)) {
      return;
    }
    setBusy(true); setErr(''); setSuricataMsg('');
    try {
      const r = await fetch(`/api/uploads/${selected}`, { method: 'DELETE' });
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        throw new Error(data.detail || `delete failed (${r.status})`);
      }
      const remaining = uploads.filter(x => x.id !== selected);
      const nextId = remaining.length ? remaining[0].id : null;
      setSelected(nextId);
      setAlerts([]); setSummary(null); setTimeline(null);
      await loadUploads();
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
    }
  };

  const chartCommonOptions = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { display: false } },
      y: { grid: { color: theme === 'dark' ? 'rgba(148,163,184,0.1)' : 'rgba(148,163,184,0.2)' } },
    },
  }), [theme]);

  const sevData = summary && {
    labels: Object.keys(summary.by_severity),
    datasets: [{
      data: Object.values(summary.by_severity),
      backgroundColor: Object.keys(summary.by_severity).map(s => SEV_COLORS[s] || '#64748b'),
      borderColor: theme === 'dark' ? '#0f172a' : '#ffffff',
      borderWidth: 2,
    }],
  };
  const catData = summary && {
    labels: Object.keys(summary.by_category),
    datasets: [{
      label: 'alerts',
      data: Object.values(summary.by_category),
      backgroundColor: theme === 'dark' ? '#60a5fa' : '#2563eb',
      borderRadius: 4,
    }],
  };
  const tlData = timeline && {
    labels: timeline.buckets.map(b => new Date(b.ts * 1000).toLocaleTimeString()),
    datasets: [{
      label: 'alerts',
      data: timeline.buckets.map(b => b.count),
      backgroundColor: theme === 'dark' ? '#a78bfa' : '#7c3aed',
      borderRadius: 3,
    }],
  };

  const currentUpload = uploads.find(u => u.id === selected) || null;

  return (
    <div className="min-h-screen">
      <Header
        theme={theme}
        toggleTheme={toggleTheme}
        onUpload={onUpload}
        busy={busy}
      />

      <main className="max-w-7xl mx-auto px-6 py-6">
        <nav className="flex gap-1 mb-6 border-b border-slate-200 dark:border-slate-800">
          <TabBtn active={tab === 'dashboard'} onClick={() => setTab('dashboard')}>Dashboard</TabBtn>
          <TabBtn active={tab === 'rules'} onClick={() => setTab('rules')}>Suricata Rules</TabBtn>
          <TabBtn active={tab === 'live'} onClick={() => setTab('live')}>Live Sniffer</TabBtn>
        </nav>

        {err && (
          <div className="bg-rose-100 border border-rose-200 text-rose-800 dark:bg-rose-500/10 dark:border-rose-500/30 dark:text-rose-300 p-3 rounded-lg mb-4 text-sm">
            {err}
          </div>
        )}

        {tab === 'dashboard' && (
          <div className="animate-fade-in">
            <section className="nade-card p-4 mb-6 flex flex-wrap items-center gap-3">
              <label className="text-sm text-slate-600 dark:text-slate-400">Upload:</label>
              <select
                className="nade-input min-w-[260px]"
                value={selected ?? ''}
                onChange={e => setSelected(Number(e.target.value))}
              >
                {uploads.length === 0 && <option value="">No uploads yet</option>}
                {uploads.map(u => (
                  <option key={u.id} value={u.id}>
                    #{u.id} {u.filename} ({u.packet_count} pkts, {u.status})
                  </option>
                ))}
              </select>
              <RefreshButton
                refreshing={refreshing}
                onClick={refreshDashboard}
                disabled={busy}
                lastRefreshed={lastRefreshed}
              />
              <div className="flex-1" />
              {selected != null && (
                <>
                  <button onClick={runSuricata} disabled={busy}
                    className="nade-btn bg-violet-600 hover:bg-violet-700 text-white dark:bg-violet-500 dark:hover:bg-violet-400">
                    Run Suricata
                  </button>
                  {currentUpload?.has_capture && (
                    <a href={`/api/uploads/${selected}/download`} className="nade-btn-success">
                      ↓ Download PCAP
                    </a>
                  )}
                  <button onClick={deleteSelected} disabled={busy} className="nade-btn-danger">
                    Delete
                  </button>
                  <div className="flex items-center gap-1 text-xs">
                    <ReportLink id={selected} format="html">HTML</ReportLink>
                    <ReportLink id={selected} format="json">JSON</ReportLink>
                    <ReportLink id={selected} format="pdf">PDF</ReportLink>
                  </div>
                </>
              )}
              {suricataMsg && (
                <div className="basis-full text-xs text-slate-500 dark:text-slate-400 pt-1">
                  {suricataMsg}
                </div>
              )}
            </section>

            {summary && (
              <section className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <Card title="Totals" subtitle="Counts for this capture">
                  <div className="grid grid-cols-3 gap-3 mt-1">
                    <StatTile label="Packets" value={fmtNum(summary.totals.packets)} accent="brand" />
                    <StatTile label="Flows" value={fmtNum(summary.totals.flows)} accent="violet" />
                    <StatTile label="Alerts" value={fmtNum(summary.totals.alerts)} accent="rose" />
                  </div>
                </Card>
                <Card title="By Severity">
                  {sevData && Object.keys(summary.by_severity).length
                    ? <div className="h-48"><Doughnut data={sevData} options={{
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, padding: 12 } } },
                        cutout: '60%',
                      }} /></div>
                    : <Empty />}
                </Card>
                <Card title="By Category">
                  {catData && Object.keys(summary.by_category).length
                    ? <div className="h-48"><Bar data={catData} options={chartCommonOptions} /></div>
                    : <Empty />}
                </Card>
              </section>
            )}

            {tlData && (
              <Card title="Alert Timeline" className="mb-6">
                <div className="h-56"><Bar data={tlData} options={chartCommonOptions} /></div>
              </Card>
            )}

            <Card title={`Alerts (${alerts.length})`}>
              <div className="overflow-auto max-h-[480px] -mx-4">
                <table className="w-full text-sm">
                  <thead className="text-left text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/60 sticky top-0">
                    <tr>
                      <th className="px-4 py-2 font-medium">Sev</th>
                      <th className="font-medium">Category</th>
                      <th className="font-medium">Title</th>
                      <th className="font-medium">Src</th>
                      <th className="font-medium">Dst</th>
                      <th className="font-medium">MITRE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.map(a => (
                      <tr key={a.id} className="border-t border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/60">
                        <td className="px-4 py-1.5">
                          <span className={`nade-pill ${SEV_BADGE[a.severity] || 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200'}`}>
                            {a.severity}
                          </span>
                        </td>
                        <td><code className="text-xs text-slate-500 dark:text-slate-400">{a.category}</code></td>
                        <td>{a.title}</td>
                        <td className="font-mono text-xs">{a.src_ip}</td>
                        <td className="font-mono text-xs">{a.dst_ip}</td>
                        <td><code className="text-xs">{a.mitre_id || '—'}</code></td>
                      </tr>
                    ))}
                    {!alerts.length && (
                      <tr><td colSpan="6" className="text-center text-slate-400 dark:text-slate-500 py-8">No alerts</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
        )}

        {tab === 'rules' && <div className="animate-fade-in"><RulesView /></div>}
        {tab === 'live'  && <div className="animate-fade-in"><LiveView /></div>}
      </main>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header / Logo
// ---------------------------------------------------------------------------

function Header({ theme, toggleTheme, onUpload, busy }) {
  return (
    <header className="sticky top-0 z-30 backdrop-blur-md bg-white/80 dark:bg-slate-950/80 border-b border-slate-200 dark:border-slate-800">
      <div className="max-w-7xl mx-auto px-6 py-3 flex items-center gap-4">
        <Logo />
        <div className="flex-1" />
        <ThemeToggle theme={theme} onClick={toggleTheme} />
        <label className="nade-btn-primary cursor-pointer">
          {busy ? (
            <>
              <span className="inline-block animate-spin">↻</span>
              Working…
            </>
          ) : (
            <>
              <span>⬆</span>
              Upload PCAP
            </>
          )}
          <input type="file" accept=".pcap,.pcapng,.cap" hidden onChange={onUpload} disabled={busy} />
        </label>
      </div>
    </header>
  );
}

function Logo() {
  // The four words below align under N-A-D-E so the acronym visibly "spreads"
  // across the full form. Each letter gets its own column with the matching
  // word right beneath it.
  const cols = [
    { letter: 'N', word: 'Network' },
    { letter: 'A', word: 'Attack' },
    { letter: 'D', word: 'Detection' },
    { letter: 'E', word: 'Engine' },
  ];
  return (
    <div className="flex items-center gap-3 select-none">
      <NetworkMark />
      <div className="leading-none">
        <div className="grid grid-cols-4 gap-x-3 items-end">
          {cols.map(({ letter }) => (
            <span
              key={letter}
              className="text-[28px] font-extrabold tracking-tight text-center
                         bg-gradient-to-br from-brand-600 via-brand-500 to-violet-600
                         dark:from-brand-300 dark:via-brand-400 dark:to-violet-300
                         bg-clip-text text-transparent"
            >
              {letter}
            </span>
          ))}
        </div>
        <div className="grid grid-cols-4 gap-x-3 mt-0.5">
          {cols.map(({ word }) => (
            <span
              key={word}
              className="text-[9px] uppercase tracking-[0.14em] text-center font-semibold
                         text-slate-500 dark:text-slate-400"
            >
              {word}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// Compact networking glyph: the mesh links are arranged so the bold strokes
// trace an "N" (left vertical, top-left → bottom-right diagonal, right
// vertical) while faint links keep the network feel. The central hub pulses
// to suggest live traffic.
function NetworkMark() {
  return (
    <div className="relative w-11 h-11 rounded-xl bg-gradient-to-br from-brand-500 via-brand-600 to-violet-600 shadow-soft ring-1 ring-white/10 grid place-items-center overflow-hidden">
      {/* faint scan-line backdrop */}
      <div
        className="absolute inset-0 opacity-30"
        style={{
          backgroundImage:
            'linear-gradient(transparent 0 50%, rgba(255,255,255,0.18) 50% 51%, transparent 51% 100%)',
          backgroundSize: '100% 6px',
        }}
      />
      <svg
        viewBox="0 0 32 32"
        className="relative w-7 h-7 text-white"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {/* faint mesh cross-links (network feel) */}
        <path d="M6 8 L26 8"  strokeWidth="1.1" opacity="0.35" />
        <path d="M6 24 L26 24" strokeWidth="1.1" opacity="0.35" />
        <path d="M6 24 L26 8"  strokeWidth="1"   opacity="0.25" strokeDasharray="1.5 2" />

        {/* highlighted "N" — left vertical, diagonal, right vertical */}
        <g strokeWidth="2.6" filter="url(#nGlow)">
          <path d="M6 24 L6 8"  />
          <path d="M6 8  L26 24" />
          <path d="M26 24 L26 8" />
        </g>

        {/* node endpoints of the N */}
        <circle cx="6"  cy="8"  r="2.2" fill="currentColor" stroke="none" />
        <circle cx="26" cy="8"  r="2.2" fill="currentColor" stroke="none" />
        <circle cx="6"  cy="24" r="2.2" fill="currentColor" stroke="none" />
        <circle cx="26" cy="24" r="2.2" fill="currentColor" stroke="none" />

        {/* pulsing live-traffic dot riding the N's diagonal */}
        <circle r="1.6" fill="#fff" stroke="none" opacity="0.95">
          <animateMotion dur="2.6s" repeatCount="indefinite"
            path="M6 8 L26 24" />
          <animate attributeName="opacity"
            values="0;1;1;0" keyTimes="0;0.15;0.85;1" dur="2.6s" repeatCount="indefinite" />
        </circle>

        <defs>
          <filter id="nGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="0.6" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
      </svg>
    </div>
  );
}

function ThemeToggle({ theme, onClick }) {
  const isDark = theme === 'dark';
  return (
    <button
      onClick={onClick}
      className="nade-btn-ghost"
      title={`Switch to ${isDark ? 'light' : 'dark'} theme`}
      aria-label="Toggle theme"
    >
      {isDark ? '☀' : '☾'}
      <span className="hidden sm:inline">{isDark ? 'Light' : 'Dark'}</span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Small primitives
// ---------------------------------------------------------------------------

function TabBtn({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={`nade-tab ${active ? 'nade-tab-active' : 'nade-tab-inactive'}`}
    >
      {children}
    </button>
  );
}

function Card({ title, subtitle, children, className = '' }) {
  return (
    <div className={`nade-card p-4 ${className}`}>
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{title}</h2>
        {subtitle && <span className="text-xs text-slate-400 dark:text-slate-500">{subtitle}</span>}
      </div>
      {children}
    </div>
  );
}

function Empty() {
  return <p className="text-slate-400 dark:text-slate-500 text-sm">No data</p>;
}

function StatTile({ label, value, accent = 'brand' }) {
  const accents = {
    brand:  'from-brand-500/15 to-brand-500/0 text-brand-700 dark:text-brand-300',
    violet: 'from-violet-500/15 to-violet-500/0 text-violet-700 dark:text-violet-300',
    rose:   'from-rose-500/15 to-rose-500/0 text-rose-700 dark:text-rose-300',
  };
  return (
    <div className={`rounded-lg p-3 bg-gradient-to-br ${accents[accent]} border border-slate-200/60 dark:border-slate-700/60`}>
      <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</div>
      <div className="text-xl font-bold mt-0.5">{value}</div>
    </div>
  );
}

function ReportLink({ id, format, children }) {
  return (
    <a
      href={`/api/report/${id}?format=${format}`}
      target="_blank"
      rel="noreferrer"
      className="px-2 py-1 rounded-md text-brand-700 dark:text-brand-300 hover:bg-brand-50 dark:hover:bg-brand-500/10 font-medium"
    >
      {children}
    </a>
  );
}

function RefreshButton({ refreshing, onClick, disabled, lastRefreshed }) {
  return (
    <div className="flex items-center gap-2">
      <button
        onClick={onClick}
        disabled={disabled || refreshing}
        className="nade-btn-ghost"
        title="Refresh this tab"
      >
        <span className={refreshing ? 'inline-block animate-spin' : ''}>↻</span>
        {refreshing ? 'Refreshing…' : 'Refresh'}
      </button>
      {lastRefreshed && (
        <span className="text-xs text-slate-500 dark:text-slate-400"
          title={new Date(lastRefreshed).toLocaleString()}>
          {Math.max(0, Math.round((Date.now() - lastRefreshed) / 1000))}s ago
        </span>
      )}
    </div>
  );
}

function fmtNum(n) {
  if (n == null) return '—';
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
