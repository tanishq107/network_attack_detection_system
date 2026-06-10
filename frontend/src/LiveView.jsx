import React, { useEffect, useRef, useState } from 'react';

const SEV_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
};

const SEV_BADGE = {
  critical: 'bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300',
  high:     'bg-orange-100 text-orange-700 dark:bg-orange-500/15 dark:text-orange-300',
  medium:   'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300',
  low:      'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300',
};

export default function LiveView() {
  const [interfaces, setInterfaces] = useState([]);
  const [iface, setIface] = useState('');
  const [bpf, setBpf] = useState('');
  const [withSuricata, setWithSuricata] = useState(false);
  const [status, setStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const [err, setErr] = useState('');
  const pollRef = useRef(null);

  const loadInterfaces = async () => {
    try {
      const r = await fetch(`/api/live/interfaces?_=${Date.now()}`, { cache: 'no-store' });
      const data = await r.json();
      setInterfaces(data.interfaces || []);
      if (!iface && data.interfaces?.length) setIface(data.interfaces[0]);
    } catch (e) { setErr(String(e)); }
  };

  // `manual=true` flips a visible spinner; the 2.5s background poll keeps
  // manual=false so it stays silent.
  const refresh = async (manual = false) => {
    if (manual) setRefreshing(true);
    try {
      const r = await fetch(`/api/live/status?_=${Date.now()}`, { cache: 'no-store' });
      const s = await r.json();
      setStatus(s);
      if (s.upload_id != null) {
        const a = await fetch(
          `/api/alerts?upload_id=${s.upload_id}&limit=100&_=${Date.now()}`,
          { cache: 'no-store' },
        ).then(x => x.json());
        setAlerts(a);
      }
      setLastRefreshed(Date.now());
    } catch (e) {
      if (manual) setErr(String(e));
    } finally {
      if (manual) setRefreshing(false);
    }
  };

  // also reload the interface list when the user clicks Refresh — hot-plugged
  // adapters etc. would otherwise never appear without a page reload.
  const refreshAll = async () => {
    await Promise.all([refresh(true), loadInterfaces()]);
  };

  useEffect(() => {
    loadInterfaces();
    refresh();
    pollRef.current = setInterval(() => refresh(false), 2500);
    return () => clearInterval(pollRef.current);
  }, []);

  const start = async () => {
    setBusy(true); setErr('');
    try {
      const r = await fetch('/api/live/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: iface,
          bpf_filter: bpf || null,
          with_suricata: withSuricata,
        }),
      });
      if (!r.ok) {
        const data = await r.json();
        throw new Error(data.detail || JSON.stringify(data));
      }
      await refresh();
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  };

  const stop = async () => {
    setBusy(true); setErr('');
    try {
      const r = await fetch('/api/live/stop', { method: 'POST' });
      if (!r.ok) {
        const data = await r.json();
        throw new Error(data.detail || JSON.stringify(data));
      }
      await refresh();
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  };

  const running = !!status?.running;

  return (
    <div>
      <div className="bg-amber-50 border border-amber-200 text-amber-800 dark:bg-amber-500/10 dark:border-amber-500/30 dark:text-amber-300 text-sm px-3 py-2 rounded-lg mb-4">
        <b>Heads up:</b> live capture requires raw-socket privileges. On macOS / Linux start the
        backend with <code>sudo</code> (or grant <code>cap_net_raw</code> to the Python binary).
        Otherwise the start call will fail with a permission error.
      </div>

      <div className="nade-card p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">Sniffer Control</h3>
          <div className="flex items-center gap-3">
            {lastRefreshed && (
              <span className="text-xs text-slate-500 dark:text-slate-400"
                title={new Date(lastRefreshed).toLocaleString()}>
                refreshed {Math.max(0, Math.round((Date.now() - lastRefreshed) / 1000))}s ago
              </span>
            )}
            <button
              onClick={refreshAll}
              disabled={refreshing}
              className="nade-btn-ghost text-xs"
              title="Refresh this tab (status + alerts + interface list)"
            >
              <span className={refreshing ? 'inline-block animate-spin' : ''}>↻</span>
              {refreshing ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <div className="text-slate-500 dark:text-slate-400 mb-1">Interface</div>
            <select className="nade-input min-w-[160px]"
              value={iface} onChange={e => setIface(e.target.value)} disabled={running}>
              {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
            </select>
          </label>
          <label className="text-sm flex-1">
            <div className="text-slate-500 dark:text-slate-400 mb-1">BPF filter (optional)</div>
            <input className="nade-input w-full font-mono text-xs"
              placeholder='e.g. "tcp and not port 22"'
              value={bpf} onChange={e => setBpf(e.target.value)} disabled={running} />
          </label>
          <label className="text-sm flex items-center gap-2 select-none text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              className="accent-brand-600"
              checked={withSuricata}
              onChange={e => setWithSuricata(e.target.checked)}
              disabled={running}
            />
            <span>Run Suricata IDS</span>
          </label>
          {!running ? (
            <button
              disabled={busy || !iface}
              onClick={start}
              className="nade-btn-success disabled:opacity-50"
            >Start</button>
          ) : (
            <button
              disabled={busy}
              onClick={stop}
              className="nade-btn-danger disabled:opacity-50"
            >Stop</button>
          )}
          {status?.upload_id != null && !running && status?.pcap_path && (
            <a
              href={`/api/uploads/${status.upload_id}/download`}
              className="nade-btn-success"
              title="Download the captured packets as a PCAP file"
            >↓ Download capture</a>
          )}
        </div>
        {err && <div className="bg-rose-100 text-rose-800 dark:bg-rose-500/10 dark:text-rose-300 text-sm px-3 py-2 rounded-lg mt-3">{err}</div>}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        <Stat label="State" value={running ? 'running' : 'stopped'}
          accent={running ? 'emerald' : 'slate'} />
        <Stat label="Interface" value={status?.interface || '—'} />
        <Stat label="Packets" value={status?.packet_count ?? 0} />
        <Stat label="Alerts (live)" value={status?.alert_count ?? 0} />
        <Stat label="Buffer (last 60s)" value={status?.buffered_packets ?? 0} />
        <Stat label="Last scan" value={status?.last_scan_at
          ? new Date(status.last_scan_at * 1000).toLocaleTimeString() : '—'} />
        <Stat label="Window / interval"
          value={status ? `${status.window_sec}s / ${status.scan_interval_sec}s` : '—'} />
        <Stat label="PCAP captured"
          value={status?.pcap_bytes ? formatBytes(status.pcap_bytes) : '—'} />
      </div>

      {status?.error && (
        <div className="bg-rose-100 text-rose-800 dark:bg-rose-500/10 dark:text-rose-300 text-sm px-3 py-2 rounded-lg mb-4">
          Sniffer error: {status.error}
        </div>
      )}

      {status?.suricata && (
        <div className="nade-card p-4 mb-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">Suricata IDS</h3>
            <span className={`nade-pill ${status.suricata.running ? 'bg-emerald-500 text-white' : 'bg-slate-400 text-white dark:bg-slate-600'}`}>
              {status.suricata.running ? 'running' : 'stopped'}
            </span>
          </div>
          {status.suricata.error && (
            <div className="bg-rose-100 border border-rose-200 text-rose-800 dark:bg-rose-500/10 dark:border-rose-500/30 dark:text-rose-300 text-sm px-3 py-2 rounded-lg mb-3">
              <b>Suricata error:</b> {status.suricata.error}
            </div>
          )}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <Stat label="Binary" value={status.suricata.binary || '—'} />
            <Stat label="Rules loaded" value={status.suricata.rules ?? 0} />
            <Stat label="Suricata alerts" value={status.suricata.alert_count ?? 0} />
            <Stat label="Started" value={status.suricata.started_at
              ? new Date(status.suricata.started_at * 1000).toLocaleTimeString() : '—'} />
          </div>
          {status.suricata.stderr_tail && (
            <details className="mt-3 text-xs">
              <summary className="cursor-pointer text-slate-500 dark:text-slate-400">stderr tail</summary>
              <pre className="bg-slate-50 dark:bg-slate-900 dark:text-slate-300 p-2 rounded-md overflow-auto max-h-40 text-[10px] font-mono">
{status.suricata.stderr_tail}
              </pre>
            </details>
          )}
        </div>
      )}

      <div className="nade-card overflow-hidden">
        <div className="px-4 py-2 border-b border-slate-200 dark:border-slate-800 text-sm font-semibold text-slate-700 dark:text-slate-200">
          Live Alerts ({alerts.length})
        </div>
        <div className="overflow-auto max-h-[480px]">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-900/60 text-left text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
              <tr>
                <th className="px-3 py-2 font-medium">Time</th>
                <th className="font-medium">Sev</th>
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
                  <td className="px-3 py-1 font-mono text-xs text-slate-500 dark:text-slate-400">
                    {new Date(a.ts * 1000).toLocaleTimeString()}
                  </td>
                  <td>
                    <span className={`nade-pill ${SEV_BADGE[a.severity] || 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200'}`}>
                      {a.severity}
                    </span>
                  </td>
                  <td><code className="text-xs text-slate-500 dark:text-slate-400">{a.category}</code></td>
                  <td className="text-slate-700 dark:text-slate-200">{a.title}</td>
                  <td className="font-mono text-xs">{a.src_ip}</td>
                  <td className="font-mono text-xs">{a.dst_ip}</td>
                  <td><code className="text-xs">{a.mitre_id || '—'}</code></td>
                </tr>
              ))}
              {!alerts.length && (
                <tr><td colSpan="7" className="text-center text-slate-400 dark:text-slate-500 py-6">
                  {running ? 'Listening… alerts appear here as detectors fire.' : 'No live session.'}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, accent = 'slate' }) {
  const accents = {
    slate:   'text-slate-900 dark:text-slate-100',
    emerald: 'text-emerald-600 dark:text-emerald-400',
    rose:    'text-rose-600 dark:text-rose-400',
    brand:   'text-brand-700 dark:text-brand-300',
  };
  return (
    <div className="nade-card px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</div>
      <div className={`text-sm font-semibold ${accents[accent] || accents.slate}`}>{value}</div>
    </div>
  );
}

function formatBytes(n) {
  if (n == null || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
