import React, { useEffect, useMemo, useState } from 'react';

const SOURCE_BADGE = {
  bundled:  'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-300',
  custom:   'bg-blue-100 text-blue-800 dark:bg-blue-500/15 dark:text-blue-300',
  imported: 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300',
};

const TEMPLATE = `alert tcp any any -> any 8080 (msg:"My custom rule"; flow:stateless; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:9000001; rev:1; metadata:mitre T1046;)`;

export default function RulesView() {
  const [data, setData] = useState({ rules: [], engine: '', binary: null, count: 0 });
  const [filter, setFilter] = useState('all');     // all|bundled|custom|imported
  const [search, setSearch] = useState('');
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const [msg, setMsg] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [form, setForm] = useState({ name: '', category: 'custom', rule_text: TEMPLATE });
  const [importForm, setImportForm] = useState({ url: '', text: '', source_label: 'imported' });

  const load = async () => {
    setRefreshing(true);
    try {
      // cache-bust to defeat any browser caching of the GET
      const r = await fetch(`/api/rules?_=${Date.now()}`, { cache: 'no-store' });
      setData(await r.json());
      setLastRefreshed(Date.now());
    } finally {
      setRefreshing(false);
    }
  };
  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    let rs = data.rules;
    if (filter !== 'all') rs = rs.filter(r => r.source === filter);
    if (search.trim()) {
      const q = search.toLowerCase();
      rs = rs.filter(r =>
        r.name.toLowerCase().includes(q)
        || r.category.toLowerCase().includes(q)
        || String(r.sid).includes(q)
        || (r.mitre_id || '').toLowerCase().includes(q)
        || r.rule_text.toLowerCase().includes(q)
      );
    }
    return rs;
  }, [data.rules, filter, search]);

  const toggle = async (rule) => {
    setBusy(true);
    try {
      const r = await fetch(`/api/rules/${rule.id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      if (!r.ok) throw new Error(await r.text());
      await load();
    } catch (e) { setMsg(String(e)); }
    finally { setBusy(false); }
  };

  const remove = async (rule) => {
    if (!confirm(`Delete rule SID ${rule.sid} (${rule.name})?`)) return;
    setBusy(true);
    try {
      const r = await fetch(`/api/rules/${rule.id}`, { method: 'DELETE' });
      if (!r.ok && r.status !== 204) throw new Error(await r.text());
      await load();
    } catch (e) { setMsg(String(e)); }
    finally { setBusy(false); }
  };

  const create = async () => {
    setBusy(true); setMsg('');
    try {
      const r = await fetch('/api/rules', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!r.ok) throw new Error(await r.text());
      setShowCreate(false);
      setForm({ name: '', category: 'custom', rule_text: TEMPLATE });
      setMsg('Rule created.');
      await load();
    } catch (e) { setMsg(`Error: ${e}`); }
    finally { setBusy(false); }
  };

  const importRules = async () => {
    setBusy(true); setMsg('');
    try {
      const r = await fetch('/api/rules/import', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(importForm),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || JSON.stringify(data));
      setMsg(`Imported: added ${data.added}, skipped ${data.skipped}`);
      setShowImport(false);
      await load();
    } catch (e) { setMsg(`Error: ${e}`); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <div className="nade-card p-3 flex flex-wrap items-center gap-3 mb-4">
        <div className="text-sm text-slate-700 dark:text-slate-300">
          Engine: <code className="bg-slate-100 dark:bg-slate-800 dark:text-slate-200 px-1.5 py-0.5 rounded text-xs">{data.engine}</code>
          {data.binary && <span className="ml-1 text-xs text-slate-500 dark:text-slate-400">({data.binary})</span>}
          <span className="ml-3 text-slate-500 dark:text-slate-400">{data.count} rules total</span>
        </div>
        <div className="flex-1" />
        {lastRefreshed && (
          <span className="text-xs text-slate-500 dark:text-slate-400" title={new Date(lastRefreshed).toLocaleString()}>
            refreshed {Math.max(0, Math.round((Date.now() - lastRefreshed) / 1000))}s ago
          </span>
        )}
        <button
          className="nade-btn-ghost"
          onClick={load}
          disabled={busy || refreshing}
          title="Refresh this tab"
        >
          <span className={refreshing ? 'inline-block animate-spin' : ''}>↻</span>
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
        <select className="nade-input text-sm" value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="all">All sources</option>
          <option value="bundled">Bundled</option>
          <option value="custom">Custom</option>
          <option value="imported">Imported</option>
        </select>
        <input
          className="nade-input text-sm"
          placeholder="Search SID / name / MITRE…"
          value={search} onChange={e => setSearch(e.target.value)}
        />
        <button
          className="nade-btn-primary text-sm"
          onClick={() => setShowCreate(s => !s)}
        >+ New rule</button>
        <button
          className="nade-btn bg-amber-500 hover:bg-amber-600 text-white dark:bg-amber-500 dark:hover:bg-amber-400 text-sm"
          onClick={() => setShowImport(s => !s)}
        >Import…</button>
      </div>

      {msg && <div className="bg-slate-100 border border-slate-200 text-slate-700 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300 text-sm px-3 py-2 rounded-lg mb-4">{msg}</div>}

      {showCreate && (
        <div className="nade-card p-4 mb-4 animate-fade-in">
          <h3 className="text-sm font-semibold mb-3 text-slate-700 dark:text-slate-200">Create custom rule</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-2">
            <label className="text-sm text-slate-600 dark:text-slate-400">
              Name
              <input className="nade-input w-full mt-1"
                value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="Short description" />
            </label>
            <label className="text-sm text-slate-600 dark:text-slate-400">
              Category
              <input className="nade-input w-full mt-1"
                value={form.category} onChange={e => setForm({ ...form, category: e.target.value })} />
            </label>
          </div>
          <label className="text-sm block text-slate-600 dark:text-slate-400">
            Rule text (Suricata syntax)
            <textarea
              className="nade-input w-full mt-1 font-mono text-xs"
              rows={5}
              value={form.rule_text}
              onChange={e => setForm({ ...form, rule_text: e.target.value })}
            />
          </label>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Tip: include <code>sid:NNNNNNN</code> (≥ 1,000,000); MITRE via <code>metadata:mitre T1046;</code>.
          </p>
          <div className="mt-3 flex gap-2">
            <button disabled={busy || !form.name || !form.rule_text}
              className="nade-btn-primary text-sm disabled:opacity-50"
              onClick={create}>Save</button>
            <button className="nade-btn-ghost text-sm" onClick={() => setShowCreate(false)}>Cancel</button>
          </div>
        </div>
      )}

      {showImport && (
        <div className="nade-card p-4 mb-4 animate-fade-in">
          <h3 className="text-sm font-semibold mb-3 text-slate-700 dark:text-slate-200">Import rules</h3>
          <label className="text-sm block mb-2 text-slate-600 dark:text-slate-400">
            URL (e.g. an Emerging Threats `.rules` file)
            <input className="nade-input w-full mt-1"
              placeholder="https://rules.emergingthreats.net/open/suricata-7/rules/emerging-scan.rules"
              value={importForm.url}
              onChange={e => setImportForm({ ...importForm, url: e.target.value })} />
          </label>
          <label className="text-sm block mb-2 text-slate-600 dark:text-slate-400">
            …or paste rule text
            <textarea className="nade-input w-full mt-1 font-mono text-xs"
              rows={5}
              value={importForm.text}
              onChange={e => setImportForm({ ...importForm, text: e.target.value })} />
          </label>
          <label className="text-sm block text-slate-600 dark:text-slate-400">
            Source label
            <input className="nade-input mt-1"
              value={importForm.source_label}
              onChange={e => setImportForm({ ...importForm, source_label: e.target.value })} />
          </label>
          <div className="mt-3 flex gap-2">
            <button disabled={busy || (!importForm.url && !importForm.text)}
              className="nade-btn bg-amber-500 hover:bg-amber-600 text-white dark:bg-amber-500 dark:hover:bg-amber-400 text-sm disabled:opacity-50"
              onClick={importRules}>Import</button>
            <button className="nade-btn-ghost text-sm" onClick={() => setShowImport(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="nade-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 dark:bg-slate-900/60 text-left text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">
            <tr>
              <th className="px-3 py-2 font-medium">SID</th>
              <th className="font-medium">Name</th>
              <th className="font-medium">Category</th>
              <th className="font-medium">MITRE</th>
              <th className="font-medium">Source</th>
              <th className="font-medium">Enabled</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(r => (
              <RuleRow key={r.id} rule={r} onToggle={() => toggle(r)} onDelete={() => remove(r)} />
            ))}
            {!filtered.length && (
              <tr><td colSpan="7" className="text-center text-slate-400 dark:text-slate-500 py-6">No rules match.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RuleRow({ rule, onToggle, onDelete }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <>
      <tr className="border-t border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/60">
        <td className="px-3 py-2 font-mono text-xs text-slate-500 dark:text-slate-400">{rule.sid}</td>
        <td>
          <button className="text-left text-slate-700 dark:text-slate-200 hover:underline" onClick={() => setExpanded(e => !e)}>
            {rule.name}
          </button>
        </td>
        <td><code className="text-xs text-slate-500 dark:text-slate-400">{rule.category}</code></td>
        <td><code className="text-xs text-slate-500 dark:text-slate-400">{rule.mitre_id || '—'}</code></td>
        <td>
          <span className={`nade-pill ${SOURCE_BADGE[rule.source] || 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-200'}`}>
            {rule.source}
          </span>
        </td>
        <td>
          <button
            onClick={onToggle}
            className={`text-xs px-2 py-0.5 rounded-md font-medium ${rule.enabled ? 'bg-emerald-600 text-white dark:bg-emerald-500' : 'bg-slate-300 text-slate-700 dark:bg-slate-700 dark:text-slate-300'}`}
          >{rule.enabled ? 'on' : 'off'}</button>
        </td>
        <td className="pr-3 text-right">
          {rule.source !== 'bundled' && (
            <button onClick={onDelete} className="text-xs text-rose-600 dark:text-rose-400 hover:underline">delete</button>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-slate-50 dark:bg-slate-900/60">
          <td colSpan="7" className="px-3 py-2">
            <pre className="font-mono text-xs whitespace-pre-wrap text-slate-700 dark:text-slate-300">{rule.rule_text}</pre>
          </td>
        </tr>
      )}
    </>
  );
}
