"""
Web Dashboard — Flask app with Server-Sent Events live-scan progress updates.

Serves a minimal dark-mode HTML UI that shows:
- Historical scan overview
- Per-detector findings
- Real-time progress via Server-Sent Events (SSE)

Usage:
    python -m agents.web --port 8000 --db ~/.local/state/rushingtech-agents/evolution.db

Then open http://localhost:8000 in your browser.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import sqlite3
import threading
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Minimal HTML template (single file, no build step)
# ---------------------------------------------------------------------------
_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>agents — findings</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root {
  --ink: #0b0f17; --panel: #121826; --panel-2: #182033; --line: #212b45;
  --text: #e8edf7; --muted: #8b96b0; --accent: #22d3ee; --accent-ink: #062b33;
  --violet: #a78bfa;
  --critical: #fb7185; --high: #fb923c; --medium: #facc15; --low: #4ade80; --info: #60a5fa;
  --shadow: 0 20px 60px rgba(0,0,0,.45);
}
:root[data-theme="light"] {
  --ink: #f4f6fb; --panel: #ffffff; --panel-2: #f1f4fa; --line: #dfe5f0;
  --text: #0f172a; --muted: #5b6478; --accent: #0891b2; --accent-ink: #ffffff;
  --violet: #6d28d9;
  --critical: #e11d48; --high: #c2410c; --medium: #a16207; --low: #15803d; --info: #1d4ed8;
  --shadow: 0 16px 40px rgba(15,23,42,.10);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { background: var(--ink); }
body {
  min-height: 100vh; color: var(--text);
  font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 15px; line-height: 1.5;
  background:
    radial-gradient(900px 500px at 10% -10%, rgba(34,211,238,.14), transparent 60%),
    radial-gradient(700px 400px at 100% 0%, rgba(167,139,250,.12), transparent 60%),
    var(--ink);
}
a { color: var(--accent); }
code, .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace; }
.display { font-family: "Space Grotesk", Inter, sans-serif; letter-spacing: -.02em; }

header {
  position: sticky; top: 0; z-index: 5; backdrop-filter: blur(14px);
  background: color-mix(in srgb, var(--ink) 80%, transparent); border-bottom: 1px solid var(--line);
}
.bar { max-width: 1080px; margin: 0 auto; padding: 14px 20px; display: flex; align-items: center; gap: 14px; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 17px; }
.brand .mark { width: 28px; height: 28px; border-radius: 8px; background: linear-gradient(135deg, var(--accent), var(--violet)); display: grid; place-items: center; color: #0b0f17; font-family: "JetBrains Mono", monospace; font-weight: 700; font-size: 13px; }
.brand small { color: var(--muted); font-weight: 500; font-size: 12px; margin-left: 4px; }
.spacer { flex: 1; }
.live { display: inline-flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); padding: 6px 10px; border: 1px solid var(--line); border-radius: 999px; background: var(--panel); }
.live .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
.live[data-state="live"] .dot { background: var(--low); box-shadow: 0 0 0 0 rgba(74,222,128,.6); animation: pulse 2s infinite; }
.live[data-state="lost"] .dot { background: var(--critical); }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(74,222,128,.5);} 70% { box-shadow: 0 0 0 8px rgba(74,222,128,0);} 100% { box-shadow: 0 0 0 0 rgba(74,222,128,0);} }
.btn { cursor: pointer; background: var(--panel); border: 1px solid var(--line); color: var(--text); border-radius: 8px; padding: 7px 11px; font: inherit; font-size: 13px; }
.btn:hover { border-color: var(--accent); }
.btn:focus-visible, .chip:focus-visible, .card summary:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

main { max-width: 1080px; margin: 0 auto; padding: 28px 20px 64px; }

/* Attention hero */
.hero { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); gap: 18px; margin-bottom: 26px; }
.attention { position: relative; overflow: hidden; background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 22px 24px; box-shadow: var(--shadow); }
.attention .eyebrow { font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.attention .big { font-size: clamp(56px, 12vw, 96px); line-height: 1; font-weight: 700; margin: 6px 0 2px; }
.attention .big.hot { color: var(--critical); text-shadow: 0 0 40px rgba(251,113,133,.35); }
.attention .big.ok { color: var(--low); }
.attention .sub { color: var(--muted); font-size: 14px; }
.attention .glow { position: absolute; inset: auto -40px -60px auto; width: 220px; height: 220px; border-radius: 50%; background: radial-gradient(circle, rgba(251,113,133,.25), transparent 65%); pointer-events: none; }
.attention.ok .glow { background: radial-gradient(circle, rgba(74,222,128,.22), transparent 65%); }
.stats { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 12px; }
.stat { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; }
.stat .label { font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.stat .value { font-size: 28px; font-weight: 700; line-height: 1.15; margin-top: 4px; }
.stat .hint { font-size: 12px; color: var(--muted); margin-top: 2px; }

/* Filters */
.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 0 0 14px; }
.chip { cursor: pointer; border: 1px solid var(--line); background: var(--panel); color: var(--muted); border-radius: 999px; padding: 6px 12px; font: inherit; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
.chip .n { font-family: "JetBrains Mono", monospace; font-weight: 600; }
.chip[aria-pressed="true"] { color: var(--text); border-color: var(--sev, var(--accent)); box-shadow: inset 0 0 0 1px var(--sev, var(--accent)); }
.chip[data-sev="CRITICAL"] { --sev: var(--critical); } .chip[data-sev="HIGH"] { --sev: var(--high); }
.chip[data-sev="MEDIUM"] { --sev: var(--medium); } .chip[data-sev="LOW"] { --sev: var(--low); } .chip[data-sev="INFO"] { --sev: var(--info); }
.search { flex: 1; min-width: 180px; background: var(--panel); border: 1px solid var(--line); color: var(--text); border-radius: 10px; padding: 8px 12px; font: inherit; font-size: 13px; }
.search::placeholder { color: var(--muted); }

/* Finding cards — styled as code-review annotations */
.list { display: grid; gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; position: relative; }
.card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--sev); }
.card[data-sev="CRITICAL"] { --sev: var(--critical); } .card[data-sev="HIGH"] { --sev: var(--high); }
.card[data-sev="MEDIUM"] { --sev: var(--medium); } .card[data-sev="LOW"] { --sev: var(--low); } .card[data-sev="INFO"] { --sev: var(--info); }
.card summary { list-style: none; cursor: pointer; padding: 14px 16px 14px 20px; display: grid; grid-template-columns: auto minmax(0,1fr) auto; gap: 12px; align-items: start; }
.card summary::-webkit-details-marker { display: none; }
.badge { font-family: "JetBrains Mono", monospace; font-size: 11px; font-weight: 600; letter-spacing: .04em; color: var(--sev); border: 1px solid color-mix(in srgb, var(--sev) 50%, transparent); background: color-mix(in srgb, var(--sev) 12%, transparent); border-radius: 6px; padding: 3px 7px; white-space: nowrap; margin-top: 2px; }
.title { font-weight: 600; font-size: 15px; }
.where { margin-top: 4px; font-size: 12.5px; color: var(--muted); display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: center; }
.where a { text-decoration: none; font-weight: 600; }
.where .loc { font-family: "JetBrains Mono", monospace; font-size: 12px; color: var(--text); word-break: break-all; }
.where .loc b { color: var(--accent); font-weight: 600; }
.caret { color: var(--muted); transition: transform .2s; margin-top: 4px; }
.card[open] .caret { transform: rotate(180deg); }
.body { padding: 0 16px 16px 20px; display: grid; gap: 12px; }
.snippet { background: var(--ink); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; font-family: "JetBrains Mono", monospace; font-size: 12.5px; overflow-x: auto; white-space: pre; }
.snippet .gutter { color: var(--muted); user-select: none; }
.snippet .plus { color: var(--low); font-weight: 600; }
.note { border-left: 2px solid var(--line); padding: 2px 0 2px 12px; }
.note h4 { font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-bottom: 4px; }
.note.why { border-color: var(--sev); }
.note.fix { border-color: var(--accent); }
.note p { font-size: 14px; }
.meta { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: center; font-size: 12px; color: var(--muted); }
.tag { font-family: "JetBrains Mono", monospace; font-size: 11px; color: var(--violet); border: 1px solid color-mix(in srgb, var(--violet) 40%, transparent); border-radius: 6px; padding: 2px 6px; }
.copy { margin-left: auto; }
.empty { border: 1px dashed var(--line); border-radius: 14px; padding: 28px 20px; text-align: center; color: var(--muted); }
.empty code { color: var(--text); }

/* Live feed */
.feed { margin-top: 26px; background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; font-family: "JetBrains Mono", monospace; font-size: 12px; color: var(--muted); max-height: 180px; overflow-y: auto; }
.feed .t { color: var(--muted); margin-right: 8px; }
.feed .ev { color: var(--text); }
.feed .err { color: var(--critical); }

@media (max-width: 720px) {
  .hero { grid-template-columns: 1fr; }
  .stats { grid-template-columns: repeat(2, minmax(0,1fr)); }
  .card summary { grid-template-columns: auto minmax(0,1fr); }
  .caret { display: none; }
}
@media (prefers-reduced-motion: reduce) { .live .dot, .caret { animation: none; transition: none; } }
</style>
</head>
<body>
<header>
  <div class="bar">
    <div class="brand display"><span class="mark">&gt;_</span>agents<small id="version"></small></div>
    <span class="spacer"></span>
    <span class="live" id="live" data-state="idle"><span class="dot"></span><span id="live-text">connecting</span></span>
    <button class="btn" id="theme" type="button" aria-label="Toggle light and dark theme">◐</button>
  </div>
</header>

<main>
  <section class="hero">
    <div class="attention" id="attention">
      <div class="glow"></div>
      <div class="eyebrow">Needs attention</div>
      <div class="big display" id="attn-count">–</div>
      <div class="sub" id="attn-sub">critical and high findings across every recorded scan</div>
    </div>
    <div class="stats">
      <div class="stat"><div class="label">Scans</div><div class="value display" id="s-scans">–</div><div class="hint" id="s-last">no scans yet</div></div>
      <div class="stat"><div class="label">Findings</div><div class="value display" id="s-findings">–</div><div class="hint" id="s-projects"></div></div>
      <div class="stat"><div class="label">Medium</div><div class="value display" style="color:var(--medium)" id="s-medium">–</div><div class="hint">worth a look</div></div>
      <div class="stat"><div class="label">Low / info</div><div class="value display" style="color:var(--low)" id="s-low">–</div><div class="hint">housekeeping</div></div>
    </div>
  </section>

  <div class="toolbar" id="filters" role="group" aria-label="Filter by severity">
    <button class="chip" data-sev="CRITICAL" aria-pressed="false" type="button">Critical <span class="n">0</span></button>
    <button class="chip" data-sev="HIGH" aria-pressed="false" type="button">High <span class="n">0</span></button>
    <button class="chip" data-sev="MEDIUM" aria-pressed="false" type="button">Medium <span class="n">0</span></button>
    <button class="chip" data-sev="LOW" aria-pressed="false" type="button">Low <span class="n">0</span></button>
    <button class="chip" data-sev="INFO" aria-pressed="false" type="button">Info <span class="n">0</span></button>
    <input class="search" id="search" type="search" placeholder="Filter by file, repo, issue, detector…" aria-label="Filter findings">
  </div>

  <section class="list" id="list" aria-live="polite">
    <div class="empty">Loading findings…</div>
  </section>

  <div class="feed" id="feed" aria-label="Live events"><span class="t">·</span>waiting for events…</div>
</main>

<script>
const $ = (s) => document.querySelector(s);
const state = { findings: [], sev: new Set(), q: '' };

function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function when(iso) {
  if (!iso) return '';
  const d = new Date(iso); if (isNaN(d)) return esc(iso);
  const mins = Math.round((Date.now() - d) / 60000);
  if (mins < 1) return 'just now'; if (mins < 60) return mins + ' min ago';
  const h = Math.round(mins / 60); if (h < 48) return h + ' h ago';
  return d.toLocaleDateString();
}

async function loadSummary() {
  try {
    const d = await (await fetch('/api/summary')).json();
    const s = d.by_severity || {};
    const hot = (s.CRITICAL || 0) + (s.HIGH || 0);
    const attn = $('#attention'); const big = $('#attn-count');
    big.textContent = hot; big.className = 'big display ' + (hot ? 'hot' : 'ok'); attn.classList.toggle('ok', !hot);
    $('#attn-sub').textContent = hot
      ? `${s.CRITICAL || 0} critical · ${s.HIGH || 0} high — open each one below for the line, the reason, and the fix`
      : 'no critical or high findings in any recorded scan';
    $('#s-scans').textContent = d.total_scans ?? 0;
    $('#s-last').textContent = d.last_scan_at ? 'last ' + when(d.last_scan_at) : 'no scans yet';
    $('#s-findings').textContent = d.total_findings ?? 0;
    $('#s-projects').textContent = d.projects ? `across ${d.projects} project${d.projects === 1 ? '' : 's'}` : '';
    $('#s-medium').textContent = s.MEDIUM || 0;
    $('#s-low').textContent = (s.LOW || 0) + (s.INFO || 0);
    document.querySelectorAll('.chip[data-sev]').forEach(c => c.querySelector('.n').textContent = s[c.dataset.sev] || 0);
  } catch (e) { console.warn('summary', e); }
}

async function loadFindings() {
  try {
    const d = await (await fetch('/api/findings?limit=200')).json();
    state.findings = d.findings || [];
    render();
  } catch (e) { console.warn('findings', e); }
}

function whereHtml(f) {
  const parts = [];
  const pr = f.pull_request;
  if (pr && pr.url) parts.push(`<a href="${esc(pr.url)}" target="_blank" rel="noopener">${esc(pr.repo || f.project_label)} #${esc(pr.number)}</a>`);
  else if (f.project_label) parts.push(`<span>${esc(f.project_label)}</span>`);
  if (f.file_path) parts.push(`<span class="loc">${esc(f.file_path)}${f.line ? `<b>:${esc(f.line)}</b>` : ''}</span>`);
  parts.push(`<span>${when(f.scanned_at)}</span>`);
  return parts.join('');
}

function card(f) {
  const id = esc(f.finding_id || '');
  const dismiss = `agents feedback ${f.finding_id} dismiss --reason "…"`;
  return `
  <details class="card" data-sev="${esc(f.severity)}">
    <summary>
      <span class="badge">${esc(f.severity)}</span>
      <span>
        <div class="title">${esc(f.issue)}</div>
        <div class="where">${whereHtml(f)}</div>
      </span>
      <span class="caret" aria-hidden="true">▾</span>
    </summary>
    <div class="body">
      ${f.snippet ? `<div class="snippet"><span class="gutter">${f.line ? esc(String(f.line).padStart(4)) : '    '}</span> <span class="plus">+</span> ${esc(f.snippet)}</div>` : ''}
      ${f.why ? `<div class="note why"><h4>Why this matters</h4><p>${esc(f.why)}</p></div>` : ''}
      ${f.fix ? `<div class="note fix"><h4>How to fix</h4><p>${esc(f.fix)}</p></div>` : ''}
      <div class="meta">
        <span class="tag">${esc(f.detector)}</span>
        ${f.pull_request && f.pull_request.head_sha ? `<span class="mono">${esc(String(f.pull_request.head_sha).slice(0, 7))}</span>` : ''}
        <span class="mono">${id}</span>
        <button class="btn copy" type="button" data-copy="${esc(dismiss)}" title="Copy the command that marks this finding a false positive">Copy dismiss command</button>
      </div>
    </div>
  </details>`;
}

function render() {
  const q = state.q.toLowerCase();
  const rows = state.findings.filter(f =>
    (!state.sev.size || state.sev.has(f.severity)) &&
    (!q || [f.issue, f.file_path, f.project_label, f.detector, f.pull_request && f.pull_request.title].join(' ').toLowerCase().includes(q)));
  const list = $('#list');
  if (!state.findings.length) {
    list.innerHTML = `<div class="empty">Nothing recorded yet. Open a pull request on a connected repository, or run <code>agents scan --path . </code> locally with recording on, and findings land here.</div>`;
    return;
  }
  if (!rows.length) { list.innerHTML = `<div class="empty">No findings match this filter.</div>`; return; }
  list.innerHTML = rows.map(card).join('');
}

document.querySelectorAll('.chip[data-sev]').forEach(c => c.addEventListener('click', () => {
  const s = c.dataset.sev; const on = !state.sev.has(s);
  on ? state.sev.add(s) : state.sev.delete(s); c.setAttribute('aria-pressed', on); render();
}));
$('#search').addEventListener('input', e => { state.q = e.target.value; render(); });
document.addEventListener('click', async e => {
  const b = e.target.closest('[data-copy]'); if (!b) return;
  try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copied'; setTimeout(() => b.textContent = 'Copy dismiss command', 1500); }
  catch { prompt('Copy this command', b.dataset.copy); }
});

// Theme: follow the system, remember an explicit choice.
const root = document.documentElement;
try { const saved = localStorage.getItem('agents-theme'); if (saved) root.dataset.theme = saved;
  else if (matchMedia('(prefers-color-scheme: light)').matches) root.dataset.theme = 'light'; } catch {}
$('#theme').addEventListener('click', () => {
  root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
  try { localStorage.setItem('agents-theme', root.dataset.theme); } catch {}
});

// Live feed (Server-Sent Events); the browser reconnects on its own.
const feed = $('#feed'); const live = $('#live');
function log(text, cls) {
  const line = document.createElement('div');
  line.innerHTML = `<span class="t">${new Date().toLocaleTimeString()}</span><span class="${cls || 'ev'}">${esc(text)}</span>`;
  if (feed.firstChild && feed.firstChild.textContent.includes('waiting')) feed.innerHTML = '';
  feed.appendChild(line); feed.scrollTop = feed.scrollHeight;
}
if (typeof EventSource !== 'undefined') {
  const es = new EventSource('/api/events');
  es.onopen = () => { live.dataset.state = 'live'; $('#live-text').textContent = 'live'; };
  es.onmessage = e => {
    if (e.data === 'connected') return;
    log(e.data);
    if (e.data.startsWith('scan_complete')) { loadSummary(); loadFindings(); }
  };
  es.onerror = () => { live.dataset.state = 'lost'; $('#live-text').textContent = 'reconnecting'; };
}

fetch('/health').then(r => r.json()).then(h => { $('#version').textContent = 'v' + h.version; }).catch(() => {});
loadSummary(); loadFindings();
setInterval(() => { loadSummary(); loadFindings(); }, 30000);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Dashboard application
# ---------------------------------------------------------------------------

_DEFAULT_DATABASE = object()


class AgentsDashboard:
    """
    Minimal web dashboard for rushingtech-agents.

    Works without Flask when used as a library (pure data layer).
    Requires Flask for the HTTP server path. For the hosted service
    (dashboard + GitHub webhook + health) see `agents.server`.
    """

    def __init__(self, db_path: Optional[str] | object = _DEFAULT_DATABASE) -> None:
        self._db_path = _default_db_path() if db_path is _DEFAULT_DATABASE else db_path
        self._sse_queues: List[queue.Queue] = []
        self._lock = threading.Lock()

    # ── Data layer ────────────────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        """Return scan/finding counts for the dashboard cards."""
        conn = self._connect()
        if conn is None:
            return {
                "total_scans": 0,
                "total_findings": 0,
                "by_severity": {},
                "last_scan_at": None,
                "projects": 0,
            }
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM scan_runs")
            total_scans = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM findings")
            total_findings = cur.fetchone()[0]
            cur.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
            by_severity: Dict[str, int] = {}
            for row in cur.fetchall():
                by_severity[row[0]] = row[1]
            cur.execute("SELECT MAX(created_at) FROM scan_runs")
            last_scan_at = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT project_key) FROM scan_runs")
            projects = cur.fetchone()[0]
            return {
                "total_scans": total_scans,
                "total_findings": total_findings,
                "by_severity": by_severity,
                "last_scan_at": last_scan_at,
                "projects": projects,
            }
        except sqlite3.OperationalError:
            return {
                "total_scans": 0,
                "total_findings": 0,
                "by_severity": {},
                "last_scan_at": None,
                "projects": 0,
            }
        finally:
            conn.close()

    def get_findings(self, limit: int = 50) -> Dict[str, Any]:
        """Return the most recent findings, newest scan first.

        Reads the evolution store's own schema (findings joined to scan_runs
        for the timestamp and project). Line numbers and the originating
        pull request are not columns — they live in the recorded report
        JSON — so they are looked up per scan for the page being rendered.
        """
        conn = self._connect()
        if conn is None:
            return {"findings": []}
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT f.severity, f.issue, f.file, f.agent, f.tool, f.fix, "
                "f.finding_id, r.created_at, r.project_path, r.scan_id "
                "FROM findings f JOIN scan_runs r ON r.scan_id = f.scan_id "
                "ORDER BY r.created_at DESC, CASE f.severity WHEN 'CRITICAL' THEN 0 "
                "WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
                "f.file, f.rowid LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
            extras = self._report_extras(cur, {row[9] for row in rows})
            findings = []
            for row in rows:
                scan_extra = extras.get(row[9], {})
                per_finding = scan_extra.get("findings", {}).get(row[6], {})
                findings.append(
                    {
                        "severity": row[0],
                        "issue": row[1],
                        "file_path": row[2],
                        "line": per_finding.get("line"),
                        "snippet": per_finding.get("snippet"),
                        "why": per_finding.get("why") or _rationale(row[4], row[1]),
                        "detector": f"{row[3]}.{row[4]}" if row[4] else row[3],
                        "fix": row[5],
                        "finding_id": row[6],
                        "scanned_at": row[7],
                        "project": row[8],
                        "project_label": _project_label(row[8]),
                        "pull_request": scan_extra.get("pull_request"),
                        "scan_id": row[9],
                    }
                )
            return {"findings": findings}
        except sqlite3.OperationalError:
            return {"findings": []}
        finally:
            conn.close()

    @staticmethod
    def _report_extras(cur: sqlite3.Cursor, scan_ids: set) -> Dict[str, Any]:
        """Per scan: the pull-request block and finding_id → line map."""
        extras: Dict[str, Any] = {}
        for scan_id in scan_ids:
            cur.execute(
                "SELECT report_json FROM scan_runs WHERE scan_id = ?", (scan_id,)
            )
            row = cur.fetchone()
            if not row:
                continue
            try:
                report = json.loads(row[0])
            except (TypeError, ValueError):
                continue
            per_finding: Dict[str, Dict[str, Any]] = {}
            for entry in report.get("results", []):
                for finding in entry.get("result", {}).get("findings", []):
                    if isinstance(finding, dict) and finding.get("finding_id"):
                        per_finding[finding["finding_id"]] = {
                            "line": finding.get("line"),
                            "snippet": finding.get("snippet"),
                            "why": finding.get("why"),
                        }
            extras[scan_id] = {
                "pull_request": report.get("pull_request"),
                "findings": per_finding,
            }
        return extras

    # ── SSE (Server-Sent Events) ──────────────────────────────────────

    def publish_event(self, message: str) -> None:
        """Publish a live-scan event to all connected SSE clients."""
        with self._lock:
            for q in list(self._sse_queues):
                try:
                    q.put_nowait(message)
                except queue.Full:
                    pass

    def sse_stream(self) -> Generator[str, None, None]:
        """Generator that yields SSE-formatted lines for a single client."""
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self._sse_queues.append(q)
        try:
            yield "data: connected\n\n"
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"  # keep-alive
        finally:
            with self._lock:
                try:
                    self._sse_queues.remove(q)
                except ValueError:
                    pass

    # ── Flask app factory ─────────────────────────────────────────────

    def create_flask_app(self):  # type: ignore[return]
        """Create and return a Flask WSGI application."""
        try:
            from flask import Flask, Response, jsonify, request  # type: ignore
        except ImportError:
            raise ImportError(
                "Flask is required for the web dashboard: pip install flask"
            )

        app = Flask("agents-dashboard")
        dashboard = self

        @app.route("/")
        def index():
            return Response(_HTML, mimetype="text/html")

        @app.route("/api/summary")
        def api_summary():
            return jsonify(dashboard.get_summary())

        @app.route("/api/findings")
        def api_findings():
            limit = int(request.args.get("limit", 50))
            return jsonify(dashboard.get_findings(limit=limit))

        @app.route("/api/events")
        def api_events():
            return Response(dashboard.sse_stream(), mimetype="text/event-stream")

        return app

    # ── Helpers ───────────────────────────────────────────────────────

    def _connect(self) -> Optional[sqlite3.Connection]:
        if not self._db_path or not os.path.isfile(self._db_path):
            return None
        return sqlite3.connect(self._db_path)


def _rationale(tool: str, issue: str) -> str:
    try:
        from agents.server import explain_finding
    except Exception:  # noqa: BLE001 - dashboard must render without the server extra
        return ""
    return explain_finding(tool or "", {"issue": issue})


def _project_label(project_path: str) -> str:
    """`/github/owner/repo` → `owner/repo`; a filesystem path → its basename."""
    if not project_path:
        return ""
    if project_path.startswith("/github/"):
        return project_path[len("/github/") :]
    return os.path.basename(project_path.rstrip("/")) or project_path


def _default_db_path() -> str:
    try:
        from agents.evolution import default_database_path

        return default_database_path()
    except Exception:  # noqa: BLE001
        xdg = os.environ.get(
            "XDG_STATE_HOME", os.path.join(os.path.expanduser("~"), ".local", "state")
        )
        return os.path.join(xdg, "rushingtech-agents", "evolution.db")


# ---------------------------------------------------------------------------
# CLI entry point: python -m agents.web
# ---------------------------------------------------------------------------


def _main() -> None:
    import argparse
    import webbrowser

    parser = argparse.ArgumentParser(description="rushingtech-agents web dashboard")
    parser.add_argument(
        "--port", type=int, default=8000, help="HTTP port (default: 8000)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)"
    )
    parser.add_argument("--db", default=None, help="Path to evolution.db")
    parser.add_argument(
        "--no-browser", action="store_true", help="Don't open browser automatically"
    )
    args = parser.parse_args()

    dashboard = (
        AgentsDashboard() if args.db is None else AgentsDashboard(db_path=args.db)
    )
    flask_app = dashboard.create_flask_app()

    url = f"http://{args.host}:{args.port}"
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    print(f"Dashboard running at {url}")
    flask_app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    _main()
