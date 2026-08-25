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
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>rushingtech-agents dashboard</title>
<style>
:root[data-theme="dark"] {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #e6edf3; --muted: #8b949e;
  --critical: #ff7b72; --high: #ffa657; --medium: #e3b341; --low: #7ee787; --info: #58a6ff;
}
:root[data-theme="light"] {
  --bg: #ffffff; --surface: #f6f8fa; --border: #d0d7de;
  --text: #1f2328; --muted: #57606a;
  --critical: #cf222e; --high: #bc4c00; --medium: #9a6700; --low: #1a7f37; --info: #0550ae;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; }
header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; justify-content: space-between; align-items: center; }
header h1 { font-size: 18px; font-weight: 600; }
.toggle { cursor: pointer; background: none; border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 4px 10px; }
main { padding: 24px; max-width: 1200px; margin: 0 auto; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 6px; }
.card .value { font-size: 28px; font-weight: 700; }
.CRITICAL { color: var(--critical); } .HIGH { color: var(--high); } .MEDIUM { color: var(--medium); } .LOW { color: var(--low); } .INFO { color: var(--info); }
table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
th { font-size: 12px; text-transform: uppercase; color: var(--muted); }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; background: var(--surface); border: 1px solid var(--border); }
.fix { color: var(--muted); font-size: 12px; margin-top: 4px; }
.where { font-size: 12px; }
.where a { color: var(--info); text-decoration: none; }
.where .loc { color: var(--muted); font-family: monospace; word-break: break-all; }
#sse-log { margin-top: 24px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px; max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px; color: var(--muted); }
</style>
</head>
<body>
<header>
  <h1>🔍 rushingtech-agents</h1>
  <button class="toggle" onclick="toggleTheme()">Toggle theme</button>
</header>
<main>
  <div class="cards" id="summary-cards">
    <div class="card"><div class="label">Total scans</div><div class="value" id="c-scans">–</div></div>
    <div class="card"><div class="label">Total findings</div><div class="value" id="c-findings">–</div></div>
    <div class="card"><div class="label CRITICAL">Critical</div><div class="value CRITICAL" id="c-critical">–</div></div>
    <div class="card"><div class="label HIGH">High</div><div class="value HIGH" id="c-high">–</div></div>
    <div class="card"><div class="label MEDIUM">Medium</div><div class="value MEDIUM" id="c-medium">–</div></div>
  </div>

  <h2 style="margin-bottom:12px;font-size:16px;">Recent findings</h2>
  <table id="findings-table">
    <thead><tr><th>Severity</th><th>Issue</th><th>Where</th><th>Detector</th><th>Scanned at</th></tr></thead>
    <tbody id="findings-body"><tr><td colspan="5" style="color:var(--muted)">Loading…</td></tr></tbody>
  </table>

  <div id="sse-log"><em>Live scan output will appear here…</em></div>
</main>

<script>
function toggleTheme() {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
}

async function loadSummary() {
  try {
    const r = await fetch('/api/summary');
    const d = await r.json();
    document.getElementById('c-scans').textContent = d.total_scans ?? 0;
    document.getElementById('c-findings').textContent = d.total_findings ?? 0;
    document.getElementById('c-critical').textContent = d.by_severity?.CRITICAL ?? 0;
    document.getElementById('c-high').textContent = d.by_severity?.HIGH ?? 0;
    document.getElementById('c-medium').textContent = d.by_severity?.MEDIUM ?? 0;
  } catch(e) { console.warn('summary fetch failed', e); }
}

async function loadFindings() {
  try {
    const r = await fetch('/api/findings?limit=50');
    const d = await r.json();
    const tbody = document.getElementById('findings-body');
    if (!d.findings || d.findings.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted)">No findings yet — run a scan.</td></tr>';
      return;
    }
    tbody.innerHTML = d.findings.map(f => `
      <tr>
        <td><span class="badge ${f.severity}">${f.severity}</span></td>
        <td>${esc(f.issue)}${f.fix ? `<div class="fix">${esc(f.fix)}</div>` : ''}</td>
        <td class="where">${where(f)}</td>
        <td style="color:var(--muted);font-size:12px">${esc(f.detector ?? '')}</td>
        <td style="color:var(--muted);font-size:12px">${esc(f.scanned_at ?? '')}</td>
      </tr>`).join('');
  } catch(e) { console.warn('findings fetch failed', e); }
}

function where(f) {
  const parts = [];
  const pr = f.pull_request;
  if (pr && pr.url) {
    parts.push(`<a href="${esc(pr.url)}" target="_blank" rel="noopener">${esc(pr.repo || f.project_label || '')} #${esc(pr.number)}</a>`);
  } else if (f.project_label) {
    parts.push(esc(f.project_label));
  }
  const loc = (f.file_path || '') + (f.line ? ':' + f.line : '');
  if (loc) parts.push(`<span class="loc">${esc(loc)}</span>`);
  return parts.join('<br>') || '<span style="color:var(--muted)">—</span>';
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// SSE live updates
const log = document.getElementById('sse-log');
if (typeof EventSource !== 'undefined') {
  const es = new EventSource('/api/events');
  es.onmessage = e => {
    const p = document.createElement('div');
    p.textContent = e.data;
    log.appendChild(p);
    log.scrollTop = log.scrollHeight;
    // Reload data when a scan completes
    if (e.data.includes('scan_complete')) { loadSummary(); loadFindings(); }
  };
  es.onerror = () => { log.innerHTML += '<div style="color:var(--critical)">SSE connection lost</div>'; };
}

loadSummary();
loadFindings();
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
            return {"total_scans": 0, "total_findings": 0, "by_severity": {}}
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
            return {
                "total_scans": total_scans,
                "total_findings": total_findings,
                "by_severity": by_severity,
            }
        except sqlite3.OperationalError:
            return {"total_scans": 0, "total_findings": 0, "by_severity": {}}
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
                "ORDER BY r.created_at DESC, f.rowid DESC LIMIT ?",
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
                            "line": finding.get("line")
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
