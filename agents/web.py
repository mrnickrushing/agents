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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<meta name="color-scheme" content="dark light" />
<meta name="theme-color" content="#0b0f17" media="(prefers-color-scheme: dark)" />
<meta name="theme-color" content="#f4f6fb" media="(prefers-color-scheme: light)" />
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
<meta name="apple-mobile-web-app-title" content="agents" />
<link rel="manifest" href="/manifest.webmanifest" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
<link rel="icon" href="/apple-touch-icon.png" type="image/png" />
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
html { background: var(--ink); -webkit-text-size-adjust: 100%; }
button, summary, a { -webkit-tap-highlight-color: transparent; touch-action: manipulation; }
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
  position: sticky; top: 0; z-index: 5; -webkit-backdrop-filter: blur(14px); backdrop-filter: blur(14px);
  background: color-mix(in srgb, var(--ink) 80%, transparent); border-bottom: 1px solid var(--line);
  padding-top: env(safe-area-inset-top);
}
.bar { max-width: 1080px; margin: 0 auto; padding: 12px max(20px, env(safe-area-inset-right)) 12px max(20px, env(safe-area-inset-left)); display: flex; align-items: center; gap: 12px; min-height: 56px; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 17px; }
.brand .mark { width: 28px; height: 28px; border-radius: 8px; background: linear-gradient(135deg, var(--accent), var(--violet)); display: grid; place-items: center; color: #0b0f17; font-family: "JetBrains Mono", monospace; font-weight: 700; font-size: 13px; }
.brand small { color: var(--muted); font-weight: 500; font-size: 12px; margin-left: 4px; }
.spacer { flex: 1; }
.live { display: inline-flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); padding: 6px 10px; border: 1px solid var(--line); border-radius: 999px; background: var(--panel); }
.live .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
.live[data-state="live"] .dot { background: var(--low); box-shadow: 0 0 0 0 rgba(74,222,128,.6); animation: pulse 2s infinite; }
.live[data-state="lost"] .dot { background: var(--critical); }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(74,222,128,.5);} 70% { box-shadow: 0 0 0 8px rgba(74,222,128,0);} 100% { box-shadow: 0 0 0 0 rgba(74,222,128,0);} }
.btn { cursor: pointer; background: var(--panel); border: 1px solid var(--line); color: var(--text); border-radius: 10px; padding: 8px 12px; min-height: 40px; font: inherit; font-size: 13px; }
.btn:hover { border-color: var(--accent); }
.btn:active, .chip:active { transform: scale(.97); }
.btn:focus-visible, .chip:focus-visible, .card summary:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

main { max-width: 1080px; margin: 0 auto; padding: 28px max(20px, env(safe-area-inset-right)) calc(64px + env(safe-area-inset-bottom)) max(20px, env(safe-area-inset-left)); }

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

/* Run panel */
.runner { background: var(--panel); border: 1px solid var(--line); border-radius: 16px; margin-bottom: 18px; }
.runner > summary { list-style: none; cursor: pointer; display: flex; align-items: center; gap: 12px; padding: 14px 16px; min-height: 56px; }
.runner > summary::-webkit-details-marker { display: none; }
.runner .title { font-size: 16px; font-weight: 700; }
.runner .hint { color: var(--muted); font-size: 13px; flex: 1; }
.runner-body { padding: 0 16px 16px; display: grid; gap: 12px; border-top: 1px solid var(--line); padding-top: 14px; }
.row { display: flex; flex-wrap: wrap; gap: 10px; }
.field { display: grid; gap: 5px; min-width: 160px; }
.field.grow { flex: 1; }
.field > span { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.field > span small { text-transform: none; letter-spacing: 0; font-weight: 500; }
.field input, .field select, .field textarea {
  width: 100%; background: var(--ink); border: 1px solid var(--line); color: var(--text); border-radius: 10px;
  padding: 9px 12px; min-height: 40px; font: inherit; font-size: 16px; -webkit-appearance: none; appearance: none;
}
.field select:not([multiple]) { background-image: linear-gradient(45deg, transparent 50%, var(--muted) 50%), linear-gradient(135deg, var(--muted) 50%, transparent 50%); background-position: calc(100% - 18px) 50%, calc(100% - 13px) 50%; background-size: 5px 5px; background-repeat: no-repeat; padding-right: 32px; }
.field select[multiple] { padding: 6px; min-height: 120px; }
.field select[multiple] option { padding: 6px 8px; border-radius: 6px; }
.field textarea { min-height: 140px; font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 13px; line-height: 1.45; resize: vertical; }
.field input:focus, .field select:focus, .field textarea:focus { outline: 2px solid var(--accent); outline-offset: 1px; border-color: var(--accent); }
.fields { display: grid; gap: 10px; }
.desc { color: var(--muted); font-size: 13px; }
.actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.btn.primary { background: var(--accent); color: var(--accent-ink); border-color: transparent; font-weight: 600; }
.btn.primary:disabled { opacity: .6; cursor: progress; }
.status { font-size: 13px; color: var(--muted); }
.status.err { color: var(--critical); }
.status.ok { color: var(--low); }
.mode-form[hidden] { display: none; }
.switch { display: inline-flex; align-items: center; gap: 10px; min-height: 40px; cursor: pointer; font-size: 15px; font-weight: 600; text-transform: none; letter-spacing: 0; }
.switch input { width: 20px; height: 20px; accent-color: var(--accent); }
.switch small { color: var(--muted); font-weight: 500; }
[hidden] { display: none !important; }
.account { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; }
.account img { width: 28px; height: 28px; border-radius: 50%; border: 1px solid var(--line); }
.account .login { font-weight: 600; }
.signin { display: inline-flex; align-items: center; justify-content: center; text-decoration: none; }
.field .signin { min-height: 40px; }
.result-pre { white-space: pre-wrap; word-break: break-word; }

/* Filters */
.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 0 0 14px; }
.chips { display: flex; gap: 8px; flex-wrap: wrap; }
.chip { cursor: pointer; border: 1px solid var(--line); background: var(--panel); color: var(--muted); border-radius: 999px; padding: 8px 13px; min-height: 40px; font: inherit; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
.chip .n { font-family: "JetBrains Mono", monospace; font-weight: 600; }
.chip[aria-pressed="true"] { color: var(--text); border-color: var(--sev, var(--accent)); box-shadow: inset 0 0 0 1px var(--sev, var(--accent)); }
.chip[data-sev="CRITICAL"] { --sev: var(--critical); } .chip[data-sev="HIGH"] { --sev: var(--high); }
.chip[data-sev="MEDIUM"] { --sev: var(--medium); } .chip[data-sev="LOW"] { --sev: var(--low); } .chip[data-sev="INFO"] { --sev: var(--info); }
.search { flex: 1; min-width: 180px; min-height: 40px; background: var(--panel); border: 1px solid var(--line); color: var(--text); border-radius: 10px; padding: 8px 12px; font: inherit; font-size: 16px; -webkit-appearance: none; appearance: none; }
.search::placeholder { color: var(--muted); }

/* Finding cards — styled as code-review annotations */
.list { display: grid; gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; position: relative; }
.card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--sev); }
.card[data-sev="CRITICAL"] { --sev: var(--critical); } .card[data-sev="HIGH"] { --sev: var(--high); }
.card[data-sev="MEDIUM"] { --sev: var(--medium); } .card[data-sev="LOW"] { --sev: var(--low); } .card[data-sev="INFO"] { --sev: var(--info); }
.card summary { list-style: none; cursor: pointer; padding: 14px 16px 14px 20px; min-height: 56px; display: grid; grid-template-columns: auto minmax(0,1fr) auto; gap: 12px; align-items: start; }
.card summary::marker { display: none; content: ""; }
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
.verdict { font-size: 11px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; border-radius: 6px; padding: 2px 7px; vertical-align: middle; margin-left: 6px; }
.verdict.dismissed { color: var(--muted); border: 1px solid var(--line); }
.verdict.confirmed { color: var(--low); border: 1px solid color-mix(in srgb, var(--low) 50%, transparent); }
.reason { color: var(--muted); font-style: italic; }
.card[data-verdict="FALSE_POSITIVE"] { opacity: .72; }
.copy { margin-left: auto; }
.empty { border: 1px dashed var(--line); border-radius: 14px; padding: 28px 20px; text-align: center; color: var(--muted); }
.empty code { color: var(--text); }

/* Live feed */
.feed { margin-top: 26px; background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; font-family: "JetBrains Mono", monospace; font-size: 12px; color: var(--muted); max-height: 180px; overflow-y: auto; }
.feed .t { color: var(--muted); margin-right: 8px; }
.feed .ev { color: var(--text); }
.feed .err { color: var(--critical); }

@media (max-width: 720px) {
  body { font-size: 16px; }
  main { padding-top: 18px; }
  .hero { grid-template-columns: 1fr; gap: 10px; margin-bottom: 14px; }
  .attention { padding: 14px 16px; border-radius: 16px; display: grid; grid-template-columns: auto minmax(0,1fr); column-gap: 16px; align-items: center; }
  .attention .eyebrow { grid-column: 2; font-size: 11px; }
  .attention .big { grid-column: 1; grid-row: 1 / span 2; font-size: 56px; margin: 0; }
  .attention .sub { grid-column: 2; font-size: 13px; }
  .attention .glow { width: 160px; height: 160px; inset: auto -50px -70px auto; }
  .stats { grid-template-columns: repeat(4, minmax(0,1fr)); gap: 8px; }
  .stat { padding: 10px 10px; border-radius: 12px; }
  .stat .label { font-size: 10px; letter-spacing: .06em; }
  .stat .value { font-size: 20px; }
  .stat .hint { display: none; }
  .toolbar { gap: 8px; }
  .chips { flex-wrap: nowrap; overflow-x: auto; width: 100%; padding-bottom: 2px; scrollbar-width: none; -webkit-overflow-scrolling: touch; }
  .chips::-webkit-scrollbar { display: none; }
  .chip { flex: 0 0 auto; }
  .toolbar .search { flex-basis: 100%; }
  .card summary { grid-template-columns: minmax(0,1fr); gap: 8px; padding: 14px 14px 14px 18px; }
  .badge { justify-self: start; }
  .caret { display: none; }
  .body { padding: 0 14px 14px 18px; }
  .snippet { font-size: 12px; }
  .meta { row-gap: 10px; }
  .copy { margin-left: 0; width: 100%; justify-content: center; }
  .feed { max-height: 140px; }
}
@media (pointer: coarse) {
  .card summary:hover { background: transparent; }
  .live { min-height: 36px; }
}
@media (hover: hover) { .card summary:hover { background: color-mix(in srgb, var(--panel-2) 60%, transparent); } }
@media (prefers-reduced-motion: reduce) { .live .dot, .caret { animation: none; transition: none; } }
</style>
</head>
<body>
<header>
  <div class="bar">
    <div class="brand display"><span class="mark">&gt;_</span>agents<small id="version"></small></div>
    <span class="spacer"></span>
    <span class="live" id="live" data-state="idle"><span class="dot"></span><span id="live-text">connecting</span></span>
    <span id="account" class="account"></span>
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
      <div class="stat"><div class="label">Minor</div><div class="value display" style="color:var(--low)" id="s-low">–</div><div class="hint">housekeeping</div></div>
    </div>
  </section>

  <details class="runner" id="runner">
    <summary>
      <span class="title display">Run agents</span>
      <span class="hint" id="runner-hint">Scan a GitHub repository, or run one check on pasted code</span>
      <span class="caret" aria-hidden="true">▾</span>
    </summary>
    <div class="runner-body">
      <div class="row">
        <label class="field"><span>What to run</span>
          <select id="mode">
            <option value="repo">Scan a GitHub repository</option>
            <option value="check">Run one check on pasted code</option>
          </select>
        </label>
        <label class="field grow" id="token-field"><span>Access token</span>
          <input id="token" type="password" autocomplete="off" placeholder="DASHBOARD_TOKEN from the Railway service">
        </label>
        <div class="field grow" id="signin-field" hidden><span>Account</span>
          <a class="btn primary signin" href="/auth/login">Sign in with GitHub</a>
        </div>
      </div>

      <form id="repo-form" class="mode-form">
        <div class="row">
          <label class="field grow"><span>Repository</span>
            <select id="repo-select" hidden></select>
            <input id="repo" placeholder="owner/name" autocapitalize="none" autocorrect="off" spellcheck="false">
          </label>
          <label class="field"><span>Branch or tag</span>
            <select id="ref-select" hidden></select>
            <input id="ref" placeholder="default branch" autocapitalize="none" autocorrect="off" spellcheck="false">
          </label>
        </div>
        <div class="field">
          <span>Agents</span>
          <label class="switch"><input type="checkbox" id="all-agents" checked> <span>All agents</span> <small id="all-agents-count"></small></label>
          <div id="pick-agents" hidden>
            <div class="row" style="margin-bottom:6px">
              <button class="btn" type="button" id="agents-select-all">Select all</button>
              <button class="btn" type="button" id="agents-clear">Clear</button>
              <span class="status" id="agents-picked"></span>
            </div>
            <select id="scan-agents" multiple size="6"></select>
          </div>
        </div>
        <div class="actions">
          <button class="btn primary" type="submit" id="scan-btn">Scan repository</button>
          <span class="status" id="scan-status"></span>
        </div>
      </form>

      <form id="check-form" class="mode-form" hidden>
        <div class="row">
          <label class="field grow"><span>Agent</span><select id="agent"></select></label>
          <label class="field grow"><span>Check</span><select id="tool"></select></label>
        </div>
        <p class="desc" id="tool-desc"></p>
        <div id="tool-fields" class="fields"></div>
        <div class="actions">
          <button class="btn primary" type="submit" id="run-btn">Run check</button>
          <span class="status" id="run-status"></span>
        </div>
        <div id="run-result" class="list"></div>
      </form>
    </div>
  </details>

  <div class="toolbar" id="filters">
    <div class="chips" role="group" aria-label="Filter by severity">
      <button class="chip" data-sev="CRITICAL" aria-pressed="false" type="button">Critical <span class="n">0</span></button>
      <button class="chip" data-sev="HIGH" aria-pressed="false" type="button">High <span class="n">0</span></button>
      <button class="chip" data-sev="MEDIUM" aria-pressed="false" type="button">Medium <span class="n">0</span></button>
      <button class="chip" data-sev="LOW" aria-pressed="false" type="button">Low <span class="n">0</span></button>
      <button class="chip" data-sev="INFO" aria-pressed="false" type="button">Info <span class="n">0</span></button>
      <button class="chip" id="chip-dismissed" aria-pressed="false" type="button" title="Show findings a person dismissed as false positives">Dismissed <span class="n">0</span></button>
    </div>
    <input class="search" id="search" type="search" placeholder="Filter by file, repo, issue, detector…" aria-label="Filter findings">
    <button class="btn" type="button" id="copy-claude" title="Copy the findings shown below as Markdown to paste into Claude">Copy for Claude</button>
  </div>

  <section class="list" id="list" aria-live="polite">
    <div class="empty">Loading findings…</div>
  </section>

  <div class="feed" id="feed" aria-label="Live events"><span class="t">·</span>waiting for events…</div>
</main>

<script>
const $ = (s) => document.querySelector(s);
const state = { findings: [], sev: new Set(), q: '', open: new Set(), lastPayload: '', showDismissed: false };

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
    const r = await fetch('/api/summary');
    if (r.status === 401) { location.href = '/login'; return; }
    const d = await r.json();
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
    $('#chip-dismissed .n').textContent = d.dismissed || 0;
  } catch (e) { console.warn('summary', e); }
}

async function loadFindings() {
  try {
    const text = await (await fetch('/api/findings?limit=200')).text();
    if (text === state.lastPayload) return;   // nothing changed: keep open cards and scroll position
    state.lastPayload = text;
    state.findings = (JSON.parse(text).findings) || [];
    render();
  } catch (e) { console.warn('findings', e); }
}

function whereHtml(f) {
  const parts = [];
  const pr = f.pull_request, repo = f.repository;
  const slug = (pr && pr.repo) || (repo && repo.repo) || '';
  const sha = (pr && pr.head_sha) || (repo && repo.head_sha) || '';
  if (pr && pr.url) parts.push(`<a href="${esc(pr.url)}" target="_blank" rel="noopener">${esc(slug || f.project_label)} #${esc(pr.number)}</a>`);
  else if (repo && repo.repo) parts.push(`<a href="https://github.com/${esc(repo.repo)}${repo.ref ? '/tree/' + esc(repo.ref) : ''}" target="_blank" rel="noopener">${esc(repo.repo)}${repo.ref ? ' @ ' + esc(repo.ref) : ''}</a>`);
  else if (f.project_label) parts.push(`<span>${esc(f.project_label)}</span>`);
  if (f.file_path) {
    const loc = `${esc(f.file_path)}${f.line ? `<b>:${esc(f.line)}</b>` : ''}`;
    const linkable = slug && sha && !f.file_path.startsWith('(');
    parts.push(linkable
      ? `<a class="loc" href="https://github.com/${esc(slug)}/blob/${esc(sha)}/${esc(f.file_path)}${f.line ? '#L' + esc(f.line) : ''}" target="_blank" rel="noopener" title="Open this line on GitHub">${loc}</a>`
      : `<span class="loc">${loc}</span>`);
  }
  if (f.scanned_at) parts.push(`<span>${when(f.scanned_at)}</span>`);
  return parts.join('');
}

function card(f) {
  const id = esc(f.finding_id || '');
  const dismiss = `agents feedback ${f.finding_id} dismiss --reason "…"`;
  const sha = (f.pull_request && f.pull_request.head_sha) || (f.repository && f.repository.head_sha) || '';
  return `
  <details class="card" data-sev="${esc(f.severity)}" data-id="${id}" data-verdict="${esc(f.verdict || '')}"${state.open.has(f.finding_id) ? ' open' : ''}>
    <summary>
      <span class="badge">${esc(f.severity)}</span>
      <span>
        <div class="title">${esc(f.issue)}${f.verdict ? ` <span class="verdict ${f.verdict === 'FALSE_POSITIVE' ? 'dismissed' : 'confirmed'}" title="${esc(f.verdict_reason || '')}">${f.verdict === 'FALSE_POSITIVE' ? 'dismissed' : 'confirmed'}</span>` : ''}</div>
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
        ${sha ? `<span class="mono">${esc(String(sha).slice(0, 7))}</span>` : ''}
        ${id ? `<span class="mono">${id}</span>` : ''}
        ${f.verdict_reason ? `<span class="reason">“${esc(f.verdict_reason)}”</span>` : ''}
        ${id && f.verdict !== 'FALSE_POSITIVE' ? `<button class="btn copy" type="button" data-verdict="dismiss" data-id="${id}" title="Mark this a false positive; it leaves the board and future scans remember">Dismiss…</button>` : ''}
        ${id && f.verdict !== 'CONFIRMED' ? `<button class="btn" type="button" data-verdict="confirm" data-id="${id}" title="Mark this real">Confirm…</button>` : ''}
        ${id ? `<button class="btn" type="button" data-copy="${esc(dismiss)}" title="Copy the CLI command instead">Copy command</button>` : ''}
      </div>
    </div>
  </details>`;
}

function render() {
  const rows = visibleFindings();
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
$('#list').addEventListener('toggle', e => {
  const card = e.target.closest('.card'); if (!card) return;
  card.open ? state.open.add(card.dataset.id) : state.open.delete(card.dataset.id);
}, true);
// Markdown hand-off: the findings currently shown, ready to paste to Claude.
function visibleFindings() {
  const q = state.q.toLowerCase();
  return state.findings.filter(f =>
    (state.showDismissed ? f.verdict === 'FALSE_POSITIVE' : f.verdict !== 'FALSE_POSITIVE') &&
    (!state.sev.size || state.sev.has(f.severity)) &&
    (!q || [f.issue, f.file_path, f.project_label, f.detector, f.pull_request && f.pull_request.title].join(' ').toLowerCase().includes(q)));
}
$('#chip-dismissed').addEventListener('click', () => {
  state.showDismissed = !state.showDismissed;
  $('#chip-dismissed').setAttribute('aria-pressed', state.showDismissed);
  render();
});
async function sendVerdict(id, verdict) {
  const reason = prompt(verdict === 'dismiss' ? 'Why is this a false positive?' : 'Confirm — what makes it real?');
  if (reason === null || !reason.trim()) return;
  const r = await fetch('/api/feedback', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ finding_id: id, verdict, reason: reason.trim() }) });
  const d = await r.json();
  if (!r.ok) { alert(d.error || r.statusText); return; }
  state.lastPayload = ''; loadSummary(); loadFindings();
}
document.addEventListener('click', e => {
  const b = e.target.closest('[data-verdict]'); if (!b) return;
  sendVerdict(b.dataset.id, b.dataset.verdict);
});
function findingsMarkdown(rows) {
  const groups = new Map();
  for (const f of rows) {
    const key = f.project_label || f.project || 'unknown';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  const lines = [`# agents findings — ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`, '',
    `Please fix these ${rows.length} finding(s). For each: change the code, keep behaviour, and say what you changed. Dismiss with \`agents feedback <id> dismiss --reason "..."\` if it is a false positive.`, ''];
  for (const [repo, list] of groups) {
    const first = list[0];
    const where = first.pull_request && first.pull_request.url ? ` (PR #${first.pull_request.number}: ${first.pull_request.url})`
      : first.repository && first.repository.head_sha ? ` (@ ${first.repository.ref || 'default'} ${String(first.repository.head_sha).slice(0, 7)})` : '';
    lines.push(`## ${repo}${where}`, '');
    for (const f of list) {
      lines.push(`- **${f.severity}** \`${f.file_path || '?'}${f.line ? ':' + f.line : ''}\` — ${f.issue}`);
      if (f.snippet) lines.push(`  - line: \`${f.snippet}\``);
      if (f.why) lines.push(`  - why: ${f.why}`);
      if (f.fix) lines.push(`  - fix: ${f.fix}`);
      lines.push(`  - detector: ${f.detector}${f.finding_id ? ` · id: ${f.finding_id}` : ''}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}
$('#copy-claude').addEventListener('click', async () => {
  const rows = visibleFindings(); const b = $('#copy-claude');
  if (!rows.length) { b.textContent = 'Nothing to copy'; setTimeout(() => b.textContent = 'Copy for Claude', 1500); return; }
  const text = findingsMarkdown(rows);
  try { await navigator.clipboard.writeText(text); b.textContent = `Copied ${rows.length}`; setTimeout(() => b.textContent = 'Copy for Claude', 1500); }
  catch { prompt('Copy this', text); }
});

document.addEventListener('click', async e => {
  const b = e.target.closest('[data-copy]'); if (!b) return;
  try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copied'; setTimeout(() => b.textContent = 'Copy dismiss command', 1500); }
  catch { prompt('Copy this command', b.dataset.copy); }
});

// ── Run agents from the page ─────────────────────────────────────────
const runner = { catalog: [], enabled: false };
const tokenInput = $('#token');
try { tokenInput.value = localStorage.getItem('agents-token') || ''; } catch {}
tokenInput.addEventListener('change', () => { try { localStorage.setItem('agents-token', tokenInput.value); } catch {} });
const authHeaders = () => {
  const h = { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' };
  if (!runner.signedIn && tokenInput.value.trim()) h['Authorization'] = 'Bearer ' + tokenInput.value.trim();
  return h;
};
const setStatus = (el, text, cls) => { el.textContent = text; el.className = 'status' + (cls ? ' ' + cls : ''); };

// Account: sign in with GitHub, or fall back to the access token.
async function loadMe() {
  try {
    const me = await (await fetch('/api/me')).json();
    runner.signedIn = !!me.signed_in;
    const account = $('#account');
    if (me.signed_in) {
      account.innerHTML = `${me.avatar_url ? `<img src="${esc(me.avatar_url)}" alt="">` : ''}<span class="login">${esc(me.login)}</span><button class="btn" type="button" id="signout">Sign out</button>`;
      $('#signout').addEventListener('click', async () => { await fetch('/auth/logout', { method: 'POST', headers: authHeaders() }); location.href = '/login'; });
    } else if (me.sign_in_enabled) {
      account.innerHTML = `<a class="btn primary signin" href="/auth/login">Sign in with GitHub</a>`;
    } else {
      account.innerHTML = '';
    }
    $('#token-field').hidden = me.signed_in || !me.token_enabled;
    $('#signin-field').hidden = me.signed_in || !me.sign_in_enabled;
    if (me.signed_in || (me.token_enabled && tokenInput.value.trim())) loadRepos();
  } catch (e) { console.warn('me', e); }
}

// Repository + branch dropdowns, from the signed-in account.
async function loadRepos() {
  const sel = $('#repo-select'), text = $('#repo');
  try {
    const r = await fetch('/api/repos', { headers: authHeaders() });
    if (!r.ok) { sel.hidden = true; text.hidden = false; return; }
    const data = await r.json();
    const repos = data.repos || [];
    if (!repos.length) { sel.hidden = true; text.hidden = false; if (data.hint) setStatus($('#scan-status'), data.hint, 'err'); return; }
    sel.innerHTML = '<option value="">Choose a repository…</option>' + repos.map(x =>
      `<option value="${esc(x.full_name)}" data-branch="${esc(x.default_branch)}">${esc(x.full_name)}${x.private ? ' 🔒' : ''}</option>`).join('');
    sel.hidden = false; text.hidden = true;
  } catch (e) { sel.hidden = true; text.hidden = false; }
}
async function loadBranches(repo, preferred) {
  const sel = $('#ref-select'), text = $('#ref');
  sel.hidden = true; text.hidden = false; text.value = preferred || '';
  if (!repo) return;
  try {
    const r = await fetch('/api/branches?repo=' + encodeURIComponent(repo), { headers: authHeaders() });
    if (!r.ok) return;
    const branches = (await r.json()).branches || [];
    if (!branches.length) return;
    sel.innerHTML = branches.map(b => `<option value="${esc(b)}"${b === preferred ? ' selected' : ''}>${esc(b)}</option>`).join('');
    sel.hidden = false; text.hidden = true;
  } catch {}
}
$('#repo-select').addEventListener('change', e => {
  const opt = e.target.selectedOptions[0];
  loadBranches(e.target.value, opt ? opt.dataset.branch : '');
});
const chosenRepo = () => ($('#repo-select').hidden ? $('#repo').value : $('#repo-select').value).trim();
const chosenRef = () => ($('#ref-select').hidden ? $('#ref').value : $('#ref-select').value).trim();

async function loadCatalog() {
  try {
    const d = await (await fetch('/api/agents')).json();
    runner.catalog = d.agents || []; runner.enabled = !!d.runs_enabled;
    if (!runner.enabled) $('#runner-hint').textContent = 'Disabled until sign-in (GITHUB_OAUTH_CLIENT_ID/SECRET) or DASHBOARD_TOKEN is set on the service';
    const opts = runner.catalog.map(a => `<option value="${esc(a.key)}">${esc(a.key)} — ${esc(a.description || a.name)}</option>`).join('');
    $('#scan-agents').innerHTML = opts;
    $('#agent').innerHTML = opts;
    $('#all-agents-count').textContent = `(all ${runner.catalog.length})`;
    fillTools();
  } catch (e) { console.warn('catalog', e); }
}
function currentAgent() { return runner.catalog.find(a => a.key === $('#agent').value); }
function fillTools() {
  const a = currentAgent(); const sel = $('#tool');
  sel.innerHTML = a ? a.tools.map(t => `<option value="${esc(t.name)}">${esc(t.name)}</option>`).join('') : '';
  fillFields();
}
const CODE_LIKE = /code|content|schema|diff|log|yaml|json|config|manifest|text|incident|figma|package|requirements|dockerfile|workflow/i;
function fillFields() {
  const a = currentAgent(); const t = a && a.tools.find(t => t.name === $('#tool').value);
  $('#tool-desc').textContent = t ? t.description : '';
  const props = (t && t.parameters && t.parameters.properties) || {};
  const required = new Set((t && t.parameters && t.parameters.required) || []);
  $('#tool-fields').innerHTML = Object.entries(props).map(([name, p]) => {
    const label = `<span>${esc(name)}${required.has(name) ? '' : ' <small>(optional)</small>'}</span>`;
    const desc = p.description ? `<small class="desc">${esc(p.description)}</small>` : '';
    let control;
    if (p.enum) control = `<select name="${esc(name)}" data-type="string">${p.enum.map(v => `<option>${esc(v)}</option>`).join('')}</select>`;
    else if (p.type === 'boolean') control = `<select name="${esc(name)}" data-type="boolean"><option value="false">no</option><option value="true">yes</option></select>`;
    else if (p.type === 'integer' || p.type === 'number') control = `<input name="${esc(name)}" data-type="number" type="number" inputmode="decimal">`;
    else if (p.type === 'object' || p.type === 'array') control = `<textarea name="${esc(name)}" data-type="json" placeholder="JSON"></textarea>`;
    else if (CODE_LIKE.test(name) || CODE_LIKE.test(p.description || '')) control = `<textarea name="${esc(name)}" data-type="string" spellcheck="false" placeholder="Paste here"></textarea>`;
    else control = `<input name="${esc(name)}" data-type="string" autocapitalize="none" autocorrect="off">`;
    return `<label class="field">${label}${control}${desc}</label>`;
  }).join('') || '<p class="desc">This check takes no input.</p>';
}
$('#agent').addEventListener('change', fillTools);
$('#tool').addEventListener('change', fillFields);
$('#mode').addEventListener('change', e => {
  const repoMode = e.target.value === 'repo';
  $('#repo-form').hidden = !repoMode; $('#check-form').hidden = repoMode;
});

$('#check-form').addEventListener('submit', async e => {
  e.preventDefault();
  const status = $('#run-status'), out = $('#run-result'), btn = $('#run-btn');
  const args = {};
  for (const el of $('#tool-fields').querySelectorAll('[name]')) {
    const v = el.value; if (v === '' && el.tagName !== 'SELECT') continue;
    const kind = el.dataset.type;
    if (kind === 'number') args[el.name] = Number(v);
    else if (kind === 'boolean') args[el.name] = v === 'true';
    else if (kind === 'json') { try { args[el.name] = JSON.parse(v); } catch { setStatus(status, `${el.name} must be valid JSON`, 'err'); return; } }
    else args[el.name] = v;
  }
  btn.disabled = true; setStatus(status, 'running…'); out.innerHTML = '';
  try {
    const r = await fetch('/api/run', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ agent: $('#agent').value, tool: $('#tool').value, args }) });
    const d = await r.json();
    if (!r.ok) { setStatus(status, d.error || r.statusText, 'err'); return; }
    const res = d.result || {};
    if (Array.isArray(res.findings)) {
      setStatus(status, res.findings.length ? `${res.findings.length} finding(s) — not recorded` : 'clean — no findings', res.findings.length ? '' : 'ok');
      out.innerHTML = res.findings.map(f => card({ ...f, severity: f.severity || 'INFO', issue: f.issue || JSON.stringify(f), detector: `${$('#agent').value}.${$('#tool').value}`, file_path: f.file || '', finding_id: '' })).join('');
    } else {
      setStatus(status, 'done', 'ok');
      out.innerHTML = `<pre class="snippet result-pre">${esc(JSON.stringify(res, null, 2))}</pre>`;
    }
  } catch (err) { setStatus(status, String(err), 'err'); }
  finally { btn.disabled = false; }
});

// All agents by default; choosing specific ones is the exception.
const allAgents = $('#all-agents'), pickAgents = $('#pick-agents'), agentSelect = $('#scan-agents');
const pickedCount = () => { const n = agentSelect.selectedOptions.length; $('#agents-picked').textContent = n ? `${n} selected` : 'none selected'; };
allAgents.addEventListener('change', () => { pickAgents.hidden = allAgents.checked; if (!allAgents.checked) pickedCount(); });
agentSelect.addEventListener('change', pickedCount);
$('#agents-select-all').addEventListener('click', () => { for (const o of agentSelect.options) o.selected = true; pickedCount(); });
$('#agents-clear').addEventListener('click', () => { for (const o of agentSelect.options) o.selected = false; pickedCount(); });
const chosenAgents = () => allAgents.checked ? [] : Array.from(agentSelect.selectedOptions).map(o => o.value);

$('#repo-form').addEventListener('submit', async e => {
  e.preventDefault();
  const status = $('#scan-status'), btn = $('#scan-btn');
  const agents = chosenAgents();
  if (!allAgents.checked && !agents.length) { setStatus(status, 'pick at least one agent, or switch All agents back on', 'err'); return; }
  btn.disabled = true; setStatus(status, 'submitting…');
  try {
    if (!chosenRepo()) { setStatus(status, 'choose a repository first', 'err'); btn.disabled = false; return; }
    const r = await fetch('/api/scan', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ repo: chosenRepo(), ref: chosenRef(), agents }) });
    const d = await r.json();
    if (!r.ok) { setStatus(status, d.error || r.statusText, 'err'); btn.disabled = false; return; }
    const id = d.job.id;
    const poll = async () => {
      const j = (await (await fetch('/api/jobs/' + id)).json()).job;
      if (j.status === 'done') {
        const s = j.result.by_severity || {};
        setStatus(status, `done — ${j.result.findings} finding(s) in ${j.result.files_scanned ?? '?'} files (${s.CRITICAL || 0} critical, ${s.HIGH || 0} high)`, j.result.findings ? '' : 'ok');
        btn.disabled = false; loadSummary(); loadFindings();
      } else if (j.status === 'failed') { setStatus(status, j.error, 'err'); btn.disabled = false; }
      else { setStatus(status, j.progress + '…'); setTimeout(poll, 2000); }
    };
    poll();
  } catch (err) { setStatus(status, String(err), 'err'); btn.disabled = false; }
});
tokenInput.addEventListener('change', () => { if (tokenInput.value.trim()) loadRepos(); });
loadCatalog();
loadMe();

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
# Sign-in page
# ---------------------------------------------------------------------------
_LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<meta name="color-scheme" content="dark light" />
<meta name="theme-color" content="#0b0f17" media="(prefers-color-scheme: dark)" />
<meta name="theme-color" content="#f4f6fb" media="(prefers-color-scheme: light)" />
<meta name="robots" content="noindex" />
<link rel="manifest" href="/manifest.webmanifest" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
<link rel="icon" href="/apple-touch-icon.png" type="image/png" />
<title>Sign in — agents</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root {
  --ink: #0b0f17; --panel: #121826; --line: #212b45; --text: #e8edf7; --muted: #8b96b0;
  --accent: #22d3ee; --accent-ink: #062b33; --violet: #a78bfa; --critical: #fb7185; --low: #4ade80;
}
@media (prefers-color-scheme: light) {
  :root { --ink: #f4f6fb; --panel: #ffffff; --line: #dfe5f0; --text: #0f172a; --muted: #5b6478;
    --accent: #0891b2; --accent-ink: #ffffff; --violet: #6d28d9; --critical: #e11d48; --low: #15803d; }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { background: var(--ink); -webkit-text-size-adjust: 100%; }
body {
  min-height: 100vh; min-height: 100dvh; color: var(--text); display: grid; place-items: center;
  padding: max(24px, env(safe-area-inset-top)) max(20px, env(safe-area-inset-right)) max(24px, env(safe-area-inset-bottom)) max(20px, env(safe-area-inset-left));
  font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 16px; line-height: 1.5;
  background:
    radial-gradient(900px 520px at 15% -10%, rgba(34,211,238,.16), transparent 60%),
    radial-gradient(700px 420px at 100% 10%, rgba(167,139,250,.14), transparent 60%),
    var(--ink);
}
.display { font-family: "Space Grotesk", Inter, sans-serif; letter-spacing: -.02em; }
.mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace; }
.card {
  width: min(440px, 100%); background: var(--panel); border: 1px solid var(--line); border-radius: 22px;
  padding: 30px 28px 24px; box-shadow: 0 30px 80px rgba(0,0,0,.35); position: relative; overflow: hidden;
}
.card::before {
  content: ""; position: absolute; inset: -1px; border-radius: 22px; padding: 1px; pointer-events: none;
  background: linear-gradient(135deg, rgba(34,211,238,.6), transparent 40%, transparent 60%, rgba(167,139,250,.6));
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0); -webkit-mask-composite: xor; mask-composite: exclude;
}
.mark {
  width: 64px; height: 64px; border-radius: 18px; display: grid; place-items: center; margin-bottom: 18px;
  background: linear-gradient(135deg, var(--accent), var(--violet)); color: #0b0f17; font-family: "JetBrains Mono", monospace; font-weight: 700; font-size: 26px;
  box-shadow: 0 0 0 0 rgba(34,211,238,.35); animation: breathe 4s ease-in-out infinite;
}
@keyframes breathe { 0%,100% { box-shadow: 0 0 0 0 rgba(34,211,238,.35); } 50% { box-shadow: 0 0 0 14px rgba(34,211,238,0); } }
h1 { font-size: 30px; font-weight: 700; line-height: 1.1; }
h1 small { display: block; font-size: 13px; font-weight: 500; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
.lede { color: var(--muted); margin: 10px 0 24px; font-size: 15px; }
.btn {
  display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; min-height: 48px;
  border-radius: 12px; border: 1px solid transparent; background: var(--accent); color: var(--accent-ink);
  font: inherit; font-weight: 600; font-size: 15px; text-decoration: none; cursor: pointer; -webkit-tap-highlight-color: transparent;
}
.btn:hover { filter: brightness(1.06); } .btn:active { transform: scale(.985); }
.btn:focus-visible, input:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
.btn.ghost { background: transparent; color: var(--text); border-color: var(--line); }
.btn svg { width: 20px; height: 20px; fill: currentColor; }
.note { margin-top: 14px; font-size: 13px; color: var(--muted); text-align: center; }
.alert { margin: 0 0 18px; padding: 10px 12px; border-radius: 10px; font-size: 14px; border: 1px solid color-mix(in srgb, var(--critical) 45%, transparent); background: color-mix(in srgb, var(--critical) 12%, transparent); color: var(--text); }
details { margin-top: 18px; border-top: 1px solid var(--line); padding-top: 14px; }
summary { cursor: pointer; list-style: none; color: var(--muted); font-size: 13px; display: flex; align-items: center; gap: 8px; }
summary::-webkit-details-marker { display: none; }
summary .caret { transition: transform .2s; } details[open] .caret { transform: rotate(180deg); }
form.token { display: grid; gap: 10px; margin-top: 12px; }
input[type=password] {
  width: 100%; min-height: 46px; background: var(--ink); border: 1px solid var(--line); color: var(--text); border-radius: 12px;
  padding: 10px 14px; font: inherit; font-size: 16px; -webkit-appearance: none; appearance: none;
}
input::placeholder { color: var(--muted); }
footer { margin-top: 22px; display: flex; justify-content: space-between; color: var(--muted); font-size: 12px; }
footer a { color: inherit; text-decoration: none; }
.status { display: inline-flex; align-items: center; gap: 6px; }
.status .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--low); }
@media (prefers-reduced-motion: reduce) { .mark { animation: none; } }
</style>
</head>
<body>
<main class="card" role="main">
  <div class="mark" aria-hidden="true">&gt;_</div>
  <h1 class="display"><small>Rushing Technologies</small>agents</h1>
  <p class="lede">Security findings for every repository — the line, the reason, and the fix. Sign in to see them and to run scans.</p>
  %%ERROR%%
  %%GITHUB_BUTTON%%
  <p class="note">%%ALLOW_NOTE%%</p>
  %%TOKEN_FORM%%
  <footer>
    <span class="status"><span class="dot"></span>service online</span>
    <span class="mono">v%%VERSION%%</span>
  </footer>
</main>
</body>
</html>
"""

_GITHUB_MARK = (
    '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 '
    "5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-"
    ".82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87"
    ".51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 "
    "2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 "
    "2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 "
    '2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>'
)


def render_login(
    *,
    version: str,
    sign_in_enabled: bool,
    token_enabled: bool,
    error: str = "",
) -> str:
    """The sign-in page. No template engine: a handful of placeholders."""
    from html import escape

    if sign_in_enabled:
        button = (
            '<a class="btn" href="/auth/login">'
            + _GITHUB_MARK
            + "Sign in with GitHub</a>"
        )
        allow_note = "Only approved GitHub accounts can sign in."
    elif token_enabled:
        button = ""
        allow_note = "Sign in with the access token set on the service."
    else:
        button = ""
        allow_note = (
            "Sign-in is not configured yet — set GITHUB_OAUTH_CLIENT_ID and "
            "GITHUB_OAUTH_CLIENT_SECRET (or DASHBOARD_TOKEN) on the service."
        )
    token_form = ""
    if token_enabled:
        form = (
            '<form class="token" method="post" action="/auth/token">'
            '<input type="password" name="token" placeholder="Access token" '
            'autocomplete="current-password" required>'
            '<button class="btn ghost" type="submit">Continue with token</button></form>'
        )
        token_form = (
            (
                '<details><summary><span class="caret">▾</span>Use an access token '
                "instead</summary>" + form + "</details>"
            )
            if sign_in_enabled
            else form
        )
    alert = f'<div class="alert" role="alert">{escape(error)}</div>' if error else ""
    return (
        _LOGIN_HTML.replace("%%ERROR%%", alert)
        .replace("%%GITHUB_BUTTON%%", button)
        .replace("%%ALLOW_NOTE%%", allow_note)
        .replace("%%TOKEN_FORM%%", token_form)
        .replace("%%VERSION%%", escape(version))
    )


# ---------------------------------------------------------------------------
# Dashboard application
# ---------------------------------------------------------------------------

_DEFAULT_DATABASE = object()

# The newest verdict per finding, humans outranking triage — the same rule
# the CLI's `latest_findings`/`evaluate` use.
_LATEST_VERDICT_CTE = (
    "WITH latest_verdict AS ("
    "SELECT fb.*, ROW_NUMBER() OVER (PARTITION BY finding_id "
    "ORDER BY CASE source WHEN 'human' THEN 0 ELSE 1 END, created_at DESC, "
    "feedback_id DESC) AS rank FROM feedback fb) "
)


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
            # Severity counts exclude findings a person dismissed; those are
            # reported separately so the board's "needs attention" is honest.
            cur.execute(
                _LATEST_VERDICT_CTE + "SELECT f.severity, COUNT(*) FROM findings f "
                "LEFT JOIN latest_verdict v ON v.finding_id = f.finding_id AND v.rank = 1 "
                "WHERE v.verdict IS NULL OR v.verdict != 'FALSE_POSITIVE' "
                "GROUP BY f.severity"
            )
            by_severity: Dict[str, int] = {}
            for row in cur.fetchall():
                by_severity[row[0]] = row[1]
            cur.execute(
                _LATEST_VERDICT_CTE + "SELECT COUNT(*) FROM findings f "
                "JOIN latest_verdict v ON v.finding_id = f.finding_id AND v.rank = 1 "
                "WHERE v.verdict = 'FALSE_POSITIVE'"
            )
            dismissed = cur.fetchone()[0]
            cur.execute("SELECT MAX(created_at) FROM scan_runs")
            last_scan_at = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT project_key) FROM scan_runs")
            projects = cur.fetchone()[0]
            return {
                "total_scans": total_scans,
                "total_findings": total_findings,
                "by_severity": by_severity,
                "dismissed": dismissed,
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

    def get_findings(
        self, limit: int = 50, project: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return the most recent findings, newest scan first.

        `project` narrows to one repository (`owner/name`) or one local
        project path.

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
            where = ""
            params: List[Any] = []
            if project:
                where = "WHERE r.project_path IN (?, ?) "
                params = [f"/github/{project.strip('/')}", project]
            cur.execute(
                _LATEST_VERDICT_CTE
                + "SELECT f.severity, f.issue, f.file, f.agent, f.tool, f.fix, "
                "f.finding_id, r.created_at, r.project_path, r.scan_id, "
                "v.verdict, v.reason, v.source "
                "FROM findings f JOIN scan_runs r ON r.scan_id = f.scan_id "
                "LEFT JOIN latest_verdict v ON v.finding_id = f.finding_id AND v.rank = 1 "
                + where
                + "ORDER BY r.created_at DESC, CASE f.severity WHEN 'CRITICAL' THEN 0 "
                "WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
                "f.file, f.rowid LIMIT ?",
                [*params, limit],
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
                        "repository": scan_extra.get("repository"),
                        "source": scan_extra.get("source"),
                        "scan_id": row[9],
                        "verdict": row[10],
                        "verdict_reason": row[11],
                        "verdict_source": row[12],
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
                "repository": report.get("repository"),
                "source": report.get("source"),
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
            limit = min(int(request.args.get("limit", 50)), 500)
            project = request.args.get("project") or None
            return jsonify(dashboard.get_findings(limit=limit, project=project))

        @app.route("/api/events")
        def api_events():
            return Response(dashboard.sse_stream(), mimetype="text/event-stream")

        @app.route("/manifest.webmanifest")
        def manifest():
            body = json.dumps(
                {
                    "name": "agents — findings",
                    "short_name": "agents",
                    "start_url": "/",
                    "display": "standalone",
                    "background_color": "#0b0f17",
                    "theme_color": "#0b0f17",
                    "icons": [
                        {
                            "src": "/apple-touch-icon.png",
                            "sizes": "180x180",
                            "type": "image/png",
                        }
                    ],
                }
            )
            return Response(
                body,
                mimetype="application/manifest+json",
                headers={"Cache-Control": "public, max-age=86400"},
            )

        @app.route("/apple-touch-icon.png")
        def touch_icon():
            return Response(
                _icon_png(),
                mimetype="image/png",
                headers={"Cache-Control": "public, max-age=604800"},
            )

        return app

    # ── Helpers ───────────────────────────────────────────────────────

    def _connect(self) -> Optional[sqlite3.Connection]:
        if not self._db_path or not os.path.isfile(self._db_path):
            return None
        return sqlite3.connect(self._db_path)


_ICON_CACHE: Dict[str, bytes] = {}


def _icon_png(size: int = 180) -> bytes:
    """Home-screen icon: the header mark (cyan→violet square with a `>_`
    prompt), rendered without an imaging library so the web extra stays
    Flask-only."""
    if "png" in _ICON_CACHE:
        return _ICON_CACHE["png"]
    import struct
    import zlib

    cyan, violet, ink = (34, 211, 238), (167, 139, 250), (11, 15, 23)
    s = size
    # `>` and `_` drawn as thick strokes on a 12x12 design grid.
    cell = s / 12
    prompt = {(2, 2), (3, 3), (4, 4), (5, 5)}  # upper arm of `>`
    prompt |= {(2, 8), (3, 7), (4, 6)}  # lower arm meets the tip at (5, 5)
    prompt |= {(7, 8), (8, 8), (9, 8)}  # the `_`
    rows = []
    for y in range(s):
        row = bytearray([0])
        for x in range(s):
            t_ = (x + y) / (2 * s)
            r = int(cyan[0] + (violet[0] - cyan[0]) * t_)
            g = int(cyan[1] + (violet[1] - cyan[1]) * t_)
            b = int(cyan[2] + (violet[2] - cyan[2]) * t_)
            gx, gy = int(x / cell), int(y / cell)
            if (gx, gy) in prompt:
                r, g, b = ink
            row += bytes((r, g, b))
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return (
            struct.pack(">I", len(data))
            + body
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", s, s, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    _ICON_CACHE["png"] = png
    return png


def _rationale(tool: str, issue: str) -> str:
    try:
        from agents.server import explain_finding
    except Exception:  # noqa: BLE001 - dashboard must render without the server extra
        return ""
    return explain_finding(tool or "", {"issue": issue})


def findings_markdown(findings: List[Dict[str, Any]], title: str = "") -> str:
    """The hand-off format: findings grouped by repository, each with the
    line, the reason, the fix and its id — what a person (or Claude) needs
    to go fix them. Mirrors the dashboard's *Copy for Claude* button."""
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        title or f"# agents findings — {stamp}",
        "",
        f"Please fix these {len(findings)} finding(s). For each: change the code, "
        "keep behaviour, and say what you changed. Dismiss with "
        '`agents feedback <id> dismiss --reason "..."` if it is a false positive.',
        "",
    ]
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        key = finding.get("project_label") or finding.get("project") or "unknown"
        groups.setdefault(key, []).append(finding)
    for repo, rows in groups.items():
        first = rows[0]
        where = ""
        pr = first.get("pull_request") or {}
        repository = first.get("repository") or {}
        if pr.get("url"):
            where = f" (PR #{pr.get('number')}: {pr['url']})"
        elif repository.get("head_sha"):
            where = (
                f" (@ {repository.get('ref') or 'default'} "
                f"{str(repository['head_sha'])[:7]})"
            )
        lines += [f"## {repo}{where}", ""]
        for f in rows:
            loc = f"{f.get('file_path') or '?'}"
            if f.get("line"):
                loc += f":{f['line']}"
            lines.append(
                f"- **{f.get('severity', 'INFO')}** `{loc}` — {f.get('issue', '')}"
            )
            if f.get("snippet"):
                lines.append(f"  - line: `{f['snippet']}`")
            if f.get("why"):
                lines.append(f"  - why: {f['why']}")
            if f.get("fix"):
                lines.append(f"  - fix: {f['fix']}")
            tail = f"  - detector: {f.get('detector', '')}"
            if f.get("finding_id"):
                tail += f" · id: {f['finding_id']}"
            lines.append(tail)
        lines.append("")
    return "\n".join(lines)


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
