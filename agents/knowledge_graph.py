"""
Codebase Knowledge Graph — AST-Based Indexing.

Builds a queryable directed graph of symbols and relationships for an entire
codebase.  Supports Python out of the box (stdlib ``ast``); JavaScript/
TypeScript files are scanned at the text level when ``tree_sitter`` is not
available.

Usage::

    from agents.knowledge_graph import CodebaseGraph

    graph = CodebaseGraph.build("/path/to/project")

    # Who calls 'validate_jwt'?
    callers = graph.find_callers("validate_jwt")

    # Which files import 'stripe'?
    importers = graph.find_importers("stripe")

    # Does user_input reach db.execute?
    paths = graph.find_tainted_paths("request.args.get", "db.execute")
"""

from __future__ import annotations

import ast
import concurrent.futures
import logging
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kg_symbols (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    kind     TEXT NOT NULL,
    file     TEXT NOT NULL,
    line     INTEGER,
    col      INTEGER,
    signature TEXT
);
CREATE INDEX IF NOT EXISTS idx_sym_name ON kg_symbols(name);
CREATE INDEX IF NOT EXISTS idx_sym_file ON kg_symbols(file);

CREATE TABLE IF NOT EXISTS kg_imports (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    file     TEXT NOT NULL,
    module   TEXT NOT NULL,
    alias    TEXT
);
CREATE INDEX IF NOT EXISTS idx_imp_file ON kg_imports(file);
CREATE INDEX IF NOT EXISTS idx_imp_module ON kg_imports(module);

CREATE TABLE IF NOT EXISTS kg_calls (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    caller_file TEXT NOT NULL,
    caller_func TEXT NOT NULL,
    callee      TEXT NOT NULL,
    line        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_call_callee ON kg_calls(callee);
CREATE INDEX IF NOT EXISTS idx_call_caller ON kg_calls(caller_func);

CREATE TABLE IF NOT EXISTS kg_data_flows (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    file   TEXT NOT NULL,
    source TEXT NOT NULL,
    sink   TEXT NOT NULL,
    line   INTEGER
);
"""

# ── Node/edge kinds ───────────────────────────────────────────────────────────

KIND_FUNCTION = "FUNCTION"
KIND_CLASS = "CLASS"
KIND_VARIABLE = "VARIABLE"
KIND_MODULE = "MODULE"

# File extensions to index
_PYTHON_EXTS = {".py"}
_JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_ALL_EXTS = _PYTHON_EXTS | _JS_EXTS

# Directories to skip
_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    "coverage",
}

# ── Helper visitors ───────────────────────────────────────────────────────────


class _PythonVisitor(ast.NodeVisitor):
    """Extract symbols, imports, calls, and basic taint from a Python AST."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.symbols: List[Dict[str, Any]] = []
        self.imports: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []
        self.data_flows: List[Dict[str, Any]] = []
        self._current_func: str = "<module>"
        self._func_stack: List[str] = []

    # ── symbols ──────────────────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # type: ignore[override]
        self._record_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # type: ignore[override]
        self._record_function(node)

    def _record_function(self, node: Any) -> None:
        args = [a.arg for a in node.args.args]
        sig = f"({', '.join(args)})"
        self.symbols.append(
            {
                "name": node.name,
                "kind": KIND_FUNCTION,
                "file": self.filepath,
                "line": node.lineno,
                "col": node.col_offset,
                "signature": sig,
            }
        )
        self._func_stack.append(node.name)
        self._current_func = node.name
        self.generic_visit(node)
        self._func_stack.pop()
        self._current_func = self._func_stack[-1] if self._func_stack else "<module>"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # type: ignore[override]
        self.symbols.append(
            {
                "name": node.name,
                "kind": KIND_CLASS,
                "file": self.filepath,
                "line": node.lineno,
                "col": node.col_offset,
                "signature": None,
            }
        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # type: ignore[override]
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.symbols.append(
                    {
                        "name": target.id,
                        "kind": KIND_VARIABLE,
                        "file": self.filepath,
                        "line": node.lineno,
                        "col": node.col_offset,
                        "signature": None,
                    }
                )
        self.generic_visit(node)

    # ── imports ───────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:  # type: ignore[override]
        for alias in node.names:
            self.imports.append(
                {
                    "file": self.filepath,
                    "module": alias.name,
                    "alias": alias.asname,
                }
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # type: ignore[override]
        module = node.module or ""
        for alias in node.names:
            self.imports.append(
                {
                    "file": self.filepath,
                    "module": f"{module}.{alias.name}" if module else alias.name,
                    "alias": alias.asname,
                }
            )

    # ── calls ─────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
        callee = _extract_call_name(node.func)
        if callee:
            self.calls.append(
                {
                    "caller_file": self.filepath,
                    "caller_func": self._current_func,
                    "callee": callee,
                    "line": node.lineno,
                }
            )
        # simple taint: look for source→sink in same call chain
        self._check_taint(node)
        self.generic_visit(node)

    def _check_taint(self, node: ast.Call) -> None:
        """Very lightweight taint: detect source patterns used as args to sinks."""
        _SOURCES = {
            "request.args.get",
            "request.form.get",
            "request.json",
            "os.getenv",
            "input",
        }
        _SINKS = {
            "db.execute",
            "cursor.execute",
            "eval",
            "exec",
            "subprocess.run",
            "os.system",
        }
        callee = _extract_call_name(node.func)
        if callee in _SINKS:
            for arg in ast.walk(node):
                if isinstance(arg, ast.Call):
                    src = _extract_call_name(arg.func)
                    if src in _SOURCES:
                        self.data_flows.append(
                            {
                                "file": self.filepath,
                                "source": src,
                                "sink": callee,
                                "line": node.lineno,
                            }
                        )


def _extract_call_name(node: Any) -> Optional[str]:
    """Best-effort extraction of a dotted call name from an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _extract_call_name(node.value)
        if owner:
            return f"{owner}.{node.attr}"
        return node.attr
    return None


# ── JS/TS text-level parser ───────────────────────────────────────────────────

_JS_FUNCTION_RE = re.compile(
    r"(?:^|\s)(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(",
    re.MULTILINE,
)
_JS_ARROW_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(",
    re.MULTILINE,
)
_JS_CLASS_RE = re.compile(r"(?:^|\s)class\s+(\w+)", re.MULTILINE)
_JS_IMPORT_RE = re.compile(
    r"import\s+(?:[^'\"]+\s+from\s+)?['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)
_JS_CALL_RE = re.compile(r"(\w[\w.]*)\s*\(", re.MULTILINE)


def _parse_js_file(filepath: str, source: str) -> Dict[str, List[Dict[str, Any]]]:
    """Extract symbols, imports, and calls from a JS/TS file via regex."""
    symbols: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    calls: List[Dict[str, Any]] = []

    def _lineno_for(match: re.Match) -> int:  # type: ignore[type-arg]
        return source[: match.start()].count("\n") + 1

    for m in _JS_FUNCTION_RE.finditer(source):
        symbols.append(
            {
                "name": m.group(1),
                "kind": KIND_FUNCTION,
                "file": filepath,
                "line": _lineno_for(m),
                "col": 0,
                "signature": None,
            }
        )
    for m in _JS_ARROW_RE.finditer(source):
        symbols.append(
            {
                "name": m.group(1),
                "kind": KIND_FUNCTION,
                "file": filepath,
                "line": _lineno_for(m),
                "col": 0,
                "signature": None,
            }
        )
    for m in _JS_CLASS_RE.finditer(source):
        symbols.append(
            {
                "name": m.group(1),
                "kind": KIND_CLASS,
                "file": filepath,
                "line": _lineno_for(m),
                "col": 0,
                "signature": None,
            }
        )
    for m in _JS_IMPORT_RE.finditer(source):
        imports.append(
            {
                "file": filepath,
                "module": m.group(1),
                "alias": None,
            }
        )
    for m in _JS_CALL_RE.finditer(source):
        name = m.group(1)
        # Skip keywords
        if name not in {"if", "while", "for", "switch", "catch", "return"}:
            calls.append(
                {
                    "caller_file": filepath,
                    "caller_func": "<module>",
                    "callee": name,
                    "line": _lineno_for(m),
                }
            )

    return {"symbols": symbols, "imports": imports, "calls": calls, "data_flows": []}


# ── Per-file indexing ─────────────────────────────────────────────────────────


def _index_file(filepath: str) -> Optional[Dict[str, List[Dict[str, Any]]]]:
    """Parse a single file and return extracted data, or None on error."""
    ext = Path(filepath).suffix.lower()
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError:
        return None

    if ext in _PYTHON_EXTS:
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return None
        visitor = _PythonVisitor(filepath)
        visitor.visit(tree)
        return {
            "symbols": visitor.symbols,
            "imports": visitor.imports,
            "calls": visitor.calls,
            "data_flows": visitor.data_flows,
        }
    elif ext in _JS_EXTS:
        return _parse_js_file(filepath, source)

    return None


# ── CodebaseGraph ─────────────────────────────────────────────────────────────


class CodebaseGraph:
    """
    In-memory + SQLite knowledge graph for a codebase.

    Build::

        graph = CodebaseGraph.build("/path/to/project")

    Query::

        graph.find_callers("validate_jwt")
        graph.find_importers("stripe")
        graph.find_tainted_paths("request.args.get", "db.execute")
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path:
            self._path: Optional[str] = db_path
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        else:
            # In-memory
            self._path = None
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._file_count = 0
        self._symbol_count = 0

    # ── build ─────────────────────────────────────────────────────────

    @classmethod
    def build(
        cls,
        project_path: str,
        db_path: Optional[str] = None,
        max_workers: int = 8,
    ) -> "CodebaseGraph":
        """
        Parse all supported source files under *project_path* and return a
        populated ``CodebaseGraph``.  Parsing runs in a thread pool.
        """
        graph = cls(db_path=db_path)
        files = list(_collect_files(project_path))
        logger.info(
            "CodebaseGraph: indexing %d files with %d workers", len(files), max_workers
        )
        start = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            results = list(pool.map(_index_file, files))

        graph._ingest_results(results)
        elapsed = time.time() - start
        logger.info(
            "CodebaseGraph: indexed %d files, %d symbols in %.1fs",
            graph._file_count,
            graph._symbol_count,
            elapsed,
        )
        return graph

    def _ingest_results(
        self, results: List[Optional[Dict[str, List[Dict[str, Any]]]]]
    ) -> None:
        conn = self._conn
        symbols_all: List[tuple] = []
        imports_all: List[tuple] = []
        calls_all: List[tuple] = []
        flows_all: List[tuple] = []

        for result in results:
            if result is None:
                continue
            self._file_count += 1
            for s in result["symbols"]:
                self._symbol_count += 1
                symbols_all.append(
                    (
                        s["name"],
                        s["kind"],
                        s["file"],
                        s["line"],
                        s.get("col"),
                        s.get("signature"),
                    )
                )
            for i in result["imports"]:
                imports_all.append((i["file"], i["module"], i.get("alias")))
            for c in result["calls"]:
                calls_all.append(
                    (c["caller_file"], c["caller_func"], c["callee"], c.get("line"))
                )
            for f in result["data_flows"]:
                flows_all.append((f["file"], f["source"], f["sink"], f.get("line")))

        conn.executemany(
            "INSERT INTO kg_symbols (name, kind, file, line, col, signature) VALUES (?,?,?,?,?,?)",
            symbols_all,
        )
        conn.executemany(
            "INSERT INTO kg_imports (file, module, alias) VALUES (?,?,?)",
            imports_all,
        )
        conn.executemany(
            "INSERT INTO kg_calls (caller_file, caller_func, callee, line) VALUES (?,?,?,?)",
            calls_all,
        )
        conn.executemany(
            "INSERT INTO kg_data_flows (file, source, sink, line) VALUES (?,?,?,?)",
            flows_all,
        )
        conn.commit()

    # ── query API ─────────────────────────────────────────────────────

    def find_callers(self, func_name: str) -> List[Dict[str, Any]]:
        """Return all call-sites that invoke *func_name* (exact or suffix match)."""
        rows = self._conn.execute(
            """
            SELECT caller_file as file, caller_func as caller_function, callee, line
            FROM kg_calls
            WHERE callee = ? OR callee LIKE ?
            ORDER BY caller_file, line
            """,
            (func_name, f"%.{func_name}"),
        ).fetchall()
        return [dict(r) for r in rows]

    def find_importers(self, module_name: str) -> List[Dict[str, Any]]:
        """Return all files that import *module_name* (exact or prefix match)."""
        rows = self._conn.execute(
            """
            SELECT file, module, alias
            FROM kg_imports
            WHERE module = ? OR module LIKE ? OR module LIKE ?
            ORDER BY file
            """,
            (module_name, f"{module_name}.%", f"%.{module_name}"),
        ).fetchall()
        return [dict(r) for r in rows]

    def find_symbols(
        self, name: str, kind: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Find all symbols with *name* (optionally filtered by kind)."""
        if kind:
            rows = self._conn.execute(
                "SELECT name, kind, file, line, col, signature FROM kg_symbols WHERE name = ? AND kind = ?",
                (name, kind),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT name, kind, file, line, col, signature FROM kg_symbols WHERE name = ?",
                (name,),
            ).fetchall()
        return [dict(r) for r in rows]

    def find_tainted_paths(self, source: str, sink: str) -> List[Dict[str, Any]]:
        """
        Return all direct source→sink data-flow edges found during indexing.

        This is a *static* approximation based on AST pattern matching, not
        a full taint-analysis engine.  False negatives are expected for
        indirect flows.
        """
        rows = self._conn.execute(
            """
            SELECT file, source, sink, line
            FROM kg_data_flows
            WHERE source = ? AND sink = ?
            ORDER BY file, line
            """,
            (source, sink),
        ).fetchall()
        return [dict(r) for r in rows]

    def symbols_in_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Return all symbols defined in *filepath*."""
        rows = self._conn.execute(
            "SELECT name, kind, file, line, col, signature FROM kg_symbols WHERE file = ? ORDER BY line",
            (filepath,),
        ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> Dict[str, int]:
        """Return graph statistics."""
        c = self._conn
        return {
            "files": self._file_count,
            "symbols": c.execute("SELECT COUNT(*) FROM kg_symbols").fetchone()[0],
            "imports": c.execute("SELECT COUNT(*) FROM kg_imports").fetchone()[0],
            "calls": c.execute("SELECT COUNT(*) FROM kg_calls").fetchone()[0],
            "data_flows": c.execute("SELECT COUNT(*) FROM kg_data_flows").fetchone()[0],
        }

    def close(self) -> None:
        self._conn.close()


# ── File collection helper ────────────────────────────────────────────────────


def _collect_files(project_path: str) -> List[str]:
    """Walk *project_path* and yield source files with supported extensions."""
    collected: List[str] = []
    for root, dirs, files in os.walk(project_path):
        # Skip unwanted directories in-place
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for filename in files:
            if Path(filename).suffix.lower() in _ALL_EXTS:
                collected.append(os.path.join(root, filename))
    return collected
