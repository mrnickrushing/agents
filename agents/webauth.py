"""
Sign in with GitHub for the hosted dashboard.

The page is public; running agents from it must not be. Instead of a shared
token, a person signs in with GitHub, the login is checked against an
allowlist, and a server-side session is created. The GitHub access token
from that sign-in stays on the server (never in a cookie) and is what lists
the person's repositories and clones private ones for web-triggered scans.

Environment:
    GITHUB_OAUTH_CLIENT_ID / GITHUB_OAUTH_CLIENT_SECRET
        An OAuth App on github.com whose callback URL is
        https://<your host>/auth/callback
    DASHBOARD_ALLOWED_LOGINS
        Comma-separated GitHub logins that may sign in. Empty → nobody.
    SESSION_SECRET
        Signs the state cookie; sessions themselves live in SQLite next to
        the evolution store, so they survive deploys.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"
OAUTH_SCOPE = "repo read:user"
SESSION_TTL = 30 * 24 * 3600
SESSION_COOKIE = "agents_session"
USER_AGENT = "rushingtech-agents"


class OAuthConfig:
    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        allowed_logins: Optional[List[str]] = None,
    ) -> None:
        self.client_id = client_id or os.environ.get("GITHUB_OAUTH_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get(
            "GITHUB_OAUTH_CLIENT_SECRET", ""
        )
        raw = (
            ",".join(allowed_logins)
            if allowed_logins is not None
            else os.environ.get("DASHBOARD_ALLOWED_LOGINS", "")
        )
        self.allowed_logins = {
            login.strip().casefold() for login in raw.split(",") if login.strip()
        }

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def allows(self, login: str) -> bool:
        return login.casefold() in self.allowed_logins


# ── GitHub calls (plain urllib; mocked in tests) ─────────────────────────


def _github_json(
    url: str,
    token: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
    accept: str = "application/vnd.github+json",
) -> Any:
    headers = {"Accept": accept, "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8", errors="replace") or "{}")


def authorize_url(config: OAuthConfig, redirect_uri: str, state: str) -> str:
    query = urllib.parse.urlencode(
        {
            "client_id": config.client_id,
            "redirect_uri": redirect_uri,
            "scope": OAUTH_SCOPE,
            "state": state,
            "allow_signup": "false",
        }
    )
    return f"{GITHUB_AUTHORIZE}?{query}"


def _token_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    token = payload.get("access_token")
    if not token:
        raise PermissionError(payload.get("error_description") or "no access token")
    expires_in = payload.get("expires_in")
    return {
        "access_token": str(token),
        # GitHub Apps issue expiring user tokens plus a refresh token; classic
        # OAuth Apps issue neither, and these stay empty.
        "refresh_token": str(payload.get("refresh_token") or ""),
        "token_expires_at": (time.time() + float(expires_in) if expires_in else 0.0),
    }


def exchange_code(config: OAuthConfig, code: str, redirect_uri: str) -> Dict[str, Any]:
    """Trade the callback `code` for tokens."""
    payload = _github_json(
        GITHUB_TOKEN_URL,
        data={
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        },
        accept="application/json",
    )
    return _token_response(payload)


def refresh_access_token(config: OAuthConfig, refresh_token: str) -> Dict[str, Any]:
    """Swap a GitHub App refresh token for a new access token."""
    payload = _github_json(
        GITHUB_TOKEN_URL,
        data={
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        accept="application/json",
    )
    return _token_response(payload)


def normalize_tokens(tokens: Any) -> Dict[str, Any]:
    """Accept a bare access token or a token dict."""
    if isinstance(tokens, dict):
        return {
            "access_token": str(tokens.get("access_token", "")),
            "refresh_token": str(tokens.get("refresh_token") or ""),
            "token_expires_at": float(tokens.get("token_expires_at") or 0.0),
        }
    return {"access_token": str(tokens), "refresh_token": "", "token_expires_at": 0.0}


def token_needs_refresh(session: Dict[str, Any], leeway: float = 120.0) -> bool:
    expires_at = float(session.get("token_expires_at") or 0.0)
    return bool(session.get("refresh_token")) and 0 < expires_at < time.time() + leeway


def fetch_user(token: str) -> Dict[str, Any]:
    user = _github_json(f"{GITHUB_API}/user", token=token)
    return {
        "login": user.get("login", ""),
        "name": user.get("name") or "",
        "avatar_url": user.get("avatar_url", ""),
    }


def list_repositories(token: str, limit: int = 300) -> List[Dict[str, Any]]:
    """Repositories the signed-in person can push to, most recently pushed
    first — the ones worth scanning."""
    repos: List[Dict[str, Any]] = []
    page = 1
    while len(repos) < limit:
        batch = _github_json(
            f"{GITHUB_API}/user/repos?"
            + urllib.parse.urlencode(
                {
                    "per_page": 100,
                    "page": page,
                    "sort": "pushed",
                    "affiliation": "owner,collaborator,organization_member",
                }
            ),
            token=token,
        )
        if not batch:
            break
        for repo in batch:
            repos.append(
                {
                    "full_name": repo.get("full_name", ""),
                    "private": bool(repo.get("private")),
                    "default_branch": repo.get("default_branch") or "main",
                    "pushed_at": repo.get("pushed_at"),
                    "language": repo.get("language"),
                }
            )
        if len(batch) < 100:
            break
        page += 1
    return repos[:limit]


def list_branches(token: Optional[str], repo: str) -> List[str]:
    branches = _github_json(
        f"{GITHUB_API}/repos/{repo}/branches?per_page=100", token=token
    )
    return [b.get("name", "") for b in branches if b.get("name")]


# ── Server-side sessions ─────────────────────────────────────────────────


class SessionStore:
    """Opaque session ids in a cookie; everything else (login, GitHub token)
    stays here. Only a hash of the id is stored, so a copy of the database
    does not hand out live sessions."""

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS web_sessions (
            id_hash TEXT PRIMARY KEY,
            login TEXT NOT NULL,
            name TEXT NOT NULL,
            avatar_url TEXT NOT NULL,
            github_token TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            refresh_token TEXT NOT NULL DEFAULT '',
            token_expires_at REAL NOT NULL DEFAULT 0
        )
    """
    # Columns added after the first release; applied to existing databases.
    MIGRATIONS = (
        "ALTER TABLE web_sessions ADD COLUMN refresh_token TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE web_sessions ADD COLUMN token_expires_at REAL NOT NULL DEFAULT 0",
    )

    def __init__(self, path: str) -> None:
        self.path = path
        self._memory: Optional[sqlite3.Connection] = None
        self._ready = False
        if path == ":memory:":
            self._memory = sqlite3.connect(":memory:", check_same_thread=False)
        # An unusable path (read-only volume, a file where the directory
        # should be) must not stop the dashboard from serving; sign-in simply
        # fails until it is fixed, and /ready reports the database problem.
        try:
            self._prepare()
        except (OSError, sqlite3.Error) as exc:
            logger.warning("session store unavailable at %s: %s", path, exc)

    def _prepare(self) -> None:
        if self._ready:
            return
        if self._memory is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        conn = self._connect()
        with conn:
            conn.execute(self.SCHEMA)
            for statement in self.MIGRATIONS:
                try:
                    conn.execute(statement)
                except sqlite3.OperationalError:
                    pass  # column already present
        if self._memory is None:
            conn.close()
        self._ready = True

    def _connect(self) -> sqlite3.Connection:
        if self._memory is not None:
            return self._memory
        return sqlite3.connect(self.path)

    @staticmethod
    def _hash(session_id: str) -> str:
        return hashlib.sha256(session_id.encode()).hexdigest()

    def create(self, user: Dict[str, Any], github_token: Any) -> str:
        self._prepare()
        tokens = normalize_tokens(github_token)
        session_id = secrets.token_urlsafe(32)
        now = time.time()
        conn = self._connect()
        with conn:
            conn.execute(
                "INSERT INTO web_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self._hash(session_id),
                    user.get("login", ""),
                    user.get("name", ""),
                    user.get("avatar_url", ""),
                    tokens["access_token"],
                    now,
                    now + SESSION_TTL,
                    tokens["refresh_token"],
                    tokens["token_expires_at"],
                ),
            )
            conn.execute("DELETE FROM web_sessions WHERE expires_at < ?", (now,))
        if self._memory is None:
            conn.close()
        return session_id

    def update_tokens(self, session_id: Optional[str], tokens: Any) -> None:
        if not session_id:
            return
        self._prepare()
        fresh = normalize_tokens(tokens)
        conn = self._connect()
        with conn:
            conn.execute(
                "UPDATE web_sessions SET github_token = ?, refresh_token = ?, "
                "token_expires_at = ? WHERE id_hash = ?",
                (
                    fresh["access_token"],
                    fresh["refresh_token"],
                    fresh["token_expires_at"],
                    self._hash(session_id),
                ),
            )
        if self._memory is None:
            conn.close()

    def get(self, session_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not session_id:
            return None
        try:
            self._prepare()
            conn = self._connect()
        except (OSError, sqlite3.Error):
            return None
        try:
            row = conn.execute(
                "SELECT login, name, avatar_url, github_token, expires_at, "
                "refresh_token, token_expires_at "
                "FROM web_sessions WHERE id_hash = ?",
                (self._hash(session_id),),
            ).fetchone()
        except sqlite3.Error:
            return None
        finally:
            if self._memory is None:
                conn.close()
        if not row or row[4] < time.time():
            return None
        return {
            "login": row[0],
            "name": row[1],
            "avatar_url": row[2],
            "github_token": row[3],
            "refresh_token": row[5],
            "token_expires_at": row[6],
        }

    def delete(self, session_id: Optional[str]) -> None:
        if not session_id:
            return
        try:
            self._prepare()
        except (OSError, sqlite3.Error):
            return
        conn = self._connect()
        with conn:
            conn.execute(
                "DELETE FROM web_sessions WHERE id_hash = ?", (self._hash(session_id),)
            )
        if self._memory is None:
            conn.close()


def default_session_db_path(evolution_db_path: str) -> str:
    if evolution_db_path == ":memory:":
        return ":memory:"
    return os.path.join(
        os.path.dirname(os.path.abspath(evolution_db_path)), "sessions.db"
    )
