"""Sign in with GitHub for the hosted dashboard, and the repository /
branch listings it unlocks. GitHub itself is mocked at the module boundary."""

import time
from urllib.parse import parse_qs, urlparse

import pytest

pytest.importorskip("flask")

from agents import webauth  # noqa: E402
from agents.server import create_app  # noqa: E402
from agents.webauth import SESSION_COOKIE, OAuthConfig, SessionStore  # noqa: E402

LEAKED_KEY = "q7Xv93LmZp2RtK8wYb4NcJ6HsD1fG0aE"


def test_session_store_round_trip_and_expiry(monkeypatch):
    store = SessionStore(":memory:")
    sid = store.create({"login": "nick", "name": "N", "avatar_url": "a"}, "gh-token")
    assert store.get(sid)["login"] == "nick"
    assert store.get(sid)["github_token"] == "gh-token"
    assert store.get("nope") is None and store.get(None) is None
    store.delete(sid)
    assert store.get(sid) is None
    sid = store.create({"login": "nick"}, "t")
    monkeypatch.setattr(webauth.time, "time", lambda: 4_000_000_000.0)
    assert store.get(sid) is None


@pytest.fixture
def github(monkeypatch):
    """Fake GitHub: code 'good' → token 'gh-abc' for @nick; 'stranger' for
    an account that is not on the allow list."""
    calls = {}

    def exchange(config, code, redirect_uri):
        calls["redirect_uri"] = redirect_uri
        if code == "good":
            return "gh-abc"
        if code == "stranger":
            return "gh-xyz"
        raise PermissionError("bad code")

    def user(token):
        return {
            "gh-abc": {"login": "Nick", "name": "Nick R", "avatar_url": "https://a/n"},
            "gh-xyz": {"login": "someone", "name": "", "avatar_url": ""},
        }[token]

    def repos(token, limit=300):
        calls["repos_token"] = token
        return [
            {"full_name": "nick/app", "private": True, "default_branch": "main"},
            {"full_name": "nick/site", "private": False, "default_branch": "master"},
        ]

    def branches(token, repo):
        calls["branches"] = (token, repo)
        return ["main", "dev"]

    monkeypatch.setattr(webauth, "exchange_code", exchange)
    monkeypatch.setattr(webauth, "fetch_user", user)
    monkeypatch.setattr(webauth, "list_repositories", repos)
    monkeypatch.setattr(webauth, "list_branches", branches)
    return calls


@pytest.fixture
def app(tmp_path, github):
    return create_app(
        db_path=str(tmp_path / "evolution.db"),
        webhook_secret="",
        dashboard_token="",
        oauth=OAuthConfig(
            client_id="cid", client_secret="csecret", allowed_logins=["nick"]
        ),
        session_db_path=":memory:",
    )


def _sign_in(client, code="good"):
    login = client.get("/auth/login")
    assert login.status_code == 302
    query = parse_qs(urlparse(login.headers["Location"]).query)
    assert query["client_id"] == ["cid"]
    assert query["redirect_uri"] == ["http://localhost/auth/callback"]
    state = query["state"][0]
    return client.get(f"/auth/callback?code={code}&state={state}")


def test_sign_in_flow_sets_a_session_and_unlocks_the_api(app, github):
    client = app.test_client()
    assert client.get("/api/me").get_json() == {
        "signed_in": False,
        "login": None,
        "name": None,
        "avatar_url": None,
        "sign_in_enabled": True,
        "token_enabled": False,
    }
    # Not signed in: the API refuses.
    assert client.post("/api/run", json={}).status_code == 401

    done = _sign_in(client)
    assert done.status_code == 302 and done.headers["Location"].endswith("/")
    cookie = done.headers.get("Set-Cookie", "")
    assert SESSION_COOKIE in cookie and "HttpOnly" in cookie
    assert github["redirect_uri"] == "http://localhost/auth/callback"

    me = client.get("/api/me").get_json()
    assert me["signed_in"] is True and me["login"] == "Nick"

    same_site = {"X-Requested-With": "fetch", "Origin": "http://localhost"}
    r = client.post(
        "/api/run",
        json={
            "agent": "security_audit",
            "tool": "audit_hardcoded_secrets",
            "args": {"code": f'api_key = "{LEAKED_KEY}"'},
        },
        headers=same_site,
    )
    assert r.status_code == 200 and r.get_json()["result"]["findings"]


def test_cookie_writes_need_the_fetch_header_and_a_same_site_origin(app):
    client = app.test_client()
    _sign_in(client)
    body = {
        "agent": "security_audit",
        "tool": "audit_hardcoded_secrets",
        "args": {"code": "x"},
    }
    assert client.post("/api/run", json=body).status_code == 403
    assert (
        client.post(
            "/api/run",
            json=body,
            headers={"X-Requested-With": "fetch", "Origin": "https://evil.example"},
        ).status_code
        == 403
    )


def test_repos_and_branches_use_the_signed_in_token(app, github):
    client = app.test_client()
    assert client.get("/api/repos").status_code == 401
    _sign_in(client)
    repos = client.get("/api/repos").get_json()
    assert [r["full_name"] for r in repos["repos"]] == ["nick/app", "nick/site"]
    assert github["repos_token"] == "gh-abc"
    assert client.get("/api/repos").get_json()["cached"] is True
    branches = client.get("/api/branches?repo=nick/app").get_json()
    assert branches["branches"] == ["main", "dev"]
    assert github["branches"] == ("gh-abc", "nick/app")
    assert client.get("/api/branches?repo=junk").status_code == 400


def test_logins_off_the_allow_list_are_refused(app):
    client = app.test_client()
    refused = _sign_in(client, code="stranger")
    assert refused.status_code == 403
    assert "someone" in refused.get_json()["error"]
    assert client.get("/api/me").get_json()["signed_in"] is False


def test_bad_state_and_bad_code_are_refused(app):
    client = app.test_client()
    client.get("/auth/login")
    assert client.get("/auth/callback?code=good&state=wrong").status_code == 400
    assert _sign_in(client, code="broken").status_code == 502


def test_logout_ends_the_session(app):
    client = app.test_client()
    _sign_in(client)
    assert client.get("/api/me").get_json()["signed_in"] is True
    out = client.post("/auth/logout", headers={"X-Requested-With": "fetch"})
    assert out.status_code == 200
    assert client.get("/api/me").get_json()["signed_in"] is False


def test_scan_uses_the_signed_in_token_for_the_clone(app, monkeypatch, tmp_path):
    import subprocess

    origin = tmp_path / "origin"
    origin.mkdir()
    (origin / "README.md").write_text("clean\n")
    subprocess.run(["git", "init", "-q"], cwd=origin, check=True)
    subprocess.run(["git", "add", "."], cwd=origin, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=origin,
        check=True,
    )
    seen = {}

    def fake_clone(repo, ref, destination, token=None):
        seen["token"] = token
        subprocess.run(["git", "clone", "-q", str(origin), destination], check=True)
        return "abc"

    monkeypatch.setattr("agents.server._clone_repository", fake_clone)
    client = app.test_client()
    _sign_in(client)
    r = client.post(
        "/api/scan",
        json={"repo": "nick/app", "agents": ["security_audit"]},
        headers={"X-Requested-With": "fetch", "Origin": "http://localhost"},
    )
    assert r.status_code == 202
    job_id = r.get_json()["job"]["id"]
    for _ in range(100):
        job = client.get(f"/api/jobs/{job_id}").get_json()["job"]
        if job["status"] in ("done", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "done", job
    assert job["requested_by"] == "Nick"
    assert seen["token"] == "gh-abc"
    assert "gh-abc" not in str(job)


def test_github_app_tokens_are_refreshed_when_expiring(app, github, monkeypatch):
    """GitHub Apps issue 8-hour user tokens with a refresh token; the 30-day
    session must renew them quietly instead of failing."""
    refreshed = {}

    def exchange(config, code, redirect_uri):
        return {
            "access_token": "gh-abc",
            "refresh_token": "ghr-1",
            "token_expires_at": time.time() + 30,  # about to expire
        }

    def refresh(config, refresh_token):
        refreshed["with"] = refresh_token
        return {
            "access_token": "gh-new",
            "refresh_token": "ghr-2",
            "token_expires_at": time.time() + 8 * 3600,
        }

    monkeypatch.setattr(webauth, "exchange_code", exchange)
    monkeypatch.setattr(webauth, "refresh_access_token", refresh)
    client = app.test_client()
    _sign_in(client)
    client.get("/api/repos")
    assert refreshed["with"] == "ghr-1"
    assert github["repos_token"] == "gh-new"
    # Second call: the renewed token is stored, no second refresh.
    refreshed.clear()
    client.get("/api/branches?repo=nick/app")
    assert not refreshed and github["branches"][0] == "gh-new"


def test_session_store_migrates_older_databases(tmp_path):
    import sqlite3

    path = tmp_path / "sessions.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE web_sessions (id_hash TEXT PRIMARY KEY, login TEXT NOT NULL, "
            "name TEXT NOT NULL, avatar_url TEXT NOT NULL, github_token TEXT NOT NULL, "
            "created_at REAL NOT NULL, expires_at REAL NOT NULL)"
        )
    store = SessionStore(str(path))
    sid = store.create({"login": "nick"}, {"access_token": "a", "refresh_token": "r"})
    assert store.get(sid)["refresh_token"] == "r"
    store.update_tokens(sid, "b")
    assert store.get(sid)["github_token"] == "b"


def test_sign_in_disabled_without_oauth_app(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "e.db"),
        webhook_secret="",
        dashboard_token="",
        oauth=OAuthConfig(client_id="", client_secret="", allowed_logins=[]),
        session_db_path=":memory:",
    )
    client = app.test_client()
    assert client.get("/auth/login").status_code == 503
    assert client.get("/api/me").get_json()["sign_in_enabled"] is False
    assert client.post("/api/run", json={}).status_code == 503
