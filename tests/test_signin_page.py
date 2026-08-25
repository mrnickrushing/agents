"""The dashboard behind sign-in: the /login page, the gate on every other
route, the access-token form, and the still-public probes and webhook."""

from urllib.parse import parse_qs, unquote, urlparse

import pytest

pytest.importorskip("flask")

from agents import webauth  # noqa: E402
from agents.server import create_app  # noqa: E402
from agents.webauth import SESSION_COOKIE, OAuthConfig  # noqa: E402

TOKEN = "dashboard-test-token"


@pytest.fixture
def github(monkeypatch):
    monkeypatch.setattr(webauth, "exchange_code", lambda c, code, r: "gh-abc")
    monkeypatch.setattr(
        webauth,
        "fetch_user",
        lambda t: {"login": "nick", "name": "Nick", "avatar_url": "https://a/n"},
    )


@pytest.fixture
def gated(tmp_path, github):
    return create_app(
        db_path=str(tmp_path / "evolution.db"),
        webhook_secret="hook",
        dashboard_token=TOKEN,
        oauth=OAuthConfig(client_id="cid", client_secret="cs", allowed_logins=["nick"]),
        session_db_path=":memory:",
    )


def test_everything_redirects_to_login_until_signed_in(gated):
    client = gated.test_client()
    home = client.get("/")
    assert home.status_code == 302 and home.headers["Location"].endswith("/login")
    for path in ("/api/summary", "/api/findings", "/api/agents", "/api/jobs"):
        r = client.get(path)
        assert r.status_code == 401, path
        assert r.get_json()["error"] == "sign in first"
    assert client.get("/api/events").status_code == 401


def test_probes_webhook_and_assets_stay_public(gated):
    client = gated.test_client()
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/manifest.webmanifest").status_code == 200
    assert client.get("/apple-touch-icon.png").status_code == 200
    assert client.get("/api/me").get_json()["sign_in_required"] is True
    # The webhook is HMAC-gated on its own; it must not bounce to /login.
    assert client.post("/webhook", data=b"{}").status_code == 401


def test_login_page_offers_github_and_token(gated):
    page = gated.test_client().get("/login")
    assert page.status_code == 200
    assert page.headers["Cache-Control"] == "no-store"
    html = page.get_data(as_text=True)
    assert 'href="/auth/login"' in html and "Sign in with GitHub" in html
    assert 'action="/auth/token"' in html and "Use an access token instead" in html
    assert "Only approved GitHub accounts" in html
    shown = gated.test_client().get("/login?error=Nope+not+you").get_data(as_text=True)
    assert 'role="alert"' in shown and "Nope not you" in shown


def test_login_page_escapes_error_text(gated):
    html = gated.test_client().get("/login?error=<img src=x>").get_data(as_text=True)
    assert "<img src=x>" not in html and "&lt;img" in html


def test_github_sign_in_unlocks_the_dashboard(gated):
    client = gated.test_client()
    login = client.get("/auth/login")
    state = parse_qs(urlparse(login.headers["Location"]).query)["state"][0]
    done = client.get(f"/auth/callback?code=ok&state={state}")
    assert done.status_code == 302 and done.headers["Location"].endswith("/")
    assert client.get("/").status_code == 200
    assert client.get("/api/summary").status_code == 200
    assert client.get("/api/agents").status_code == 200
    # Signed-in people are sent home if they revisit /login.
    assert client.get("/login").status_code == 302


def test_callback_problems_land_on_login_with_a_message(gated, monkeypatch):
    client = gated.test_client()
    client.get("/auth/login")
    bad = client.get("/auth/callback?code=ok&state=wrong")
    assert bad.status_code == 302
    assert "expired or was tampered" in unquote(bad.headers["Location"])

    monkeypatch.setattr(
        webauth,
        "fetch_user",
        lambda t: {"login": "intruder", "name": "", "avatar_url": ""},
    )
    login = client.get("/auth/login")
    state = parse_qs(urlparse(login.headers["Location"]).query)["state"][0]
    refused = client.get(f"/auth/callback?code=ok&state={state}")
    assert refused.status_code == 302
    assert "@intruder is not on this dashboard's allow list" in unquote(
        refused.headers["Location"]
    )
    assert client.get("/api/me").get_json()["signed_in"] is False


def test_access_token_form_creates_a_session(gated):
    client = gated.test_client()
    wrong = client.post("/auth/token", data={"token": "nope"})
    assert wrong.status_code == 302 and "not right" in unquote(
        wrong.headers["Location"]
    )
    assert client.get("/").status_code == 302

    ok = client.post("/auth/token", data={"token": TOKEN})
    assert ok.status_code == 302 and ok.headers["Location"].endswith("/")
    assert SESSION_COOKIE in ok.headers.get("Set-Cookie", "")
    assert client.get("/").status_code == 200
    me = client.get("/api/me").get_json()
    assert me["signed_in"] is True and me["login"] == "token"
    # Bearer header still works for scripts, no cookie needed.
    fresh = gated.test_client()
    assert (
        fresh.get(
            "/api/agents", headers={"Authorization": f"Bearer {TOKEN}"}
        ).status_code
        == 200
    )


def test_sign_out_locks_the_dashboard_again(gated):
    client = gated.test_client()
    client.post("/auth/token", data={"token": TOKEN})
    assert client.get("/").status_code == 200
    client.post("/auth/logout", headers={"X-Requested-With": "fetch"})
    assert client.get("/").status_code == 302


def test_public_mode_keeps_findings_open_but_gates_runs(tmp_path, github):
    app = create_app(
        db_path=str(tmp_path / "e.db"),
        webhook_secret="",
        dashboard_token=TOKEN,
        oauth=OAuthConfig(client_id="", client_secret="", allowed_logins=[]),
        session_db_path=":memory:",
        public=True,
    )
    client = app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/api/summary").status_code == 200
    assert client.post("/api/run", json={}).status_code == 401
    assert client.get("/api/me").get_json()["sign_in_required"] is False


def test_every_listed_origin_is_a_full_front_door(tmp_path, github):
    """The custom domain and the Railway domain both serve the site; GitHub
    is sent back to whichever one the visitor is on. Unknown hosts fall back
    to the first origin's callback instead of one GitHub has never seen."""
    app = create_app(
        db_path=str(tmp_path / "e.db"),
        webhook_secret="",
        dashboard_token=TOKEN,
        oauth=OAuthConfig(client_id="cid", client_secret="cs", allowed_logins=["nick"]),
        session_db_path=":memory:",
        public_url_override=(
            "https://agents.example.com, https://agents-server-xyz.up.railway.app/"
        ),
    )
    client = app.test_client()
    for host in ("https://agents.example.com", "https://agents-server-xyz.up.railway.app"):
        page = client.get("/login", base_url=host)
        assert page.status_code == 200, host
        login = client.get("/auth/login", base_url=host)
        assert login.status_code == 302
        encoded = host.replace("://", "%3A%2F%2F") + "%2Fauth%2Fcallback"
        assert f"redirect_uri={encoded}" in login.headers["Location"], host
    stray = client.get("/auth/login", base_url="https://preview-123.up.railway.app")
    assert (
        "redirect_uri=https%3A%2F%2Fagents.example.com%2Fauth%2Fcallback"
        in stray.headers["Location"]
    )
    # Nothing redirects between hosts any more.
    assert client.get("/login", base_url="https://preview-123.up.railway.app").status_code == 200


def test_nothing_configured_means_nothing_to_sign_into(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "e.db"),
        webhook_secret="",
        dashboard_token="",
        oauth=OAuthConfig(client_id="", client_secret="", allowed_logins=[]),
        session_db_path=":memory:",
    )
    client = app.test_client()
    assert client.get("/").status_code == 200
    html = client.get("/login").get_data(as_text=True)
    assert "Sign-in is not configured yet" in html
    assert client.post("/auth/token", data={"token": "x"}).status_code == 302
