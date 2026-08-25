"""Precision regressions from the dashboard scan of mrnickrushing/Terminal-Connection
(a Socket.io relay: no list endpoint, and a log that prints only whether the
auth token is set)."""

from agents.api_architect import APIArchitectAgent
from agents.security_audit import SecurityAuditAgent


def _log_issues(code):
    return SecurityAuditAgent()._audit_logging_security(code)["findings"]


def test_presence_check_logs_are_not_secret_leaks():
    safe = "console.log('Token:', process.env.TERMINAL_TOKEN ? '[set]' : '[NOT SET - default]');"
    assert _log_issues(safe) == []
    assert (
        _log_issues("console.log('token configured:', Boolean(process.env.TOKEN));")
        == []
    )
    assert _log_issues("console.log('api_key', key.slice(0, 4) + '***');") == []
    # A real value in the log is still flagged.
    assert _log_issues("console.log('password', password);")
    # And the downstream 'no PII redaction' finding does not fire on the safe log.
    assert not any("redaction" in f["issue"].lower() for f in _log_issues(safe))


def test_server_listen_is_not_a_list_query():
    relay = """
const server = http.createServer(app);
app.get('/', (req, res) => res.json({ status: 'running', clients: set.size }));
server.listen(PORT, '0.0.0.0', () => console.log('up'));
"""
    result = APIArchitectAgent()._review_pagination(relay, "GET /")
    assert result["findings"] == []
    assert "not applicable" in result["note"]
    # A genuine list endpoint still gets flagged.
    listing = "app.get('/items', async (req, res) => { const rows = await db.select().from(items); res.json({ items: rows }); });"
    assert APIArchitectAgent()._review_pagination(listing, "GET /items")["findings"]
