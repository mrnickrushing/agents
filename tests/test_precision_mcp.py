"""Precision regressions from the first dashboard scan of mrnickrushing/mcp:
the hardcoded-secret detector flagged a docstring example and a print
string that spanned lines."""

from agents.security_audit import SecurityAuditAgent, _is_placeholder_credential


def _issues(code):
    return [
        f["issue"]
        for f in SecurityAuditAgent()._audit_hardcoded_secrets(code)["findings"]
    ]


def test_secret_values_never_span_lines():
    code = """
        print(f"\\n{len(noise)} finding(s) suppressed as byte tables\\n"
              "  permutation from a crypto library, not a secret:")
        for f in noise:
            print(f"  [{f.severity}] {f.title}")
"""
    assert not any("Secret" in i for i in _issues(code))
    real = 'secret = "sk-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"\n'
    assert any("Secret" in i for i in _issues(real))


def test_documentation_connection_strings_are_not_credentials():
    code = """
    # A URL with credentials in it: postgres://user:secret@host/db. Matches no
    # token pattern above, and it is the shape a pasted connection string takes.
    re.compile(r"(?P<pre>\\b[a-z][a-z0-9+.\\-]*://[^\\s:@/]+:)[^\\s@/]+(?P<post>@)"),
    url = "postgres://app:${DB_PASSWORD}@db.internal/app"
    other = "mysql://root:<password>@localhost/x"
"""
    assert not any("Database URL" in i for i in _issues(code))
    leak = 'DATABASE_URL = "postgres://app:Tr0ub4dor&3xyz@db.example.net/app"\n'
    assert any("Database URL" in i for i in _issues(leak))


def test_placeholder_vocabulary():
    for value in (
        "secret",
        "PASSWORD",
        "${DB_PASSWORD}",
        "<password>",
        "{{ pass }}",
        "********",
    ):
        assert _is_placeholder_credential(value), value
    for value in ("Tr0ub4dor&3xyz", "s3cr3t-value-here", ""):
        assert not _is_placeholder_credential(value), value
