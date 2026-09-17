from agents.security_audit import SecurityAuditAgent


def test_cors_wildcard_methods_and_headers_dont_trigger_origin_finding():
    """allow_methods=["*"] / allow_headers=["*"] are common, fine config —
    they must not be mistaken for a wildcard *origin*, which is the actual
    security issue this check exists to catch."""
    agent = SecurityAuditAgent()
    code = """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    """
    result = agent._audit_cors_config(code)
    severities = [f["severity"] for f in result["cors_findings"]]
    assert "CRITICAL" not in severities


def test_cors_wildcard_origin_fastapi_still_flagged():
    agent = SecurityAuditAgent()
    code = """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
    )
    """
    result = agent._audit_cors_config(code)
    severities = [f["severity"] for f in result["cors_findings"]]
    assert severities.count("CRITICAL") == 2


def test_cors_wildcard_origin_express_still_flagged():
    agent = SecurityAuditAgent()
    code = 'app.use(cors({ origin: "*", credentials: true }));'
    result = agent._audit_cors_config(code)
    severities = [f["severity"] for f in result["cors_findings"]]
    assert severities.count("CRITICAL") == 2


def test_cors_wildcard_origin_trailing_comma_fastapi():
    agent = SecurityAuditAgent()
    code = 'app.add_middleware(CORSMiddleware, allow_origins=["*",], allow_credentials=True)'
    result = agent._audit_cors_config(code)
    severities = [f["severity"] for f in result["cors_findings"]]
    assert severities.count("CRITICAL") == 2


def test_cors_wildcard_origin_mixed_list_fastapi():
    agent = SecurityAuditAgent()
    code = 'app.add_middleware(CORSMiddleware, allow_origins=["https://trusted.example", "*"], allow_credentials=True)'
    result = agent._audit_cors_config(code)
    severities = [f["severity"] for f in result["cors_findings"]]
    assert severities.count("CRITICAL") == 2


def test_cors_wildcard_origin_quoted_key_express():
    """JSON-style quoted key ("origin": "*") rather than a bare identifier."""
    agent = SecurityAuditAgent()
    code = '{ "origin": "*", "credentials": true }'
    result = agent._audit_cors_config(code)
    severities = [f["severity"] for f in result["cors_findings"]]
    assert severities.count("CRITICAL") == 2


def test_helmet_call_described_in_a_comment_is_not_read_as_a_bare_call():
    """Regression: the bare-call check regexed the whole file, so a config
    that *mentions* helmet() in a comment while actually calling
    helmet({...}) was reported as unconfigured (VibeMaps
    backend/src/index.ts, 2026-08-28)."""
    agent = SecurityAuditAgent()
    code = """
    // Listed explicitly rather than relying on Helmet's implicit
    // defaults — identical behavior to calling helmet() bare.
    app.use(helmet({
      contentSecurityPolicy: true,
      hsts: true,
      noSniff: true,
      xFrameOptions: true,
      referrerPolicy: true,
      crossOriginOpenerPolicy: true,
      crossOriginEmbedderPolicy: false,
      crossOriginResourcePolicy: { policy: 'cross-origin' },
    }));
    """
    result = agent._analyze_helmet_config(code)
    issues = [f["issue"] for f in result["findings"]]
    assert not any("called with no options" in issue for issue in issues)
    assert not any("No helmet() call found" in issue for issue in issues)


def test_genuinely_bare_helmet_call_is_still_reported():
    agent = SecurityAuditAgent()
    result = agent._analyze_helmet_config("app.use(helmet());")
    issues = [f["issue"] for f in result["findings"]]
    assert any("called with no options" in issue for issue in issues)


def test_commented_out_helmet_call_does_not_count_as_configured():
    """A file whose only helmet() is commented out has no security headers."""
    agent = SecurityAuditAgent()
    result = agent._analyze_helmet_config("// app.use(helmet());\napp.listen(3000);")
    issues = [f["issue"] for f in result["findings"]]
    assert any("No helmet() call found" in issue for issue in issues)


def test_disabled_csp_inside_a_comment_is_not_a_finding():
    agent = SecurityAuditAgent()
    code = """
    /* We never set contentSecurityPolicy: false here — see the CSP notes. */
    app.use(helmet({ contentSecurityPolicy: { directives: {} }, hsts: true,
      noSniff: true, xFrameOptions: true, referrerPolicy: true,
      crossOriginOpenerPolicy: true, crossOriginEmbedderPolicy: true,
      crossOriginResourcePolicy: true }));
    """
    result = agent._analyze_helmet_config(code)
    issues = [f["issue"] for f in result["findings"]]
    assert not any("explicitly disabled" in issue for issue in issues)


def test_url_in_a_string_is_not_treated_as_a_comment():
    """Regression: stripping comments with a bare `//[^\\n]*` sweep also ate
    the rest of any line containing a URL, so a CSP directive after one went
    unchecked — a false negative on a security rule (Codex, agents#60)."""
    agent = SecurityAuditAgent()
    code = """
    app.use(helmet({
      contentSecurityPolicy: {
        directives: { scriptSrc: ["https://cdn.example.com", "'unsafe-inline'"] },
      },
      hsts: true, noSniff: true, xFrameOptions: true, referrerPolicy: true,
      crossOriginOpenerPolicy: true, crossOriginEmbedderPolicy: true,
      crossOriginResourcePolicy: true,
    }));
    """
    result = agent._analyze_helmet_config(code)
    issues = [f["issue"] for f in result["findings"]]
    assert any("unsafe-inline" in issue for issue in issues)


def test_strip_js_comments_keeps_urls_regexes_and_division():
    from agents.security_audit import _strip_js_comments

    # A URL's "//" is not a comment.
    assert "'unsafe-inline'" in _strip_js_comments(
        'scriptSrc: ["https://cdn.example", "\'unsafe-inline\'"]'
    )
    # Division is not a regex literal, so the rest of the line survives.
    assert "count" in _strip_js_comments("const rate = total / count; // note")
    # A regex literal containing slashes is copied through.
    assert "/https:\\/\\/x/" in _strip_js_comments("const re = /https:\\/\\/x/; // c")
    # "//" inside a string stays; a real comment goes.
    stripped = _strip_js_comments('const s = "// kept"; // dropped\nnext();')
    assert "// kept" in stripped and "dropped" not in stripped and "next()" in stripped
    # An apostrophe inside a line comment must not open a string literal.
    assert "const b = 2" in _strip_js_comments(
        "const a = 1; // don't break\nconst b = 2;"
    )


def test_browserslist_query_is_not_an_open_ended_dependency_range():
    """Create React App ships a ">0.2%" browserslist query, which looks like
    a version range to a whole-manifest regex and flagged every CRA project
    (aegisapparel frontend/package.json, 2026-08-28)."""
    from agents.supply_chain_audit import SupplyChainAuditAgent

    manifest = (
        '{"dependencies": {"react": "18.3.1"},'
        ' "browserslist": {"production": [">0.2%", "not dead"]}}'
    )
    result = SupplyChainAuditAgent()._audit_supply_chain(manifest, "package.json")
    issues = [f["issue"] for f in result["findings"]]
    assert not any("open-ended version ranges" in issue for issue in issues)


def test_genuine_open_ended_dependency_range_is_still_reported():
    from agents.supply_chain_audit import SupplyChainAuditAgent

    manifest = '{"dependencies": {"react": ">=18", "lodash": "latest"}}'
    result = SupplyChainAuditAgent()._audit_supply_chain(manifest, "package.json")
    issues = [f["issue"] for f in result["findings"]]
    assert any("open-ended version ranges" in issue for issue in issues)


def test_upload_cap_named_max_upload_bytes_counts_as_a_size_limit():
    """The name list missed MAX_UPLOAD_BYTES / MAX_FILE_SIZE, so a capped
    endpoint was reported as unbounded (aegisapparel, 2026-08-28)."""
    agent = SecurityAuditAgent()
    code = (
        "MAX_UPLOAD_BYTES = 5 * 1024 * 1024\n"
        '@api_router.post("/admin/uploads")\n'
        "async def admin_upload_file(file: UploadFile = File(...)):\n"
        "    total = 0\n"
        "    while chunk := await file.read(65536):\n"
        "        total += len(chunk)\n"
        "        if total > MAX_UPLOAD_BYTES:\n"
        '            raise HTTPException(status_code=400, detail="File too large")\n'
    )
    issues = [f["issue"] for f in agent._audit_file_upload(code)["findings"]]
    assert not any("No file size limit" in issue for issue in issues)


def test_upload_with_no_cap_at_all_is_still_reported():
    agent = SecurityAuditAgent()
    code = (
        '@app.post("/upload")\n'
        "async def upload(file: UploadFile = File(...)):\n"
        "    contents = await file.read()\n"
        '    open("out", "wb").write(contents)\n'
    )
    issues = [f["issue"] for f in agent._audit_file_upload(code)["findings"]]
    assert any("No file size limit" in issue for issue in issues)


def test_unrelated_max_size_constant_does_not_count_as_an_upload_cap():
    """A pagination or buffer limit is not a file-size cap; matching any
    max…size name suppressed the unbounded-upload finding (Codex,
    agents#64)."""
    agent = SecurityAuditAgent()
    code = (
        "MAX_PAGE_SIZE = 100\n"
        '@app.post("/upload")\n'
        "async def upload(file: UploadFile = File(...)):\n"
        "    contents = await file.read()\n"
        '    open("out", "wb").write(contents)\n'
    )
    issues = [f["issue"] for f in agent._audit_file_upload(code)["findings"]]
    assert any("No file size limit" in issue for issue in issues)


# --- innerHTML: reported per assignment, only where the value is dynamic -----


def _html_issues(code):
    return [
        f
        for f in SecurityAuditAgent()._audit_xss_patterns(code)["findings"]
        if "innerHTML" in f["issue"]
    ]


def test_literal_markup_assigned_to_innerhtml_is_not_reported():
    """Clearing a container, or dropping in a fixed empty state, carries
    nothing that could be user-controlled. Firing on every file that renders
    at all made the check unactionable (backgrounds, 2026-08-28)."""
    for code in (
        'el.innerHTML = "";',
        "list.innerHTML = '<div class=\"empty\">No items</div>';",
        "el.innerHTML = `<p>Nothing yet</p>`;",
        'el.innerHTML = "<b>" + "hi" + "</b>";',
        "// el.innerHTML = userInput;\nconst x = 1;",
    ):
        assert _html_issues(code) == [], code


def test_a_value_built_at_runtime_is_reported_with_its_line():
    for code in (
        "el.innerHTML = `<p>${name}</p>`;",
        "el.innerHTML = html;",
        "el.innerHTML = render(rows);",
        'el.innerHTML = "<b>" + name + "</b>";',
    ):
        found = _html_issues(code)
        assert found, code
        assert found[0]["line"] == 1


def test_the_append_form_is_the_same_sink():
    """`innerHTML +=` was missed entirely: the old pattern required `=`
    immediately after the property name."""
    assert _html_issues("el.innerHTML += `<li>${item}</li>`;")


def test_a_statement_continued_on_the_next_line_is_read_whole():
    """Stopping at the newline after `=` would read an empty right-hand side
    and call the assignment static."""
    found = _html_issues("node.innerHTML =\n  header(c) +\n  records(c.rows);")
    assert found and found[0]["line"] == 1


def test_the_finding_says_how_many_sites_there_are():
    code = 'a.innerHTML = x;\nb.innerHTML = "";\nc.innerHTML = y;\n'
    found = _html_issues(code)
    assert len(found) == 1
    assert "line 1 and 1 more" in found[0]["issue"]


def test_an_operator_leading_the_next_line_continues_the_expression():
    """`= '<b>'` then `+ userInput` is one expression. Reading only the
    literal would judge the assignment static and suppress the finding."""
    found = _html_issues("el.innerHTML = '<b>'\n  + userInput;\n")
    assert found and found[0]["line"] == 1


def test_a_following_statement_does_not_continue_the_expression():
    """No semicolon, but the next line starts a statement rather than
    continuing this one — the assignment really is static."""
    assert _html_issues('el.innerHTML = ""\nel.textContent = "x"\n') == []


def test_the_scan_discovery_rule_reaches_the_append_form():
    """The handler supports `+=`, but the repository scan only invokes it when
    the discovery expression matches the file first."""
    import re as _re

    from agents.cli import RULES, _discovery_text

    rule = next(r for r in RULES if r[3] == "audit_xss_patterns")
    for code in ("el.innerHTML = userInput;", "el.innerHTML += userInput;"):
        assert _re.search(
            rule[1], _discovery_text("f.js", code, "audit_xss_patterns")
        ), code


# ── SQL injection: literal extraction ─────────────────────────────────────────


def _sql(code):
    return SecurityAuditAgent()._audit_sql_injection(code)["findings"]


def _kinds(code):
    return {
        key
        for key, token in (
            ("template", "template-literal"),
            ("concat", "concatenation"),
            ("fstring", "f-string"),
            ("format", ".format()"),
            ("percent", "%-formatting"),
        )
        for finding in _sql(code)
        if token in finding["issue"]
    }


def test_fstring_query_containing_a_quoted_value_is_flagged():
    """The regression this rewrite exists for.

    `[^"']*` cannot span a literal holding the other quote, so the body
    stopped at the inner `'` and lost the `{term}` that proves the query is
    interpolated — the check read it as static SQL and said nothing. That is
    the exact shape a real injection takes.
    """
    assert _kinds("""cur.execute(f"SELECT * FROM users WHERE name = '{term}'")""") == {
        "fstring"
    }


def test_concatenated_query_containing_a_quoted_value_is_flagged():
    """Same root cause on the concatenation branch: the character class
    matched the empty span between `'` and `"` rather than the SQL."""
    assert _kinds(
        """db.query("SELECT * FROM t WHERE n = '" + req.query.n + "'")"""
    ) == {"concat"}


def test_triple_quoted_query_is_flagged():
    code = 'cur.execute(f"""\n    SELECT * FROM t\n    WHERE a = \'{x}\'\n""")'
    assert _kinds(code) == {"fstring"}


def test_format_and_percent_interpolation_are_flagged():
    """Both were named in the comment above the check but never implemented."""
    assert _kinds("""cur.execute("SELECT * FROM t WHERE a = {}".format(v))""") == {
        "format"
    }
    assert _kinds("""cur.execute("SELECT * FROM t WHERE a = %s" % v)""") == {"percent"}


def test_bound_parameters_are_not_mistaken_for_interpolation():
    """`"... %s", (v,)` is the safe form and `"... %s" % v` is not; the
    difference is whether a percent follows the closing quote."""
    for safe in (
        """conn.execute("SELECT * FROM users WHERE id = ?", (uid,))""",
        """db.query("INSERT INTO users (email) VALUES ($1)", [email])""",
        """cur.execute("UPDATE t SET a = %s WHERE b = %s", (a, b))""",
        """cur.execute("DELETE FROM t WHERE id = :tid", {"tid": tid})""",
        """cur.execute("SELECT * FROM t WHERE n LIKE '%foo%'", ())""",
    ):
        assert _sql(safe) == [], safe


def test_prose_is_not_read_as_sql():
    """The false positive the original check was tightened to avoid: an
    f-string of ordinary English containing the word "update"."""
    assert _sql('log.info(f"Last case update recorded on {when}")') == []
    assert _sql('path = f"/users/{uid}/profile"') == []


def test_static_sql_and_literal_concatenation_stay_silent():
    assert _sql('cur.execute("SELECT * FROM users")') == []
    assert _sql('q = "SELECT * FROM t" + " WHERE 1=1"') == []


def test_request_values_escalate_to_critical():
    for code in (
        "db.query(`SELECT * FROM t WHERE a = ${req.body.x}`)",
        'cur.execute(f"SELECT * FROM t WHERE a = {request.args}")',
    ):
        assert [f["severity"] for f in _sql(code)] == ["CRITICAL"], code


def test_opaque_variable_stays_medium():
    """An opaque name is as often a pre-built parameterised fragment as it is
    raw input; the check must not assert CRITICAL on a guess."""
    assert [
        f["severity"] for f in _sql("db.query(`SELECT * FROM t WHERE a = ${frag}`)")
    ] == ["MEDIUM"]


def test_scan_reaches_the_python_spellings_of_a_query():
    """A handler the scan never invokes is dead code.

    Two things had to be true for this check to run on Python, and neither
    was. The discovery expression named three receivers (`cursor`, `db`,
    `session`), missing the usual `conn`/`cur`. And it is matched against
    `_discovery_text`, which re-spaces Python tokens into `conn .execute (`
    — so even `db.execute(` verbatim could not match a .py file. The check
    had a Python f-string branch that no Python file ever reached.

    Asserting against raw source would pass while the scan stayed broken,
    so this matches what the scan actually matches.
    """
    import re

    from agents.cli import RULES, _discovery_text

    # RULES entries are (file_pattern, content_regex, agent, tool, argmaker).
    pattern = next(rule[1] for rule in RULES if rule[3] == "audit_sql_injection")
    gate = re.compile(pattern)
    for name, code in (
        ("a.py", 'conn.execute(f"SELECT * FROM t WHERE a = {x}")'),
        ("a.py", 'cur.execute(f"SELECT * FROM t WHERE a = {x}")'),
        ("a.py", 'engine.execute("SELECT * FROM t WHERE a = " + x)'),
        ("a.py", 'cur.executemany("INSERT INTO t VALUES (%s)" % v)'),
        ("a.py", 'Model.objects.raw("SELECT * FROM t WHERE a = " + x)'),
        ("a.py", 'db.execute(f"SELECT * FROM t WHERE a = {x}")'),
        ("a.py", 'session.execute(f"SELECT * FROM t WHERE a = {x}")'),
        ("a.ts", 'db.query("SELECT * FROM t WHERE n = " + name)'),
        ("a.ts", "cursor.execute(`SELECT * FROM t WHERE a = ${v}`)"),
    ):
        assert gate.search(_discovery_text(name, code, "audit_sql_injection")), code


def test_sql_inside_a_docstring_is_not_reported():
    """A documentation example is not a vulnerability.

    Found by sweeping 2302 stdlib/site-packages files: the old check reported
    CPython's own `typing.py` as having a SQL injection, because it regexed
    through the `LiteralString` docstring — whose whole point is to explain
    SQL injection. Walking literals instead means a docstring is one literal
    and the check does not read inside it.
    """
    code = '''
def run_query(sql):
    """Run a query.

    Example::

        run_query("SELECT * FROM " + literal_string)  # OK
        run_query(f"SELECT * FROM students WHERE name = {arbitrary}")
    """
    return execute(sql)
'''
    assert _sql(code) == []


def test_sql_outside_the_docstring_is_still_reported():
    """The exemption is the docstring, not the function containing one."""
    code = '''
def run_query(name):
    """Run a query."""
    return cur.execute(f"SELECT * FROM students WHERE name = '{name}'")
'''
    assert _kinds(code) == {"fstring"}
