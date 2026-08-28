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
