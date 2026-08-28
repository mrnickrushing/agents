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
