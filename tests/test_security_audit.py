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
