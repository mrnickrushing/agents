from agents.auth_security import AuthSecurityAgent


def test_apple_sign_in_client_token_acquisition_not_flagged():
    """Expo's AppleAuthentication.signInAsync only obtains the identity
    token — verifying it is a backend responsibility living in a different
    service. A client file with no local JWT decode/verify shouldn't be
    told its (nonexistent) verification logic is missing JWKS/iss/aud."""
    agent = AuthSecurityAgent()
    code = """
    const cred = await AppleAuthentication.signInAsync({
      requestedScopes: [AppleAuthentication.AppleAuthenticationScope.EMAIL],
      nonce: hashedNonce,
    });
    await loginWithSocial("apple", cred.identityToken, nonce);
    """
    result = agent._review_apple_sign_in(code)
    assert result["findings"] == []


def test_apple_sign_in_backend_still_flagged_when_missing_jwks():
    agent = AuthSecurityAgent()
    code = """
    def verify(token, nonce):
        claims = jwt.decode(token, options={"verify_signature": False})
        return claims
    """
    result = agent._review_apple_sign_in(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "CRITICAL" in severities


def test_apple_sign_in_audience_option_key_recognized():
    """jose's jwtVerify() takes an `audience:` option — the check
    shouldn't require the literal word "aud" when this is present."""
    agent = AuthSecurityAgent()
    code = """
    const { payload } = await jwtVerify(identityToken, jwks, {
      issuer: APPLE_ISSUER,
      audience: env.APPLE_BUNDLE_ID,
    });
    if (payload.nonce !== expectedNonce) throw new Error("bad nonce");
    """
    result = agent._review_apple_sign_in(code)
    issues = [f["issue"] for f in result["findings"]]
    assert not any("audience" in i.lower() for i in issues)


def test_refresh_rotation_pure_client_storage_not_flagged():
    """A mobile state file that only saves/reads tokens via SecureStore
    isn't where rotation is implemented — that's the backend /refresh
    endpoint's job, in a service this file has no import path to."""
    agent = AuthSecurityAgent()
    code = """
    export const useAuth = create((set) => ({
      acceptTokens: async (accessToken, refreshToken) => {
        await saveTokens(accessToken, refreshToken);
      },
    }));
    """
    result = agent._review_refresh_token_rotation(code, language="node")
    assert result["findings"] == []


def test_refresh_rotation_server_issuer_still_flagged_when_missing():
    agent = AuthSecurityAgent()
    code = """
    def issue_tokens(user):
        refresh_token = jwt.sign({"sub": user.id}, SECRET)
        db.sessions.insert(user_id=user.id, refresh_token=refresh_token)
        return refresh_token
    """
    result = agent._review_refresh_token_rotation(code, language="python")
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" in severities


def test_shared_secret_header_bracket_compare_flagged():
    """The most common Express gate reads the key through a bracket
    accessor — req.headers["x-api-key"] == ADMIN_SECRET. The old regex
    required secret-vocabulary words on BOTH sides of the operator and
    never flagged any of these shapes."""
    agent = AuthSecurityAgent()
    code = """
    const ADMIN_SECRET = process.env.ADMIN_SECRET;
    if (req.headers["x-api-key"] == ADMIN_SECRET) { return next(); }
    """
    result = agent._audit_shared_secret_auth(code)
    assert any("timing" in f["issue"].lower() for f in result["findings"])


def test_shared_secret_getter_and_inequality_flagged():
    agent = AuthSecurityAgent()
    result = agent._audit_shared_secret_auth(
        'if (req.get("x-api-key") !== expectedKey) { return res.status(401).json({}); }'
    )
    assert any("timing" in f["issue"].lower() for f in result["findings"])


def test_shared_secret_assigned_variable_flagged():
    """Key material assigned to an innocuous variable name carries through
    to the comparison line — the assignment itself is the evidence."""
    agent = AuthSecurityAgent()
    code = """
    const key = req.headers["x-api-key"];
    if (key !== process.env.INTERNAL_API_KEY) { return res.status(401).json({}); }
    """
    result = agent._audit_shared_secret_auth(code)
    assert any("timing" in f["issue"].lower() for f in result["findings"])


def test_shared_secret_python_env_shapes_flagged():
    agent = AuthSecurityAgent()
    code = """
    provided = request.headers.get("x-api-key")
    if provided != os.environ["ADMIN_SECRET"]:
        abort(401)
    """
    result = agent._audit_shared_secret_auth(code)
    assert any("timing" in f["issue"].lower() for f in result["findings"])


def test_shared_secret_python_getenv_default_fallback_flagged():
    """The JS `|| "fallback"` form was caught; the equivalent Python
    os.getenv("ADMIN_SECRET", "changeme") was not."""
    agent = AuthSecurityAgent()
    for line in (
        'KEY = os.getenv("ADMIN_SECRET", "changeme-in-prod")',
        'KEY = os.environ.get("APP_SECRET", "dev-secret")',
    ):
        result = agent._audit_shared_secret_auth(line)
        assert any(
            "hardcoded fallback" in f["issue"].lower() for f in result["findings"]
        ), line


def test_shared_secret_safe_code_stays_silent():
    """compare_digest is the fix, a status comparison that merely mentions
    the header elsewhere is not a secret compare, and a content-type check
    over a header accessor must not read as key material."""
    agent = AuthSecurityAgent()
    assert agent._audit_shared_secret_auth("""
    provided = request.headers.get("x-api-key")
    if not hmac.compare_digest(provided, expected):
        abort(401)
    """)["findings"] == []
    assert agent._audit_shared_secret_auth("""
    // the x-api-key header is required
    if (res.status == 401) { log("missing x-api-key"); }
    """)["findings"] == []
    assert (
        agent._audit_shared_secret_auth(
            'if (req.headers["content-type"] == "application/json") { parse(); }'
        )["findings"]
        == []
    )
