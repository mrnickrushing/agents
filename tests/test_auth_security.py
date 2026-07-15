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
