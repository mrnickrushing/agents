from agents.security_audit import SecurityAuditAgent


def _issues(result):
    return [finding["issue"] for finding in result.get("findings", result.get("jwt_findings", []))]


def test_verify_only_jwt_middleware_is_not_told_to_set_expiration():
    code = "const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });"
    issues = _issues(SecurityAuditAgent()._check_jwt_implementation(code))
    assert not any("expiration" in issue for issue in issues)


def test_token_issuer_without_expiration_is_detected_without_demanding_local_verify():
    code = "const token = jwt.sign({ sub: user.id }, secret, { algorithm: 'HS256' });"
    issues = _issues(SecurityAuditAgent()._check_jwt_implementation(code))
    assert any("expiration" in issue for issue in issues)
    assert not any("verification not found" in issue.lower() for issue in issues)


def test_jwt_verify_requires_explicit_algorithm_allowlist():
    code = "const claims = jwt.verify(token, publicKey);"
    issues = _issues(SecurityAuditAgent()._check_jwt_implementation(code))
    assert any("algorithms allowlist" in issue for issue in issues)


def test_one_argument_jsonwebtoken_decode_is_detected():
    code = "const claims = jwt.decode(token); authorize(claims.sub);"
    issues = _issues(SecurityAuditAgent()._check_jwt_implementation(code))
    assert any("without signature verification" in issue for issue in issues)


def test_hardcoded_secret_finding_never_echoes_secret_value():
    secret = "super-secret-value-that-must-not-leak"
    result = SecurityAuditAgent()._audit_hardcoded_secrets(f'api_key = "{secret}"')
    assert result["findings"]
    assert secret not in repr(result)
    assert result["findings"][0]["line"] == 1


def test_placeholder_secret_is_not_reported():
    result = SecurityAuditAgent()._audit_hardcoded_secrets('api_key = "replace_me_with_your_key"')
    assert result["findings"] == []


def test_dependency_presence_is_a_note_not_a_vulnerability():
    manifest = '{"dependencies":{"cors":"1.0.0","jsonwebtoken":"1.0.0"}}'
    result = SecurityAuditAgent()._scan_dependencies(manifest)
    assert result["findings"] == []
    assert {note["package"] for note in result["review_notes"]} == {"cors", "jsonwebtoken"}


def test_sensitive_logging_without_redaction_is_reported_once():
    result = SecurityAuditAgent()._audit_logging_security("console.log('token', token);")
    issues = _issues(result)
    assert any("logging Password/Secret" in issue for issue in issues)
    assert any("redaction" in issue for issue in issues)


def test_ordinary_logging_does_not_require_a_global_pii_redactor():
    result = SecurityAuditAgent()._audit_logging_security("console.log('server started');")
    assert result["findings"] == []


def test_apns_provider_jwt_is_not_required_to_have_exp_claim():
    code = """
const apnsToken = jwt.sign({ iss: teamId, iat: now }, privateKey, {
  algorithm: 'ES256', keyid: keyId, noTimestamp: true,
});
const endpoint = 'https://api.push.apple.com/3/device';
"""
    issues = _issues(SecurityAuditAgent()._check_jwt_implementation(code))
    assert not any("expiration" in issue for issue in issues)


def test_public_revenuecat_sdk_key_is_not_a_hardcoded_secret():
    result = SecurityAuditAgent()._audit_hardcoded_secrets(
        'apiKey: "appl_a1b2c3d4e5f6g7h8i9j0"'
    )
    assert result["findings"] == []


def test_vue_raw_user_html_is_detected():
    issues = _issues(SecurityAuditAgent()._audit_xss_patterns('<div v-html="userContent"></div>'))
    assert any("Vue v-html" in issue for issue in issues)


def test_svelte_raw_user_html_is_detected():
    issues = _issues(SecurityAuditAgent()._audit_xss_patterns('{@html userContent}'))
    assert any("Svelte @html" in issue for issue in issues)


def test_angular_sanitizer_bypass_is_detected():
    issues = _issues(SecurityAuditAgent()._audit_xss_patterns('sanitizer.bypassSecurityTrustHtml(userHtml)'))
    assert any("Angular" in issue for issue in issues)
