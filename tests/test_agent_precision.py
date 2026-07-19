import json

from agents.api_architect import APIArchitectAgent
from agents.auth_security import AuthSecurityAgent
from agents.mobile_deploy import MobileDeployAgent
from agents.railway_deploy import RailwayDeployAgent
from agents.scaffolder import ScaffolderAgent
from agents.stripe_billing import StripeBillingAgent
from agents.ui_generation import UIGenerationAgent


def _issues(result):
    return [finding["issue"] for finding in result.get("findings", [])]


def test_shared_secret_comparison_is_found_across_assignment_lines():
    code = """
const providedKey = req.get('x-api-key');
const expectedSecret = process.env.ADMIN_SECRET;
if (providedKey === expectedSecret) next();
"""
    issues = _issues(AuthSecurityAgent()._audit_shared_secret_auth(code))
    assert any("timing attack" in issue for issue in issues)


def test_naming_x_api_key_in_cors_headers_is_not_a_timing_finding():
    code = "cors({ allowedHeaders: ['content-type', 'x-api-key'] });"
    issues = _issues(AuthSecurityAgent()._audit_shared_secret_auth(code))
    assert not any("timing attack" in issue for issue in issues)


def test_customer_and_update_words_in_unrelated_places_do_not_imply_auth_bypass():
    code = "// Update the UI after customer info loads\nfunction renderCustomer(customer) { return customer.name; }"
    assert StripeBillingAgent()._audit_billing_security(code)["findings"] == []


def test_real_stripe_customer_update_without_auth_is_detected():
    code = "await stripe.customers.update(customerId, { email: req.body.email });"
    issues = _issues(StripeBillingAgent()._audit_billing_security(code))
    assert any("without auth" in issue for issue in issues)


def test_push_notification_receipt_type_is_not_a_billing_validation_finding():
    code = """
type PushReceipt = { status: 'ok' | 'error' };
async function fetchPushReceipts(receiptIds: string[]): Promise<PushReceipt[]> {
  return request('/push/receipts', { receiptIds });
}
"""
    assert StripeBillingAgent()._audit_billing_security(code)["findings"] == []


def test_request_body_purchase_receipt_without_validation_is_detected():
    code = "const receipt = req.body.receiptData; await savePurchase(receipt);"
    issues = _issues(StripeBillingAgent()._audit_billing_security(code))
    assert any("server-side validation" in issue for issue in issues)


def test_provider_response_receipt_is_not_mistaken_for_client_input():
    code = """
payload = response.json()
receipts = payload.get('data', {})
receipt = receipts.get(ticket_id)
"""
    assert StripeBillingAgent()._audit_billing_security(code)["findings"] == []


def test_client_supplied_checkout_amount_is_detected():
    code = "await stripe.paymentIntents.create({ amount: req.body.amount, currency: 'usd' });"
    issues = _issues(StripeBillingAgent()._audit_billing_security(code))
    assert any("client input" in issue for issue in issues)


def test_public_expo_sdk_key_is_not_treated_as_a_committed_secret():
    config = {
        "build": {
            "production": {
                "autoIncrement": True,
                "env": {"EXPO_PUBLIC_REVENUECAT_IOS_API_KEY": "appl_public_sdk_key"},
            }
        },
        "submit": {"production": {}},
    }
    issues = _issues(MobileDeployAgent()._review_eas_config(json.dumps(config)))
    assert not any("literal value" in issue for issue in issues)


def test_private_eas_token_literal_is_detected():
    config = {
        "build": {
            "production": {
                "autoIncrement": True,
                "env": {"SENTRY_AUTH_TOKEN": "literal-sensitive-token"},
            }
        },
        "submit": {"production": {}},
    }
    issues = _issues(MobileDeployAgent()._review_eas_config(json.dumps(config)))
    assert any("literal value" in issue for issue in issues)


def test_docker_review_catches_reproducibility_and_root_runtime():
    dockerfile = "FROM node:latest\nRUN npm install\nCMD [\"node\", \"server.js\"]\n"
    issues = _issues(RailwayDeployAgent()._review_deployment_config(dockerfile, "Dockerfile"))
    assert any(":latest" in issue for issue in issues)
    assert any("npm install" in issue for issue in issues)
    assert any("root user" in issue for issue in issues)


def test_railway_config_hardcoded_port_is_detected():
    config = '[deploy]\nstartCommand = "uvicorn app:app --port 8080"\nhealthcheckPath = "/ready"\nrestartPolicyType = "on_failure"\n'
    issues = _issues(RailwayDeployAgent()._review_deployment_config(config, "railway.toml"))
    assert any("hardcodes a port" in issue for issue in issues)


def test_fastapi_exception_detail_does_not_leak_raw_exception():
    code = "except Exception as exc:\n    raise HTTPException(status_code=500, detail=str(exc))"
    issues = _issues(APIArchitectAgent()._review_error_response_shape(code))
    assert any("caught exception" in issue for issue in issues)


def test_accessibility_validator_checks_each_form_control():
    code = '<label htmlFor="name">Name</label><input id="name" /><input placeholder="Email" />'
    result = UIGenerationAgent()._validate_accessibility(code, severity="minor")
    assert any("1 form control" in issue["issue"] for issue in result["issues"])
    assert result["wcag_21_aa_compliant"] is False


def test_visible_role_button_text_does_not_require_aria_label():
    code = '<div role="button" tabIndex={0} onKeyDown={onKey}>Save</div>'
    result = UIGenerationAgent()._validate_accessibility(code, severity="minor")
    assert not any("accessible name" in issue["issue"] for issue in result["issues"])


def test_scaffolder_no_longer_generates_auth_bypass_stub():
    files = ScaffolderAgent()._scaffold_express_api("demo", auth=True)["files"]
    assert "jwt.verify" in files["src/middleware/auth.ts"]
    assert "algorithms: ['HS256']" in files["src/middleware/auth.ts"]
    assert "=> next()" not in files["src/middleware/auth.ts"]
    assert "helmet()" in files["src/app.ts"]
