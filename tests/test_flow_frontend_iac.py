"""Direct unit tests for the three v2.13 scan-surface agents that were only
exercised indirectly through `cli scan` routing: flow_audit,
frontend_performance, iac_security."""

from agents.flow_audit import FlowAuditAgent
from agents.frontend_performance import FrontendPerformanceAgent
from agents.iac_security import IACSecurityAgent


def _issues(result):
    return [f["issue"] for f in result["findings"]]


# ── FlowAuditAgent ────────────────────────────────────────────────────────


def test_flow_oauth_without_state_is_high():
    code = "router.get('/oauth/callback', async (req, res) => { await exchange(req.query.code) })"
    result = FlowAuditAgent()._audit_flow_logic(code)
    issues = _issues(result)
    assert "OAuth flow has no visible state parameter validation" in issues
    assert result["total_issues"] == len(result["findings"])


def test_flow_oauth_state_without_expiry_is_low_only():
    code = (
        "const state = crypto.randomUUID(); store.set(state, true);\n"
        "router.get('/oauth/callback', (req, res) => { if (!store.has(req.query.state)) throw 1 })"
    )
    issues = _issues(FlowAuditAgent()._audit_flow_logic(code))
    assert "OAuth flow has no visible state parameter validation" not in issues
    assert "OAuth state exists but no visible timeout/expiry handling" in issues


def test_flow_webhook_without_idempotency_is_high_and_idempotent_one_is_clean():
    hot = "app.post('/webhook', (req, res) => { handlePayment(req.body) })"
    assert "Payment/subscription flow has no visible idempotency guard" in _issues(
        FlowAuditAgent()._audit_flow_logic(hot)
    )
    safe = (
        "app.post('/webhook', (req, res) => { if (seen.has(event.id)) return; "
        "handlePayment(req.body) })"
    )
    assert "Payment/subscription flow has no visible idempotency guard" not in _issues(
        FlowAuditAgent()._audit_flow_logic(safe)
    )


def test_flow_retry_without_backoff_and_upload_without_cleanup():
    code = (
        "const upload = multer({ dest: 'tmp/' });\n"
        "app.post('/avatar', upload.single('file'), (req, res) => {\n"
        "  for (let attempt = 0; attempt < 5; attempt++) store(req.file);\n"
        "});\n"
    )
    issues = _issues(FlowAuditAgent()._audit_flow_logic(code))
    assert "Retry logic has no visible exponential backoff" in issues
    assert "Upload workflow has no visible cleanup on failure" in issues
    assert "Upload flow has no visible malware scanning step" in issues


def test_flow_does_not_mistake_react_and_expo_idioms_for_server_flows():
    """Regression from a real scan: an Expo screen was flagged for OAuth
    state, server uploads, concurrent writes and unhandled async — none of
    which it contains."""
    code = (
        'import { useCallback, useState } from "react";\n'
        'import { File } from "expo-file-system";\n'
        "export default function Screen() {\n"
        "  const [state, setState] = useState(null);\n"
        "  const load = useCallback(async () => {\n"
        "    try {\n"
        "      const [lib, saved] = await Promise.all([getLibrary(), getSaved()]);\n"
        "      const data = await new File(saved.uri).base64();\n"
        "      setState({ lib, data });\n"
        "    } catch (e) { report(e); }\n"
        "  }, []);\n"
        "  return null;\n"
        "}\n"
    )
    assert FlowAuditAgent()._audit_flow_logic(code)["findings"] == []


def test_flow_still_flags_real_oauth_and_parallel_writes():
    oauth = "const url = `${AUTH}/authorize?client_id=${id}&redirect_uri=${cb}`;"
    assert "OAuth flow has no visible state parameter validation" in _issues(
        FlowAuditAgent()._audit_flow_logic(oauth)
    )
    writes = "await Promise.all(items.map(i => db.items.update(i.id, { seen: true })));"
    assert "Concurrent state updates with no visible lock/transaction guard" in _issues(
        FlowAuditAgent()._audit_flow_logic(writes)
    )
    unhandled = "async function go() { await fetch(url); }"
    assert "Async flow may create unhandled rejection/exception paths" in _issues(
        FlowAuditAgent()._audit_flow_logic(unhandled)
    )


def test_flow_clean_code_has_no_findings():
    code = "def add(a, b):\n    return a + b\n"
    assert FlowAuditAgent()._audit_flow_logic(code)["findings"] == []


# ── FrontendPerformanceAgent ──────────────────────────────────────────────


def test_frontend_lodash_and_keyless_list():
    code = (
        "import _ from 'lodash';\n"
        "export const List = ({ items }) => <ul>{items.map((i) => <li>{i}</li>)}</ul>;\n"
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert "Whole lodash import may increase bundle size" in issues
    assert "JSX list rendering has no key prop" in issues


def test_frontend_keyed_list_is_not_flagged():
    code = "export const List = ({ items }) => <ul>{items.map((i) => <li key={i.id}>{i}</li>)}</ul>;"
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert "JSX list rendering has no key prop" not in issues


def test_frontend_image_hints():
    bare = '<img src="/hero.png" />'
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(bare))
    assert "Image tag missing loading='lazy'" in issues
    assert "Image may be unoptimized (missing srcSet/width/height hints)" in issues

    good = '<img src="/hero.png" width=800 height=600 loading="lazy" />'
    assert (
        FrontendPerformanceAgent()._audit_frontend_performance(good)["findings"] == []
    )


def test_frontend_icon_button_needs_aria_label():
    code = "<button onClick={close}><svg /></button>"
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert "Icon-only button missing aria-label" in issues
    labelled = '<button aria-label="Close" onClick={close}><svg /></button>'
    assert "Icon-only button missing aria-label" not in _issues(
        FrontendPerformanceAgent()._audit_frontend_performance(labelled)
    )


def test_frontend_layout_thrashing_and_modal_focus():
    code = (
        "requestAnimationFrame(() => { el.style.top = el.getBoundingClientRect().top + 'px' });\n"
        "function Modal() { return <div>modal</div> }"
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert "Animation loop reads layout metrics (possible layout thrashing)" in issues
    assert "Modal/dialog lacks visible focus management" in issues


# ── IACSecurityAgent ──────────────────────────────────────────────────────


def test_iac_terraform_credentials_open_ingress_public_bucket():
    tf = (
        'provider "aws" {\n  access_key = "AKIA123"\n  secret_key = "abc"\n}\n'
        'resource "aws_security_group" "sg" {\n  ingress { cidr_blocks = ["0.0.0.0/0"] }\n}\n'
        'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
    )
    result = IACSecurityAgent()._audit_iac_security(tf, path="infra/main.tf")
    issues = _issues(result)
    assert "Terraform file contains hardcoded cloud credentials" in issues
    assert "Terraform security group appears open to 0.0.0.0/0" in issues
    assert "S3 bucket configured as public-read" in issues
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_iac_terraform_rules_only_apply_to_tf_files():
    tf = 'access_key = "AKIA123"'
    assert IACSecurityAgent()._audit_iac_security(tf, path="notes.md")["findings"] == []


def test_iac_kubernetes_deployment_hardening():
    manifest = (
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
        "      containers:\n        - name: app\n          image: app:1\n"
    )
    issues = _issues(
        IACSecurityAgent()._audit_iac_security(manifest, path="k8s/app.yaml")
    )
    assert "Kubernetes workload missing securityContext" in issues
    assert "Kubernetes deployment has no resource limits/requests" in issues

    hardened = (
        manifest
        + "          securityContext:\n            runAsNonRoot: true\n          resources:\n            limits: {cpu: 1}\n"
    )
    assert (
        IACSecurityAgent()._audit_iac_security(hardened, path="k8s/app.yaml")[
            "findings"
        ]
        == []
    )


def test_iac_kubernetes_cluster_admin_binding():
    rb = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "roleRef:\n  name: cluster-admin\n"
    )
    issues = _issues(IACSecurityAgent()._audit_iac_security(rb, path="rbac.yml"))
    assert "Kubernetes RBAC appears overly permissive" in issues


def test_iac_dockerfile_unpinned_image_and_baked_secret():
    dockerfile = "FROM python\nENV API_TOKEN=abc123\nRUN pip install .\n"
    issues = _issues(
        IACSecurityAgent()._audit_iac_security(dockerfile, path="Dockerfile")
    )
    assert "Container base image is unpinned/latest" in issues
    assert "Potential secret baked into container config" in issues

    pinned = "FROM python:3.11-slim\nRUN pip install .\n"
    assert (
        IACSecurityAgent()._audit_iac_security(pinned, path="Dockerfile")["findings"]
        == []
    )


def test_email_html_images_are_not_asked_for_loading_lazy():
    """Regression: email clients ignore loading/srcSet, so telling an email
    template to add them is dead markup. sugarhaus builds its order emails
    inline in server.js and the finding returned with a fresh id on every
    commit that touched the file (2026-08-28)."""
    code = (
        "const { Resend } = require('resend');\n"
        'const EMAIL_HEADER_HTML = `<img src="${URL}" alt="Bakery" width="600" />`;\n'
        "await resend.emails.send({ html: EMAIL_HEADER_HTML });\n"
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert not any("loading='lazy'" in issue for issue in issues)
    assert not any("unoptimized" in issue for issue in issues)


def test_ordinary_page_images_are_still_asked_for_loading_lazy():
    code = '<section><img src="/hero.png" /><p>Welcome</p></section>'
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("loading='lazy'" in issue for issue in issues)


def test_a_form_labelled_email_is_not_mistaken_for_an_email_template():
    """The marker must key on sending/building email, not the word 'email' —
    a sign-up form with an email field is an ordinary page."""
    code = (
        '<form><label htmlFor="email">Email</label>'
        '<input id="email" type="email" /><img src="/logo.png" /></form>'
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("loading='lazy'" in issue for issue in issues)


def test_table_based_email_markup_is_recognised_without_an_sdk_import():
    code = (
        '<table cellpadding="0" cellspacing="0" role="presentation">'
        '<tr><td><img src="https://cdn/x.png" width="600" /></td></tr></table>'
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert not any("loading='lazy'" in issue for issue in issues)


def test_explicitly_eager_image_is_not_asked_to_lazy_load():
    """loading="eager" / fetchPriority="high" mark an above-the-fold or LCP
    image, where lazy-loading makes load performance worse (aegisapparel
    splash and header art, 2026-08-28)."""
    code = '<img src="/hero.png" width="1376" height="768" loading="eager" fetchPriority="high" />'
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert not any("loading='lazy'" in issue for issue in issues)


def test_image_with_no_loading_hint_at_all_is_still_reported():
    code = '<section><img src="/thumb.png" width="100" height="100" /></section>'
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("loading='lazy'" in issue for issue in issues)


def test_eager_hero_does_not_vouch_for_a_bare_image_beside_it():
    """Regression: the exemption was file-wide, so one eager hero suppressed
    the check for every other image in the file (Codex, agents#63)."""
    code = (
        '<div><img src="/hero.png" loading="eager" width="1" height="1" />'
        '<img src="/other.png" /></div>'
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("loading='lazy'" in issue for issue in issues)


def test_one_image_with_dimensions_does_not_vouch_for_another_without():
    code = (
        '<img src="/a.png" width="1" height="1" loading="lazy" />'
        '<img src="/b.png" loading="lazy" />'
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("unoptimized" in issue for issue in issues)


def test_every_image_hinted_is_clean():
    code = (
        '<img src="/hero.png" loading="eager" fetchPriority="high" width="1" height="1" />'
        '<img src="/b.png" loading="lazy" width="2" height="2" />'
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert not any(
        "loading='lazy'" in issue or "unoptimized" in issue for issue in issues
    )


def test_image_filling_its_container_is_not_asked_for_dimensions():
    """An image positioned to fill its container takes its box from that
    container, so width/height would be inert markup reserving nothing
    (aegisapparel product and campaign grids, 2026-08-28)."""
    code = (
        '<div className="relative aspect-[4/5]">'
        '<img src={image} alt="" className="absolute inset-0 w-full h-full object-cover" '
        'loading="lazy" /></div>'
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert not any("unoptimized" in issue for issue in issues)


def test_fixed_size_image_without_dimensions_is_still_reported():
    code = '<img src="/badge.png" className="w-48" loading="lazy" />'
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("unoptimized" in issue for issue in issues)


def test_image_inside_a_template_literal_is_not_judged():
    """Markup a module generates into a string — an email body, an innerHTML
    fragment — isn't JSX this component renders, so browser loading hints
    don't apply (aegisapparel AdminDashboard.jsx, 2026-08-28)."""
    code = (
        'const tag = `<img src="${url}" alt="" style="max-width:100%" />`;\n'
        "setBody((prev) => prev + tag);\n"
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert not any("lazy" in issue or "unoptimized" in issue for issue in issues)


def test_real_jsx_image_beside_a_string_literal_one_is_still_reported():
    code = (
        'const tag = `<img src="${url}" />`;\n'
        'export default function C() { return (<img src="/a.png" className="w-10" />); }\n'
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("lazy" in issue for issue in issues)


def test_apostrophe_in_jsx_text_does_not_hide_a_later_image():
    """Regression: treating ' as a literal delimiter opened a span that ran to
    EOF, swallowing every image after ordinary prose (Codex, agents#64)."""
    code = '<div><p>Don\'t wait</p><img src="/hero.png" /></div>'
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("loading='lazy'" in issue for issue in issues)
    assert any("unoptimized" in issue for issue in issues)


def test_markup_injected_into_the_dom_is_still_checked():
    """innerHTML/insertAdjacentHTML markup is rendered by the browser, so the
    hints do apply to it (Codex, agents#64)."""
    code = 'el.innerHTML = `<img src="${u}" />`;'
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("loading='lazy'" in issue for issue in issues)


def test_full_size_image_without_a_reserved_parent_is_still_reported():
    """`w-full h-full` alone doesn't reserve anything — a percentage height
    resolves to auto unless the parent has a definite height, and the parent
    isn't visible from a single-file check (Codex, agents#64)."""
    code = '<div><img className="w-full h-full" src={url} /></div>'
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert any("unoptimized" in issue for issue in issues)


def test_absolutely_pinned_image_is_still_exempt():
    code = (
        '<div className="aspect-[4/5]">'
        '<img className="absolute inset-0 w-full h-full object-cover" '
        'src={i} loading="lazy" /></div>'
    )
    issues = _issues(FrontendPerformanceAgent()._audit_frontend_performance(code))
    assert not any("unoptimized" in issue for issue in issues)
