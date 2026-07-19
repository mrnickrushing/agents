from agents.infra_monitor import InfraMonitorAgent


def _issues(code):
    return [finding["issue"] for finding in InfraMonitorAgent()._review_sentry_setup(code)["findings"]]


def test_sentry_init_without_dsn_source_is_visible():
    issues = _issues("Sentry.init({ environment: env, tracesSampleRate: 0.1, sendDefaultPii: false });")
    assert any("no visible DSN" in issue for issue in issues)


def test_sentry_environment_dsn_is_recognized():
    issues = _issues("Sentry.init({ dsn: process.env.SENTRY_DSN, environment: env, tracesSampleRate: 0.1, sendDefaultPii: false });")
    assert not any("no visible DSN" in issue for issue in issues)
