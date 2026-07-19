from agents.code_review import CodeReviewAgent
from agents.cli import _run_scan


def _issues(result):
    return [finding["issue"] for finding in result["findings"]]


def test_unrelated_limit_call_does_not_hide_unbounded_find_many():
    code = """
const preview = labels.limit(3);
router.get('/users', async (_req, res) => {
  const users = await prisma.user.findMany({ where: { active: true } });
  res.json(users);
});
"""
    issues = _issues(CodeReviewAgent()._review_express_route(code, "/users"))
    assert any("specific select/findMany" in issue for issue in issues)


def test_take_on_same_find_many_query_is_bounded():
    code = """
router.get('/users', async (_req, res) => {
  try {
    const users = await prisma.user.findMany({ where: { active: true }, take: 50 });
    res.json(users);
  } catch (error) { next(error); }
});
"""
    issues = _issues(CodeReviewAgent()._review_express_route(code, "/users"))
    assert not any("Unbounded query" in issue for issue in issues)


def test_any_mentions_in_comments_are_not_findings():
    code = "// Avoid using `as any` here.\nexport function Card(){ return <div />; }"
    issues = _issues(CodeReviewAgent()._review_react_component(code, "Card"))
    assert not any("'any' type" in issue for issue in issues)


def test_real_any_type_is_still_detected():
    code = "export function parse(value: any) { return value as any; }"
    issues = _issues(CodeReviewAgent()._review_react_component(code, "parse"))
    assert any("'any' type" in issue for issue in issues)


def test_unrelated_cleanup_does_not_hide_timer_leak_in_another_effect():
    code = """
useEffect(() => { subscribe(); return () => unsubscribe(); }, []);
useEffect(() => { const timer = setInterval(refresh, 1000); }, []);
"""
    issues = _issues(CodeReviewAgent()._review_react_component(code, "Ticker"))
    assert any("Timer started" in issue for issue in issues)


def test_timer_cleanup_in_same_effect_is_recognized():
    code = """
useEffect(() => {
  const timer = setInterval(refresh, 1000);
  return () => clearInterval(timer);
}, []);
"""
    issues = _issues(CodeReviewAgent()._review_react_component(code, "Ticker"))
    assert not any("Timer started" in issue for issue in issues)


def test_network_abort_must_be_wired_and_cleaned_up_in_same_effect():
    code = """
useEffect(() => {
  const controller = new AbortController();
  fetch('/api/items', { signal: controller.signal });
  return () => controller.abort();
}, []);
"""
    issues = _issues(CodeReviewAgent()._review_react_component(code, "Items"))
    assert not any("Network request" in issue for issue in issues)


def test_small_local_state_count_is_not_architecture_advice():
    code = "\n".join(f"const [value{i}, setValue{i}] = useState(0);" for i in range(6))
    issues = _issues(CodeReviewAgent()._review_react_component(code, "Form"))
    assert not any("useState calls" in issue for issue in issues)


def test_project_express_async_errors_suppresses_per_route_try_catch_warning(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"express":"4.21.0","express-async-errors":"3.1.1"}}'
    )
    (tmp_path / "routes.ts").write_text(
        "router.get('/users', async (_req, res) => { res.json(await loadUsers()); });"
    )

    report = _run_scan(str(tmp_path), ["code_review"])
    issues = [
        finding["issue"]
        for entry in report["results"]
        for finding in entry["result"].get("findings", [])
    ]

    assert not any("try/catch" in issue for issue in issues)


def test_express5_in_one_workspace_does_not_suppress_express4_sibling(tmp_path):
    (tmp_path / "modern").mkdir()
    (tmp_path / "legacy").mkdir()
    (tmp_path / "modern/package.json").write_text('{"dependencies":{"express":"5.0.0"}}')
    (tmp_path / "legacy/package.json").write_text('{"dependencies":{"express":"4.21.0"}}')
    (tmp_path / "legacy/routes.ts").write_text(
        "router.get('/users', async (_req, res) => { res.json(await loadUsers()); });"
    )

    report = _run_scan(str(tmp_path), ["code_review"])
    issues = [
        finding["issue"]
        for entry in report["results"]
        if entry["file"] == "legacy/routes.ts"
        for finding in entry["result"].get("findings", [])
    ]

    assert any("try/catch" in issue for issue in issues)
