from agents.api_architect import APIArchitectAgent


def _issues(code):
    result = APIArchitectAgent()._review_pagination(code, endpoint="test")
    return [finding["issue"] for finding in result["findings"]]


def test_health_endpoint_does_not_require_pagination():
    code = "router.get('/healthz', (_req, res) => res.json({ status: 'ok' }));"
    assert _issues(code) == []


def test_get_by_id_endpoint_does_not_require_pagination():
    code = "router.get('/users/:id', async (req, res) => res.json(await store.getUser(req.params.id)));"
    assert _issues(code) == []


def test_collection_query_without_limit_is_detected():
    code = "router.get('/users', async (_req, res) => res.json({ users: await db.user.findMany() }));"
    assert any("No limit" in issue for issue in _issues(code))


def test_user_scoped_delegated_collection_is_defense_in_depth_not_entire_table():
    code = """
router.get('/credits/me', async (_req, res) => {
  const userId = res.locals.userId;
  res.json(await getCredits(db, userId));
});
// --- imported from credits.ts ---
async function getCredits(db, userId) {
  return db.select().from(credits).where(eq(credits.userId, userId));
}
"""
    issues = _issues(code)
    assert any("scoped to the requesting user" in issue for issue in issues)
    assert not any("entire table" in issue for issue in issues)
