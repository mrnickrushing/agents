from agents.api_architect import APIArchitectAgent


def test_pagination_user_scoped_query_downgraded_not_high():
    """A query filtered to the requesting user's own id/session is bounded
    by that user's usage, not "the entire table" — a personal blocklist,
    contact list, or API key list shouldn't get the same severity as an
    unscoped multi-tenant dump."""
    agent = APIArchitectAgent()
    code = """
    @router.get("/blocks")
    def list_personal_blocks(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
        rows = (
            db.query(PersonalBlockedNumber)
            .filter(PersonalBlockedNumber.user_id == user.id)
            .order_by(PersonalBlockedNumber.created_at.desc())
            .all()
        )
        return [{"number": r.number} for r in rows]
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" not in severities


def test_pagination_res_locals_user_id_in_query_call_downgraded():
    """res.locals.userId used directly inside the query call is a verifiable
    scope — downgrade it."""
    agent = APIArchitectAgent()
    code = """
    router.get('/api/blocks', requireUser, async (_req, res) => {
      const rows = await db.select().from(blocks).where(eq(blocks.userId, res.locals.userId));
      res.json(rows);
    });
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" not in severities


def test_pagination_delegated_scoping_not_verifiable_stays_high():
    """A route that extracts res.locals.userId and hands it to a helper
    function (the actual filtering happens in a different file this check
    can't see) can't be safely assumed to be scoped — downgrading it would
    also downgrade a route that logs the user id but runs an unrelated
    unscoped query, which is unsafe. Stay conservative and leave it HIGH."""
    agent = APIArchitectAgent()
    code = """
    router.get('/api/referrals/me', requireUser, async (_req, res) => {
      const userId = res.locals.userId as number;
      res.json(await getReferralStatus(db, userId));
    });
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" in severities


def test_pagination_audit_log_reference_does_not_scope_unrelated_query():
    """A route that merely logs req.user.id for an audit trail while
    running a fully unscoped query elsewhere must not be downgraded just
    because the user's id appears somewhere in the function."""
    agent = APIArchitectAgent()
    code = """
    router.get('/api/admin/all-users', requireAdmin, async (req, res) => {
      console.log('requested by', req.user.id);
      const rows = await db.select().from(users);
      res.json(rows);
    });
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" in severities


def test_pagination_grouped_aggregate_still_flagged():
    """GROUP BY returns one row per group — still a growing list, not a
    single scalar response, even though it uses count()."""
    agent = APIArchitectAgent()
    code = """
    router.get('/api/stats/by-user', async (_req, res) => {
      const rows = await db.select({ userId: items.userId, n: count() }).from(items).groupBy(items.userId);
      res.json(rows);
    });
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" in severities


def test_pagination_math_max_not_mistaken_for_aggregate():
    """Math.max(0, offset) is pagination-adjacent arithmetic, not a SQL
    aggregate — must not suppress the finding on an otherwise-unscoped list."""
    agent = APIArchitectAgent()
    code = """
    router.get('/api/admin/all-items', requireAdmin, async (req, res) => {
      const skip = Math.max(0, Number(req.query.skip));
      const rows = await db.select().from(items);
      res.json(rows);
    });
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" in severities


def test_pagination_object_shorthand_row_select_recognized():
    """res.json({ rows }) (object-shorthand) is still a row list even though
    the same handler also does a count() — must not be waved through as
    "aggregate-only" just because has_row_select's regex only recognized
    res.json(rows) without the braces."""
    agent = APIArchitectAgent()
    code = """
    router.get('/api/admin/items-with-count', requireAdmin, async (_req, res) => {
      const [{ n }] = await db.select({ n: count() }).from(items);
      const rows = await db.select().from(items);
      res.json({ rows });
    });
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" in severities


def test_pagination_aggregate_only_endpoint_not_flagged():
    """An endpoint returning count()/sum() scalars isn't a row list —
    pagination doesn't apply to "how many rows matched"."""
    agent = APIArchitectAgent()
    code = """
    router.get('/api/content/launch-stats', async (_req, res) => {
      const [linkedUsers] = await db.select({ n: sql`count(distinct ${items.userId})` }).from(items);
      res.json(view);
    });
    """
    result = agent._review_pagination(code)
    assert result["findings"] == []


def test_pagination_unscoped_table_dump_still_flagged_high():
    agent = APIArchitectAgent()
    code = """
    router.get('/api/admin/all-users', requireAdmin, async (_req, res) => {
      const rows = await db.select().from(users);
      res.json(rows);
    });
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" in severities
