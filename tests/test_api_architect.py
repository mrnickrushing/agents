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


def test_pagination_res_locals_user_id_scoped_downgraded():
    agent = APIArchitectAgent()
    code = """
    router.get('/api/referrals/me', requireUser, async (_req, res) => {
      const userId = res.locals.userId as number;
      res.json(await getReferralStatus(db, userId));
    });
    """
    result = agent._review_pagination(code)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" not in severities


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
