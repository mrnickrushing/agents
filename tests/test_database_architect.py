from agents.database_architect import DatabaseArchitectAgent


def _issues(result):
    return [finding["issue"] for finding in result["findings"]]


def test_drizzle_foreign_key_without_index_is_detected():
    code = """
export const posts = pgTable('posts', {
  id: uuid('id').primaryKey(),
  userId: uuid('user_id').notNull().references(() => users.id),
});
"""
    issues = _issues(DatabaseArchitectAgent()._review_index_coverage(code))
    assert any("user_id" in issue for issue in issues)


def test_drizzle_table_level_index_satisfies_foreign_key_check():
    code = """
export const posts = pgTable('posts', {
  id: uuid('id').primaryKey(),
  userId: uuid('user_id').references(() => users.id),
}, (table) => [index('posts_user_id_idx').on(table.userId)]);
"""
    assert DatabaseArchitectAgent()._review_index_coverage(code)["findings"] == []


def test_sqlalchemy_nested_foreign_key_call_is_fully_parsed():
    code = """
user_id: Mapped[int] = mapped_column(
    Integer,
    ForeignKey('users.id', ondelete=func.coalesce('RESTRICT', 'NO ACTION')),
    nullable=False,
)
"""
    issues = _issues(DatabaseArchitectAgent()._review_index_coverage(code))
    assert any("user_id" in issue for issue in issues)


def test_drop_column_in_alembic_downgrade_is_not_forward_data_loss():
    migration = """
def upgrade():
    op.add_column('users', sa.Column('nickname', sa.String(), nullable=True))

def downgrade():
    op.drop_column('users', 'nickname')
"""
    issues = _issues(DatabaseArchitectAgent()._review_migration_safety(migration))
    assert not any("drops a column" in issue for issue in issues)


def test_drop_column_in_upgrade_is_critical():
    migration = """
def upgrade():
    op.drop_column('users', 'legacy_data')

def downgrade():
    pass
"""
    result = DatabaseArchitectAgent()._review_migration_safety(migration)
    assert any(
        f["severity"] == "CRITICAL" and "drops a column" in f["issue"]
        for f in result["findings"]
    )


def test_alembic_not_null_column_without_backfill_is_detected():
    migration = """
def upgrade():
    op.add_column('users', sa.Column('plan', sa.String(), nullable=False))
"""
    issues = _issues(DatabaseArchitectAgent()._review_migration_safety(migration))
    assert any("nullable=False" in issue for issue in issues)


def test_n_plus_one_detects_js_single_line_callback():
    code = (
        "const rows = users.map(async (user) => { return await db.query(user.id); });"
    )
    issues = _issues(DatabaseArchitectAgent()._review_n_plus_one(code))
    assert any("N+1" in issue for issue in issues)


def test_n_plus_one_detects_python_indented_loop():
    code = """
for user in users:
    profile = session.execute(select(Profile).where(Profile.user_id == user.id))
    output.append(profile)
"""
    issues = _issues(DatabaseArchitectAgent()._review_n_plus_one(code))
    assert any("N+1" in issue for issue in issues)


def test_array_find_inside_map_is_not_called_a_database_query():
    code = "const rows = users.map((user) => { return cached.find((x) => x.id === user.id); });"
    assert DatabaseArchitectAgent()._review_n_plus_one(code)["findings"] == []


def test_external_ids_do_not_create_foreign_key_false_positives():
    code = """
id: uuid('id').primaryKey(),
event_id: text('event_id').notNull(),
request_id: text('request_id').notNull(),
sender_email: text('sender_email').notNull(),
"""
    assert DatabaseArchitectAgent()._review_constraints(code)["findings"] == []


def test_query_select_does_not_match_queryselector():
    """`card.querySelector(...)` inside a .forEach is DOM traversal, not a
    database call. Without a word boundary after `query`, every DOM-heavy
    script that reaches for an element inside a loop read as an N+1
    (backgrounds/workbench, 2026-08-28)."""
    agent = DatabaseArchitectAgent()
    dom = """
rows.forEach((card) => {
  const button = card.querySelector("[data-view-load]");
  const target = card.querySelectorAll(".cell");
  button.onclick = () => open(card.dataset.id);
});
"""
    assert agent._review_n_plus_one(dom)["findings"] == []


def test_a_real_query_in_a_loop_is_still_reported():
    agent = DatabaseArchitectAgent()
    for code in (
        'for (const id of ids) { const row = await db.query("SELECT 1", [id]); }',
        "users.map(async (u) => { return await prisma.user.findUnique({ where: { id: u.id } }); })",
        "for case_id in case_ids:\n    row = session.execute(select(Case))\n",
    ):
        assert agent._review_n_plus_one(code)["findings"], code


def test_the_orms_own_suffixed_spellings_still_report():
    """A boundary straight after the base name would have silenced every one
    of these — the suffix is part of the method, not the next token."""
    agent = DatabaseArchitectAgent()
    for code in (
        "for (const u of users) { await prisma.user.findUniqueOrThrow({ where: { id: u.id } }); }",
        "for (const u of users) { await prisma.user.findFirstOrThrow({ where: { id: u.id } }); }",
        "for (const u of users) { await User.findOneAndUpdate({ _id: u.id }, patch); }",
        "for (const u of users) { await User.findByIdAndDelete(u.id); }",
        "for (const u of users) { await db.selectDistinct().from(t); }",
        'for (const u of users) { await conn.executeMany("SELECT 1", [u.id]); }',
        "for (const u of users) { await db.queryRaw`SELECT 1`; }",
    ):
        assert agent._review_n_plus_one(code)["findings"], code


def test_other_dom_and_driver_lookalikes_stay_clean():
    agent = DatabaseArchitectAgent()
    for code in (
        'items.forEach((i) => { document.queryCommandState("bold"); });',
        'items.forEach((i) => { driver.executeScript("return 1"); });',
        'rows.forEach((card) => { card.querySelectorAll(".cell").forEach(paint); });',
    ):
        assert agent._review_n_plus_one(code)["findings"] == [], code
