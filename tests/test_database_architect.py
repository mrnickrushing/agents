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
    assert any(f["severity"] == "CRITICAL" and "drops a column" in f["issue"] for f in result["findings"])


def test_alembic_not_null_column_without_backfill_is_detected():
    migration = """
def upgrade():
    op.add_column('users', sa.Column('plan', sa.String(), nullable=False))
"""
    issues = _issues(DatabaseArchitectAgent()._review_migration_safety(migration))
    assert any("nullable=False" in issue for issue in issues)


def test_n_plus_one_detects_js_single_line_callback():
    code = "const rows = users.map(async (user) => { return await db.query(user.id); });"
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
