from agents.code_review import CodeReviewAgent


def test_drizzle_schema_skips_files_without_a_table_definition():
    """The scan trigger for this tool matches any file importing from
    drizzle-orm (query helpers like eq/and, the drizzle() client itself),
    not just files that define a table — a route or service file that
    merely queries the DB isn't "a schema with no primary key", it doesn't
    define a schema at all."""
    agent = CodeReviewAgent()
    code = """
    import { eq } from 'drizzle-orm';
    import { db } from '../db/client';
    import { users } from '../db/schema';

    export async function getUser(id: string) {
      return db.query.users.findFirst({ where: eq(users.id, id) });
    }
    """
    result = agent._review_drizzle_schema(code)
    assert result["findings"] == []


def test_drizzle_schema_still_flags_real_schema_missing_primary_key():
    agent = CodeReviewAgent()
    code = """
    export const widgets = pgTable('widgets', {
      name: text('name').notNull(),
    });
    """
    result = agent._review_drizzle_schema(code)
    issues = [f["issue"] for f in result["findings"]]
    assert any("primary key" in i.lower() for i in issues)


def test_drizzle_schema_detects_table_definition_with_whitespace():
    """pgTable ('widgets', ...) with a space before the paren is still a
    real table definition — an exact "pgtable(" substring match would miss
    it and silently skip a schema file that does have a real problem."""
    agent = CodeReviewAgent()
    code = """
    export const widgets = pgTable ('widgets', {
      name: text('name').notNull(),
    });
    """
    result = agent._review_drizzle_schema(code)
    issues = [f["issue"] for f in result["findings"]]
    assert any("primary key" in i.lower() for i in issues)
