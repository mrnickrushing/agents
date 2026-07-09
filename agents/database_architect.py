"""
Database Architect Agent — schema, index, migration-safety, and N+1 review.

Covers Drizzle ORM (Postgres/SQLite) and Alembic (SQLAlchemy) migrations —
the two migration systems in use across this stack. Complements
CodeReviewAgent.review_drizzle_schema (which checks a schema definition in
isolation) with migration-safety and cross-query N+1 detection.

Usage:
    from agents import DatabaseArchitectAgent
    agent = DatabaseArchitectAgent(api_key="sk-...")
    result = agent.run("Is this migration safe to run against a populated table?")
    print(result.content)
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class DatabaseArchitectAgent(BaseAgent):
    """
    Schema and migration safety specialist for Drizzle + Alembic.

    Reviews index coverage, migration safety against populated tables, N+1
    query patterns, and missing constraints.
    """

    name = "database_architect"
    description = "Reviews database schema index coverage, migration safety, N+1 query patterns, and missing constraints for Drizzle and Alembic."
    model = "gpt-5"

    system_prompt = """\
You are a database schema and migration safety specialist for solo full-stack operators using Drizzle ORM (Postgres/SQLite) and Alembic (SQLAlchemy/FastAPI).

YOUR DOMAIN:

1. INDEX COVERAGE
   - Foreign key columns (user_id, *_id references) should be indexed — without an index, every join or WHERE on that column is a full table scan
   - Columns used in ORDER BY / WHERE on large tables need an index

2. MIGRATION SAFETY (against a table with existing rows, not just a fresh dev DB)
   - Adding a NOT NULL column needs a server-side default (or a backfill step) — otherwise the migration fails outright against existing rows
   - Raw ALTER TABLE ... ADD COLUMN should be idempotent (IF NOT EXISTS) if it can run more than once (e.g. on every deploy, as this stack's Express backend does)
   - DROP COLUMN / DROP TABLE is destructive and hard to reverse — confirm it's intentional and the downgrade path (if any) is correct
   - Changing a column's type against a populated table can fail or truncate data — needs an explicit USING cast (Postgres) or a multi-step migration

3. N+1 QUERIES
   - A query inside a loop (map/forEach/for) is almost always fixable with a single batched query (WHERE id IN (...) or a join)

4. CONSTRAINTS
   - Foreign key columns should have an actual FK constraint (not just a same-named column) so referential integrity is enforced at the DB level
   - Columns like email that must be unique should have a unique constraint, not just be checked in application code (a race condition can still create duplicates)

When reviewing, always cite the exact column/migration/loop and give the exact fix — a migration or index statement, not just a description.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_index_coverage",
                "description": "Review a schema definition for missing indexes on foreign-key-like columns.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "schema_code": {"type": "string", "description": "The schema definition code (Drizzle or SQLAlchemy model)"},
                        "database": {"type": "string", "enum": ["postgresql", "sqlite"]},
                    },
                    "required": ["schema_code"],
                },
            },
            {
                "name": "review_migration_safety",
                "description": "Review a migration (Alembic upgrade/downgrade or raw ALTER TABLE) for safety against a populated table.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "migration_code": {"type": "string", "description": "The migration code to review"},
                    },
                    "required": ["migration_code"],
                },
            },
            {
                "name": "review_n_plus_one",
                "description": "Detect N+1 query patterns — a database query inside a loop.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The code to review for N+1 patterns"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_constraints",
                "description": "Review a schema for missing foreign-key and unique constraints.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "schema_code": {"type": "string", "description": "The schema definition code"},
                    },
                    "required": ["schema_code"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_index_coverage": self._review_index_coverage,
            "review_migration_safety": self._review_migration_safety,
            "review_n_plus_one": self._review_n_plus_one,
            "review_constraints": self._review_constraints,
        }

    def _review_index_coverage(self, schema_code: str, database: str = "postgresql") -> Dict[str, Any]:
        """Review index coverage on foreign-key-like columns."""
        findings = []

        # Drizzle: fooId: uuid('foo_id').references(() => foo.id) — flag if
        # no .index() call anywhere mentions the same column name.
        fk_cols = re.findall(r"(\w+):\s*\w+\([\"']([\w_]+)[\"']\)[^,]*\.references\(", schema_code)
        for field_name, column_name in fk_cols:
            if not re.search(rf"\.index\([^)]*\)|index\([^)]*\)\.on\([^)]*{re.escape(field_name)}", schema_code):
                findings.append({"severity": "MEDIUM", "column": column_name, "issue": f"Foreign key column '{column_name}' has no visible index — joins/filters on it will full-scan as the table grows", "fix": f"Add an index: {field_name}Idx: index('{column_name}_idx').on(table.{field_name})"})

        # SQLAlchemy: ForeignKey without index=True. Column(...) commonly
        # nests 2+ paren pairs (Integer(), ForeignKey('x.id'), ...) — a plain
        # [^)]* stops at the first nested close-paren, so match balanced
        # parens up to two levels deep instead of assuming a fixed shape.
        # SQLAlchemy 2.0's `name: Mapped[Type] = mapped_column(...)` style
        # (what this stack actually uses) puts a type annotation between the
        # name and "=" — a bare `\w+\s*=` never matches it.
        balanced_parens = r"\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)"
        for m in re.finditer(rf"(\w+)\s*(?::[^=\n]+)?=\s*(?:mapped_column|Column){balanced_parens}", schema_code):
            col_def = m.group(0)
            if "ForeignKey" not in col_def:
                continue
            # unique=True also creates an implicit index in SQLAlchemy, so it
            # satisfies the same concern as index=True.
            if not re.search(r"index\s*=\s*True|unique\s*=\s*True", col_def):
                findings.append({"severity": "MEDIUM", "column": m.group(1), "issue": f"Foreign key column '{m.group(1)}' has no index=True — joins/filters on it will full-scan as the table grows", "fix": f"Add index=True to the Column/mapped_column definition, or create a separate Index()"})

        return {"database": database, "findings": findings, "total_issues": len(findings)}

    def _review_migration_safety(self, migration_code: str) -> Dict[str, Any]:
        """Review a migration for safety against a populated table."""
        findings = []

        # Alembic add_column(...) commonly nests a Column(...) call inside
        # it — match balanced parens up to two levels deep, or a plain
        # [^)]* stops at Column(...)'s own close-paren and misses the
        # nullable=False that comes after it.
        balanced_parens = r"\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)"
        for m in re.finditer(rf"op\.add_column{balanced_parens}", migration_code, re.DOTALL):
            block = m.group(0)
            if re.search(r"nullable\s*=\s*False", block) and "server_default" not in block and "default" not in block:
                findings.append({"severity": "CRITICAL", "issue": "add_column with nullable=False and no server_default — this migration will fail outright against a table with existing rows (they'd violate the NOT NULL constraint)", "fix": "Add server_default=... to backfill existing rows, or do it in two migrations: add nullable, backfill, then set NOT NULL"})

        # Raw ALTER TABLE ADD COLUMN without IF NOT EXISTS
        for m in re.finditer(r"ALTER TABLE\s+\w+\s+ADD COLUMN(?!\s+IF NOT EXISTS)\s+\w", migration_code, re.IGNORECASE):
            findings.append({"severity": "MEDIUM", "issue": "ALTER TABLE ADD COLUMN without IF NOT EXISTS — fails if this migration path ever runs twice against the same DB (e.g. on every deploy, or a retried migration step)", "fix": "Use ALTER TABLE ... ADD COLUMN IF NOT EXISTS for idempotent migrations"})
            break

        # A drop_column in downgrade() is the expected, idiomatic mirror of
        # upgrade()'s add_column — flagging every migration's downgrade()
        # would be constant noise. Only flag a drop that's in upgrade() (or
        # not inside any named migration function at all, e.g. raw SQL),
        # since that's an intentional forward-migration data loss.
        downgrade_match = re.search(r"def\s+downgrade\s*\([^)]*\)[^:]*:(.*?)(?=\ndef\s|\Z)", migration_code, re.DOTALL)
        downgrade_body = downgrade_match.group(1) if downgrade_match else ""
        outside_downgrade = migration_code.replace(downgrade_body, "") if downgrade_match else migration_code
        if re.search(r"op\.drop_column\(|DROP COLUMN\b", outside_downgrade, re.IGNORECASE):
            findings.append({"severity": "HIGH", "issue": "DROP COLUMN found outside downgrade() — destructive and effectively irreversible once deployed", "fix": "Confirm this is intentional; consider a backup/export step first, or a soft deprecation period before dropping"})

        if re.search(r"ALTER TABLE\s+\w+\s+ALTER COLUMN\s+\w+\s+TYPE\b(?!.*USING)", migration_code, re.IGNORECASE):
            findings.append({"severity": "HIGH", "issue": "Column type change with no explicit USING clause — Postgres may fail or silently truncate/reinterpret data depending on the type pair", "fix": "Add an explicit USING <expression> clause for the cast, and test against a copy of production data first"})

        return {"findings": findings, "total_issues": len(findings)}

    def _review_n_plus_one(self, code: str) -> Dict[str, Any]:
        """Detect N+1 query patterns — a query inside a loop."""
        findings = []
        loop_re = re.compile(r"\.(map|forEach)\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{(.*?)\n\s*\}\s*\)", re.DOTALL)
        query_re = re.compile(r"await\s+\w[\w.]*\.(query|findOne|findFirst|find|get)\(|db\.query\(|session\.query\(|session\.get\(")

        for m in loop_re.finditer(code):
            body = m.group(2)
            if query_re.search(body):
                findings.append({"severity": "HIGH", "issue": "Database query found inside a .map()/.forEach() loop — N+1 pattern, one round trip per item instead of one batched query", "fix": "Batch with a single query: WHERE id IN (...ids) or a join, then map results in memory"})
                break

        for_loop_re = re.compile(r"for\s*\([^)]*\)\s*\{(.*?)\n\s*\}", re.DOTALL)
        for m in for_loop_re.finditer(code):
            body = m.group(1)
            if query_re.search(body):
                findings.append({"severity": "HIGH", "issue": "Database query found inside a for loop — N+1 pattern, one round trip per iteration instead of one batched query", "fix": "Batch with a single query: WHERE id IN (...ids) or a join, then map results in memory"})
                break

        return {"findings": findings, "total_issues": len(findings)}

    def _review_constraints(self, schema_code: str) -> Dict[str, Any]:
        """Review for missing unique/FK constraints."""
        findings = []

        # Only the exact field name "email" — not "email_enabled" (a bool
        # flag), "sender_email"/"reply_to_email" (legitimately per-row,
        # non-unique fields on notification/message records). A plain
        # \bemail\b still matches inside those, since \b treats "_" as a
        # word character; use lookaround for a true standalone identifier.
        # Each occurrence is checked independently (not deduped across the
        # file) since different tables can each have their own "email"
        # column with different constraints.
        field_re = r"(?<![A-Za-z0-9_])email(?![A-Za-z0-9_])"
        patterns = [
            rf"{field_re}\s*:\s*\w+\([\"'][\w_]+[\"']\)",
            rf"{field_re}\s*:\s*Mapped\[[^\]]+\]\s*=\s*(?:mapped_column|Column)\(",
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, schema_code, re.IGNORECASE):
                nearby = schema_code[m.start():m.start() + 200]
                if not re.search(r"\.unique\(\)|unique\s*=\s*True", nearby):
                    findings.append({"severity": "MEDIUM", "column": "email", "issue": "'email' column has no visible unique constraint — application-level uniqueness checks can still race under concurrent inserts", "fix": "Add .unique() to the column definition (Drizzle) or unique=True (SQLAlchemy) so the DB enforces it"})

        return {"findings": findings, "total_issues": len(findings)}
