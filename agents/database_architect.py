"""Database Architect Agent — schema review, migration safety, N+1 detection, constraints.

Reviews database schema index coverage, migration safety against populated tables,
N+1 query patterns, and missing constraints for Drizzle ORM and Alembic.

Usage:
    from agents import DatabaseArchitectAgent
    agent = DatabaseArchitectAgent(api_key="sk-...")
    result = agent.run("Is this migration safe to run against a populated table?")
    print(result.content)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent

logger = logging.getLogger(__name__)


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
                "description": "Review a schema definition for missing indexes on foreign-key-like columns and other index opportunities.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "schema_code": {"type": "string", "description": "The schema definition code (Drizzle or SQLAlchemy model)"},
                        "database": {"type": "string", "enum": ["postgresql", "sqlite"], "description": "Database type"},
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
                        "migration_code": {"type": "string", "description": "The migration code"},
                    },
                    "required": ["migration_code"],
                },
            },
            {
                "name": "review_n_plus_one",
                "description": "Detect N+1 query patterns (queries inside loops that should be batched).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The code to scan for N+1 patterns"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_constraints",
                "description": "Review a schema for missing foreign key and unique constraints.",
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
        """Review index coverage on foreign-key-like columns and other hot paths."""
        findings = []

        # FIX BUG #4: Drizzle detection now finds chained .index().on(...) patterns
        # Pattern: userId: uuid().references(...) or user_id: integer().references(...)
        fk_cols = re.findall(r"(\w+):\s*\w+\(["']([\w_]+)["']\)[^,]*\.references\(", schema_code)
        for field_name, column_name in fk_cols:
            # Check for index in multiple forms:
            # 1. .index() chained to field definition
            # 2. table.fields.fieldName.index()
            # 3. index().on(table.fieldName)
            if not re.search(
                rf"(?:{re.escape(field_name)}\s*[,\)]\.index\(|index\([^)]*\)\.on\([^)]*{re.escape(field_name)}|{re.escape(column_name)}_idx)",
                schema_code
            ):
                findings.append({
                    "severity": "MEDIUM",
                    "column": column_name,
                    "issue": f"Foreign key column '{column_name}' has no visible index — joins/filters on it will full-scan as the table grows",
                    "fix": f"Add: .index() to the column definition, or index('{column_name}_idx').on(table.{field_name})"
                })
                if self.verbose:
                    logger.debug(f"[database_architect] Missing FK index: {field_name}")

        # FIX BUG #4: SQLAlchemy 2.0 Mapped[] style support with better balanced paren matching
        # Now handles 3+ levels of nesting (was 2), fixing Column(Integer, ForeignKey(..., ondelete=func.restrict()))
        balanced_parens = r"\((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*\)"
        for m in re.finditer(rf"(\w+)\s*(?::[^=\n]+)?=\s*(?:mapped_column|Column){balanced_parens}", schema_code):
            col_def = m.group(0)
            if "ForeignKey" not in col_def:
                continue
            # unique=True also creates an implicit index in SQLAlchemy
            if not re.search(r"index\s*=\s*True|unique\s*=\s*True", col_def):
                findings.append({
                    "severity": "MEDIUM",
                    "column": m.group(1),
                    "issue": f"Foreign key column '{m.group(1)}' has no index=True — joins/filters will full-scan",
                    "fix": f"Add index=True to the Column/mapped_column, or create a separate Index()"
                })
                if self.verbose:
                    logger.debug(f"[database_architect] SQLAlchemy FK without index: {m.group(1)}")

        return {"database": database, "findings": findings, "total_issues": len(findings)}

    def _review_migration_safety(self, migration_code: str) -> Dict[str, Any]:
        """Review a migration for safety against a populated table."""
        findings = []

        # FIX BUG #5: DROP COLUMN check now line-scoped (ignores comments)
        # Comment lines start with # or -- (Python/SQL comments)
        code_lines = migration_code.split('\n')
        for i, line in enumerate(code_lines, 1):
            # Skip pure comment lines
            stripped = line.lstrip()
            if stripped.startswith('#') or stripped.startswith('--'):
                continue
            
            # Check for DROP in actual code
            if re.search(r"\b(DROP\s+COLUMN|op\.drop_column)\b", line, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"Line {i}: Destructive operation (DROP COLUMN) — data will be lost",
                    "fix": "Confirm this is intentional. Ensure downgrade() reverses it, or plan a backfill strategy."
                })
                if self.verbose:
                    logger.debug(f"[database_architect] DROP detected at line {i}")

        # Check for NOT NULL without default on ADD COLUMN
        if re.search(r"ADD\s+COLUMN.*NOT\s+NULL(?!.*DEFAULT)", migration_code, re.IGNORECASE):
            findings.append({
                "severity": "CRITICAL",
                "issue": "Adding a NOT NULL column without a DEFAULT value — migration will fail against existing rows",
                "fix": "Add a DEFAULT value or provide a server-side backfill before applying the constraint."
            })

        # FIX: Check for idempotency (IF NOT EXISTS / IF EXISTS)
        if re.search(r"ADD\s+COLUMN", migration_code, re.IGNORECASE) and not re.search(r"IF\s+NOT\s+EXISTS", migration_code, re.IGNORECASE):
            findings.append({
                "severity": "MEDIUM",
                "issue": "ADD COLUMN without IF NOT EXISTS — running this migration twice will fail",
                "fix": "Use: ALTER TABLE ... ADD COLUMN IF NOT EXISTS ... (Postgres 9.1+)"
            })

        # Check for type changes without explicit casting
        if re.search(r"ALTER\s+COLUMN|CAST|USING", migration_code, re.IGNORECASE | re.DOTALL):
            if not re.search(r"CAST|USING|::", migration_code, re.IGNORECASE):
                findings.append({
                    "severity": "HIGH",
                    "issue": "Type change detected without explicit CAST or USING — may fail or truncate data",
                    "fix": "Use USING (Postgres): ALTER TABLE t ALTER COLUMN c TYPE new_type USING c::new_type"
                })

        # NEW: Check downgrade safety
        if "def downgrade" in migration_code or "downgrade" in migration_code.lower():
            if migration_code.count("def downgrade") == 1:
                # Single downgrade function — check if it mirrors upgrade
                downgrade_content = migration_code.split("def downgrade")[1]
                if not downgrade_content.strip() or "pass" in downgrade_content:
                    findings.append({
                        "severity": "MEDIUM",
                        "issue": "Downgrade function is empty (pass) — this migration cannot be safely rolled back",
                        "fix": "Implement downgrade() to reverse any schema changes made in upgrade()"
                    })

        return {"findings": findings, "total_issues": len(findings)}

    def _review_n_plus_one(self, code: str) -> Dict[str, Any]:
        """Detect N+1 query patterns (queries inside loops)."""
        findings = []

        # FIX BUG #22: Now detects single-line loops too
        # Pattern 1: Multi-line loops
        loop_pattern = r"(?:for|while|\.(map|forEach|for))\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{([^}]*\n[^}]*)
\s*\}|(?:for|forEach)\s*\(\s*(?:async\s*)?(?:const|let|var)\s+\w+\s+of\s+\w+\)\s*\{([^}]*\n[^}]*)
\s*\}"
        
        # Pattern 2: Single-line loops
        single_line_loop = r"(?:\.map|forEach)\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{\s*(?:await\s+)?(?:db\.query|query|select|find|get)\([^)]*\)\s*\}"
        
        for m in re.finditer(loop_pattern, code, re.DOTALL | re.IGNORECASE):
            loop_body = m.group(1) or m.group(2)
            if re.search(r"(?:db\.query|query|select|find|\w+\.get|\w+\.find)\s*\(", loop_body, re.IGNORECASE):
                findings.append({
                    "severity": "HIGH",
                    "issue": "N+1 query pattern: database query inside a loop — this will execute once per iteration",
                    "fix": "Batch the query: collect IDs in the loop, then execute a single WHERE id IN (...) or use a JOIN."
                })
                if self.verbose:
                    logger.debug(f"[database_architect] N+1 detected (multi-line loop)")
        
        for m in re.finditer(single_line_loop, code, re.IGNORECASE):
            findings.append({
                "severity": "HIGH",
                "issue": "N+1 query pattern: database query inside a loop (single line) — executes once per iteration",
                "fix": "Batch: collect items first, then execute one WHERE id IN (...) query."
            })
            if self.verbose:
                logger.debug(f"[database_architect] N+1 detected (single-line loop)")

        return {"findings": findings, "total_issues": len(findings)}

    def _review_constraints(self, schema_code: str) -> Dict[str, Any]:
        """Review a schema for missing foreign key and unique constraints."""
        findings = []

        # FIX BUG #4: Email uniqueness check now word-boundary aware
        # Only flag standalone 'email' columns, not email_enabled, sender_email, reply_to_email, etc.
        email_cols = re.findall(r"(?:email|\bemail\b)(?!_)\s*(?::\s*\w+|=\s*Column|=\s*mapped_column)", schema_code, re.IGNORECASE)
        for m in email_cols:
            # Check if this specific email column has .unique()
            # Extract the column name: match from 'email' onwards to the next comma or bracket
            col_match = re.search(r"(\w*email\w*)\s*(?::\s*[\w\[\]<>,]+|=\s*(?:Column|mapped_column)\([^)]*\))", schema_code, re.IGNORECASE)
            if col_match:
                col_name = col_match.group(1)
                # Check if this column has unique constraint
                if not re.search(rf"{col_name}[^,}}]*\.unique\(|unique\s*=\s*True", schema_code, re.IGNORECASE):
                    # But only if it's standalone 'email', not 'email_enabled', 'sender_email', etc.
                    if col_name.lower() == 'email':
                        findings.append({
                            "severity": "MEDIUM",
                            "column": col_name,
                            "issue": f"Email column '{col_name}' has no unique constraint — duplicates could be created by race conditions",
                            "fix": f"Add .unique() to the column, or unique_constraint=True if using SQLAlchemy"
                        })
                        if self.verbose:
                            logger.debug(f"[database_architect] Email without unique: {col_name}")

        # Check for FK columns without explicit FK constraint
        fk_pattern = r"(\w*id)\s*(?::\s*(?:uuid|integer|bigint)|=\s*(?:Column|mapped_column)\([^)]*\))"
        for m in re.finditer(fk_pattern, schema_code, re.IGNORECASE):
            col_name = m.group(1)
            # Check if this column actually has a ForeignKey constraint
            if not re.search(rf"{col_name}[^,}}]*\.references\(|ForeignKey\([^)]*{col_name}", schema_code):
                findings.append({
                    "severity": "MEDIUM",
                    "column": col_name,
                    "issue": f"Column '{col_name}' looks like a foreign key but has no constraint — referential integrity isn't enforced at the DB level",
                    "fix": f"Add .references(...) (Drizzle) or ForeignKey(...) (SQLAlchemy) to enforce referential integrity"
                })
                if self.verbose:
                    logger.debug(f"[database_architect] FK-like column without constraint: {col_name}")

        return {"findings": findings, "total_issues": len(findings)}
