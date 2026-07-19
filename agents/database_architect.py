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


def _balanced_call(text: str, open_paren: int) -> str:
    """Return one balanced call starting at ``open_paren``.

    ORM declarations routinely contain nested calls and lambdas. Regexes
    capped at two or three parenthesis levels silently truncated exactly the
    definitions these checks needed to inspect.
    """
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index in range(open_paren, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren:index + 1]
    return text[open_paren:]


def _assignment_calls(text: str, call_names: str):
    pattern = re.compile(rf"(?m)^\s*(\w+)\s*(?::[^=\n]+)?=\s*(?:{call_names})\s*(\()")
    for match in pattern.finditer(text):
        yield match.group(1), _balanced_call(text, match.start(2))


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

        # Drizzle: userId: uuid('user_id').notNull().references(() => users.id)
        # Keep the declaration line intact; the previous pattern accidentally
        # used [\\w_] (the literal characters slash/w/underscore) and therefore
        # matched almost no real column names.
        fk_cols = re.findall(
            r"(?m)(\w+)\s*:\s*[\w.]+\(\s*['\"]([\w_]+)['\"][^\n]*?\.references\s*\(",
            schema_code,
        )
        for field_name, column_name in fk_cols:
            if not re.search(
                rf"index\s*\([^)]*\)\s*\.on\s*\([^)]*\b{re.escape(field_name)}\b|"
                rf"\b{re.escape(column_name)}_(?:idx|index)\b|\b(?:idx|index)_{re.escape(column_name)}\b",
                schema_code,
                re.IGNORECASE,
            ):
                findings.append({
                    "severity": "MEDIUM",
                    "column": column_name,
                    "issue": f"Foreign key column '{column_name}' has no visible index — joins/filters on it will full-scan as the table grows",
                    "fix": f"Add: .index() to the column definition, or index('{column_name}_idx').on(table.{field_name})"
                })
                if self.verbose:
                    logger.debug(f"[database_architect] Missing FK index: {field_name}")

        # SQLAlchemy, including arbitrarily nested ForeignKey options.
        for column_name, call in _assignment_calls(schema_code, "mapped_column|Column"):
            col_def = call
            if "ForeignKey" not in col_def:
                continue
            # unique=True also creates an implicit index in SQLAlchemy
            if not re.search(r"index\s*=\s*True|unique\s*=\s*True", col_def):
                findings.append({
                    "severity": "MEDIUM",
                    "column": column_name,
                    "issue": f"Foreign key column '{column_name}' has no index=True — joins/filters will full-scan",
                    "fix": f"Add index=True to the Column/mapped_column, or create a separate Index()"
                })
                if self.verbose:
                    logger.debug(f"[database_architect] SQLAlchemy FK without index: {column_name}")

        return {"database": database, "findings": findings, "total_issues": len(findings)}

    def _review_migration_safety(self, migration_code: str) -> Dict[str, Any]:
        """Review a migration for safety against a populated table."""
        findings = []

        # A normal Alembic downgrade drops the column that upgrade added. It
        # is not a forward-deploy data-loss bug. Review destructive operations
        # only in upgrade/forward SQL, while still checking whether downgrade
        # itself is missing.
        downgrade_match = re.search(r"(?m)^\s*def\s+downgrade\s*\(", migration_code)
        forward_code = migration_code[:downgrade_match.start()] if downgrade_match else migration_code
        code_lines = forward_code.split('\n')
        for i, line in enumerate(code_lines, 1):
            stripped = line.lstrip()
            if stripped.startswith('#') or stripped.startswith('--'):
                continue
            if re.search(r"\b(DROP\s+COLUMN|op\.drop_column)\b", line, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"Line {i}: forward migration drops a column and its data",
                    "fix": "Use an expand/migrate/contract rollout: stop reads, back up or migrate data, then drop in a later deploy"
                })
                if self.verbose:
                    logger.debug(f"[database_architect] DROP detected at line {i}")

        # Check for NOT NULL without default on ADD COLUMN
        for statement in re.findall(r"(?is)ADD\s+COLUMN\b.*?(?:;|$)", forward_code):
            if re.search(r"NOT\s+NULL", statement, re.IGNORECASE) and not re.search(r"\bDEFAULT\b", statement, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": "Adding a NOT NULL column without a default/backfill will fail when rows already exist",
                    "fix": "Add it nullable, backfill in batches, then add the NOT NULL constraint (or use a safe server default)",
                })

        for match in re.finditer(r"op\.add_column\s*(\()", forward_code):
            call = _balanced_call(forward_code, match.start(1))
            if re.search(r"nullable\s*=\s*False", call) and not re.search(r"server_default\s*=", call):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": "Alembic adds a nullable=False column without server_default/backfill",
                    "fix": "Use a phased migration: add nullable, backfill, then alter to nullable=False",
                })

        # Alembic revisions are tracked and should run once; demanding IF NOT
        # EXISTS on every ADD COLUMN hides drift and was a noisy false positive.

        if re.search(r"ALTER\s+COLUMN|op\.alter_column\s*\([^)]*type_\s*=", forward_code, re.IGNORECASE | re.DOTALL) and not re.search(r"CAST|USING|::|postgresql_using", forward_code, re.IGNORECASE):
            findings.append({
                "severity": "HIGH",
                "issue": "Column type change has no explicit cast/USING expression",
                "fix": "Provide USING/postgresql_using and verify the conversion against production-like data",
            })

        # NEW: Check downgrade safety
        if "def downgrade" in migration_code or "downgrade" in migration_code.lower():
            if migration_code.count("def downgrade") == 1:
                # Single downgrade function — check if it mirrors upgrade
                downgrade_content = migration_code.split("def downgrade", 1)[1]
                body = downgrade_content.split("def ", 1)[0]
                if not body.strip() or re.search(r"(?m)^\s*pass\s*(?:#.*)?$", body):
                    findings.append({
                        "severity": "MEDIUM",
                        "issue": "Downgrade function is empty (pass) — this migration cannot be safely rolled back",
                        "fix": "Implement downgrade() to reverse any schema changes made in upgrade()"
                    })

        return {"findings": findings, "total_issues": len(findings)}

    def _review_n_plus_one(self, code: str) -> Dict[str, Any]:
        """Detect N+1 query patterns (queries inside loops)."""
        findings = []

        query_re = re.compile(
            r"(?:await\s+)?(?:db\.(?:query|execute|select)|session\.execute|cursor\.execute|"
            r"\w+\.(?:findMany|findOne|findUnique|findFirst|query|execute)|"
            r"(?:select|query)\s*\()",
            re.IGNORECASE,
        )
        loop_bodies: List[str] = []

        # JavaScript array callbacks and for/of loops. This intentionally
        # captures a bounded body rather than treating an unrelated query
        # elsewhere in the file as if it were inside the loop.
        for pattern in (
            r"\.(?:map|forEach)\s*\(\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>\s*\{(.*?)\}\s*\)",
            r"for\s*\([^)]*\bof\b[^)]*\)\s*\{(.*?)\}",
        ):
            loop_bodies.extend(m.group(1) for m in re.finditer(pattern, code, re.DOTALL))

        # Python indentation-aware for loops.
        lines = code.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"^(\s*)for\s+.+:\s*(?:#.*)?$", line)
            if not match:
                continue
            indent = len(match.group(1))
            body = []
            for following in lines[index + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                body.append(following)
            loop_bodies.append("\n".join(body))

        if any(query_re.search(body) for body in loop_bodies):
            findings.append({
                "severity": "HIGH",
                "issue": "Database query executes inside a loop (N+1 query pattern)",
                "fix": "Collect the keys first, fetch them in one IN/JOIN/preload query, then map the results in memory",
            })

        return {"findings": findings, "total_issues": len(findings)}

    def _review_constraints(self, schema_code: str) -> Dict[str, Any]:
        """Review a schema for missing foreign key and unique constraints."""
        findings = []

        # Review the actual email declaration, not the first `*email*` token
        # anywhere in the file (sender_email and email_enabled are commonly
        # non-unique and should not influence this check).
        drizzle_email = re.search(r"(?m)^\s*email\s*:\s*([^\n]+)", schema_code, re.IGNORECASE)
        sqlalchemy_email = next((call for name, call in _assignment_calls(schema_code, "mapped_column|Column") if name.lower() == "email"), None)
        email_decl = drizzle_email.group(1) if drizzle_email else sqlalchemy_email
        has_table_unique = bool(re.search(r"unique(?:Index|_constraint|Constraint)?\s*\([^\n]*email", schema_code, re.IGNORECASE))
        if email_decl and not re.search(r"\.unique\s*\(|unique\s*=\s*True", email_decl, re.IGNORECASE) and not has_table_unique:
            findings.append({
                "severity": "MEDIUM",
                "column": "email",
                "issue": "Email column has no visible database unique constraint — application-only checks race",
                "fix": "Add a database UNIQUE constraint/index when email identifies an account; suppress this finding if duplicate emails are intentional",
            })

        # A name ending in _id/Id is only suggestive, so keep this lower
        # confidence and skip IDs that are commonly external identifiers.
        external_ids = {"id", "event_id", "request_id", "provider_id", "external_id", "stripe_id", "plaid_id"}
        candidates = []
        for match in re.finditer(r"(?m)^\s*(\w+(?:_id|Id))\s*[:=]([^\n]+)", schema_code):
            name, declaration = match.group(1), match.group(2)
            if name.lower() in external_ids or re.search(r"\.references\s*\(|ForeignKey\s*\(", declaration):
                continue
            candidates.append(name)
        for name, call in _assignment_calls(schema_code, "mapped_column|Column"):
            if not (name.endswith("_id") or name.endswith("Id")) or name.lower() in external_ids or "ForeignKey" in call:
                continue
            candidates.append(name)
        for col_name in sorted(set(candidates)):
            findings.append({
                "severity": "LOW",
                "confidence": "medium",
                "column": col_name,
                "issue": f"Column '{col_name}' looks relational but has no visible foreign-key constraint",
                "fix": "Add .references(...)/ForeignKey(...) if this points to an internal table; otherwise document or rename the external identifier",
            })

        return {"findings": findings, "total_issues": len(findings)}
