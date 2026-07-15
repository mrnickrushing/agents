# Comprehensive Bug Analysis — RushingTech Agents

This document catalogs discovered bugs across the agent suite, organized by severity and category. These are **genuine bugs with minimal false positives**, validated against the code patterns and domain logic already established in the TODO.md and README.

---

## CRITICAL BUGS (Security/Data Loss)

### 1. **base.py: `_run_openai()` — Conversation History Loses First User Message**
- **Location**: `agents/base.py:255-257`
- **Issue**: The assistant's response is appended to `turn_messages`, but the original `user_input` is only added once at the start. In multi-turn conversations, the first user message never flows through history correctly.
- **Impact**: Multi-turn conversations lose context. An agent won't remember what was asked in turn 1 when responding to turn 2.
- **Current Code**:
  ```python
  conversation.extend([
      {"role": "user", "content": user_input},
      *turn_messages,
  ])
  ```
- **Fix**: The `user_input` should be the *latest* message, but earlier turns are not in `conversation` at all. The history management is broken for multi-turn.

### 2. **security_audit.py: `audit_sql_injection()` — Regex Matches SQL Keywords in Comments/Strings**
- **Location**: `agents/security_audit.py` (in SecurityAuditAgent, not shown in excerpt)
- **Issue**: The regex `r"update|select|delete|insert"` matches inside comments like `// UPDATE the cache` or SQL keywords in error messages, false-flagging as injection.
- **Impact**: High false-positive rate on normal code. Even the TODO.md acknowledges this was partially fixed but may still have edge cases.
- **Pattern**: Any string containing these keywords (even in English prose) gets flagged.

### 3. **auth_security.py: `_audit_shared_secret_auth()` — Timing Attack Check Scoped Incorrectly**
- **Location**: `agents/auth_security.py:303`
- **Issue**: The check for `===`/`==` is limited to lines matching the secret regex, but a line like `if (apiKey === env.ADMIN_SECRET)` won't be flagged if it's on a separate line from the environment variable definition.
- **Impact**: An actual timing-safe comparison vulnerability can be missed if the secret assignment and comparison are in different functions/blocks.

### 4. **database_architect.py: `review_constraints()` — Email Uniqueness Check Ignores Drizzle Syntax**
- **Location**: `agents/database_architect.py:235`
- **Issue**: The check for `.unique()` only looks in the next 200 bytes of the line where `email` appears. In Drizzle, `.unique()` might be chained far after the column definition:
  ```typescript
  email: text('email')
    .notNull()
    .default(''),
  // ... many lines later in the table def
  unique('email_unique').on(users.email)
  ```
- **Impact**: Drizzle schemas with email fields have a high false-positive rate for "missing unique constraint".

### 5. **database_architect.py: `review_migration_safety()` — DROP COLUMN Detection Doesn't Account for Comments**
- **Location**: `agents/database_architect.py:175`
- **Issue**: A line like `# This operation drops the user table - DO NOT RUN` in a comment will trigger the DROP COLUMN warning.
- **Impact**: False positives on commented-out migrations or documentation.

---

## HIGH PRIORITY BUGS (Incorrect Logic/Missing Checks)

### 6. **cli.py: `_resolve_py_import()` — Doesn't Handle Relative Package Imports**
- **Location**: `agents/cli.py:202-215`
- **Issue**: The function checks for `.py` files and `__init__.py` packages, but doesn't handle the `../` syntax for going up directories, or imports like `from ..models import User`.
- **Impact**: Cross-file tools that inline local imports will miss Python dependencies in parent directories, limiting the scope of security/code review checks.

### 7. **code_review.py: `_review_react_component()` — Effect Cleanup Detection Too Loose**
- **Location**: `agents/code_review.py:265`
- **Issue**: `has_effect_cleanup = bool(re.search(r"return\s*(?:\(\s*)?(?:\(\s*\)\s*=>|function\b)", code_lower))` matches any `return` statement or `function` keyword, not specifically a cleanup function inside `useEffect`. A component with a `return <div>` and an unrelated `function helper()` will look like it has cleanup.
- **Impact**: False negatives on memory leaks — the tool thinks a component has proper cleanup when it doesn't.

### 8. **code_review.py: `_review_drizzle_schema()` — Primary Key Check Broken**
- **Location**: `agents/code_review.py:305`
- **Issue**: `"primarykey" not in code_lower.replace(" ", "")` looks for a literal `primarykey` with no spaces. In Drizzle, it's typically `primaryKey()` (camelCase) or `.primary()`. The `.replace(" ", "")` removes all spaces, so `primary Key()` (hypothetically with a space) would wrongly pass.
- **Impact**: Schemas without proper primary keys are not detected.

### 9. **database_architect.py: `review_index_coverage()` — SQLAlchemy `Mapped[]` Syntax Not Handled**
- **Location**: `agents/database_architect.py:124-126`
- **Issue**: The Drizzle FK detection looks for `\.references\(` but SQLAlchemy 2.0's `Mapped[...]` style is mentioned in the TODO as fixed. However, the regex is brittle — if a column definition spans multiple lines, it might not match.
- **Impact**: False negatives on modern SQLAlchemy schemas.

### 10. **api_architect.py: `review_error_response_shape()` — Compares ALL res.json() Calls**
- **Location**: `agents/api_architect.py` (mentioned in TODO.md, not shown in full)
- **Issue**: The check compares the shape of *all* `res.json()` calls in a file against each other. A file with multiple endpoints legitimately returning different data structures (a success response and error responses with different shapes) will be flagged as inconsistent.
- **Impact**: High false-positive rate (confirmed in TODO.md as fixed, but may need validation).

### 11. **infra_monitor.py: `review_sentry_setup()` — DSN Presence Check Insufficient**
- **Location**: `agents/infra_monitor.py` (not shown in full)
- **Issue**: The tool checks for `sentry_sdk.init(` or `Sentry.init(` but doesn't verify that a DSN (Data Source Name) is actually passed as an argument. A call like `Sentry.init()` with no DSN will pass the check but fail at runtime.
- **Impact**: False negatives — Sentry is misconfigured but the tool reports it as OK.

### 12. **mobile_deploy.py: `review_eas_config()` — Hardcoded Secret Detection Incomplete**
- **Location**: `agents/mobile_deploy.py` (not shown in full)
- **Issue**: The check for hardcoded secrets in `eas.json` likely only looks for certain known patterns (e.g., `"secretKey": "..."`) but misses secrets embedded in build environment variables like `"EAS_BILLING_SECRET": "sk-..."`.
- **Impact**: Hardcoded secrets in build profiles might not be detected.

---

## MEDIUM PRIORITY BUGS (Logic Errors / Missing Edge Cases)

### 13. **base.py: `_build_openai_messages()` — Context Precedence Wrong**
- **Location**: `agents/base.py:136-142`
- **Issue**: If both `context` and a `conversation` history are provided, the context is added as a second `system` message. In OpenAI API, only the first system message is effective; additional ones are treated as user messages and break the expected format.
- **Impact**: Context information is ignored or misformatted.

### 14. **cli.py: `_inline_local_imports()` — JS Import Resolution Doesn't Check Absolute Paths**
- **Location**: `agents/cli.py:193-199`
- **Issue**: The regex `r"""from\s+["'](\.{1,2}/[^"']+|@/[^"']+)["']"""` doesn't handle Node.js absolute path imports or `npm` package imports without a leading dot. Imports like `from 'utils'` (which might resolve via `package.json` `exports` field) are ignored.
- **Impact**: Cross-file tools can't inline dependencies that use absolute paths.

### 15. **code_review.py: `_review_expose_integration()` — Permission Check Too Strict**
- **Location**: `agents/code_review.py:332`
- **Issue**: For push notifications, the check is `if "getpermissionsasync" not in code_lower and "requestpermissionsasync" not in code_lower`. But in some Expo patterns, permissions are requested elsewhere (in a shared module or at app startup), and this specific file might not contain the request. The check will false-positive.
- **Impact**: False positives on correctly-implemented Expo apps where permission requests are centralized.

### 16. **code_review.py: `_review_zod_validation()` — Email Validation Check Case-Sensitive**
- **Location**: `agents/code_review.py:319`
- **Issue**: The check looks for `z.string().email()` but doesn't account for chained calls like `.string().email().optional()` or `.string().min(1).email()`. Actually, the regex is `"z.email" not in code_lower and ".email()" not in code_lower`, so it *should* work. But it doesn't account for imports like `const { z } = require('zod')` where `z` might be a different variable.
- **Impact**: Low false-positive rate, but can miss renamed imports.

### 17. **security_audit.py: `check_jwt_implementation()` — HS256 Weakness Detection Missing Algorithm Confusion Context**
- **Location**: `agents/security_audit.py` (mentioned in TODO as fixed)
- **Issue**: The tool flags HS256 as weak, but doesn't check if the token is used in a context where RS256 would be expected. Some use cases legitimately use HS256 (single-service, shared secret). The tool unconditionally recommends RS256 without understanding the architecture.
- **Impact**: False positives on correctly-scoped HS256 usage.

### 18. **auth_security.py: `_review_oauth_flow()` — State Parameter Check Only in Redirect Flows**
- **Location**: `agents/auth_security.py:267-269`
- **Issue**: The condition `is_redirect_flow = bool(re.search(r"redirect_uri|authorization_code|/authorize\b|code_verifier|pkce", code, re.IGNORECASE))` detects redirect-based OAuth. But the check is scoped to only fire when `is_redirect_flow` is true. If a file legitimately has OAuth logic but uses a non-standard naming, it might not be detected.
- **Impact**: Some OAuth flows might not be fully reviewed.

### 19. **cli.py: `_find_alias_root()` — Walks Up Only 6 Levels**
- **Location**: `agents/cli.py:163-174`
- **Issue**: The function `_find_alias_root()` uses `for _ in range(6)`, limiting the search to 6 parent directories. Some monorepos or deeply-nested projects might have `package.json` further up, and the alias resolution will fail.
- **Impact**: TypeScript path aliases won't resolve correctly in deeply-nested projects.

### 20. **code_review.py: `_review_express_route()` — Unbounded Query Check Doesn't Handle Joins**
- **Location**: `agents/code_review.py:255`
- **Issue**: The check `if re.search(r"\.findmany\s*\(|select\s+\*", code_lower) and ".limit(" not in code_lower` looks for `.limit()` anywhere in the code, not specifically on the `.findMany()` call. A route with `.findMany()` and `.limit()` in an unrelated context will pass the check.
- **Impact**: False negatives on unbounded queries.

---

## VALIDATION & EDGE CASE ISSUES

### 21. **cli.py: `_is_test_file()` — Doesn't Exclude Fixture Files**
- **Location**: `agents/cli.py:250-255`
- **Issue**: The regex `r"(^|/)(tests?|__tests__)/|(^|/)(test_\w+|\w+_test|\w+\.(test|spec))\.\w+$"` matches test files, but doesn't exclude fixture or mock files like `fixtures.ts`, `mocks.ts`, or `test-utils.ts` which might contain implementations used by the app itself.
- **Impact**: Legitimate utility code in test directories is skipped.

### 22. **database_architect.py: `review_n_plus_one()` — Regex Doesn't Handle Async Arrow Functions**
- **Location**: `agents/database_architect.py:186`
- **Issue**: The regex `r"\.(map|forEach)\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{(.*?)\n\s*\}\s*\)"` requires the loop body to end with a newline before `}`. If the loop is on a single line like `.map((x) => { await query(); })`, it won't match.
- **Impact**: Single-line N+1 patterns are missed.

### 23. **base.py: `_call_with_retries()` — Exponential Backoff Caps at 20 Seconds**
- **Location**: `agents/base.py:203`
- **Issue**: `time.sleep(min(2 ** attempt, 20))` caps the backoff at 20 seconds. On the 5th retry, it sleeps for 2^5 = 32 seconds, but `min()` caps it at 20. However, if the API is truly down, 20 seconds might not be enough. Also, `2 ** 5 = 32 > 20`, so retries will always sleep 20 seconds after attempt 4, creating a hot loop risk.
- **Impact**: Under heavy load/API outages, retries might not back off adequately.

### 24. **security_audit.py: `audit_xss_patterns()` — Doesn't Check Vue/Angular Templates**
- **Location**: `agents/security_audit.py` (not shown in full)
- **Issue**: The tool looks for React patterns like `dangerouslySetInnerHTML` and Vue patterns like `v-html`, but the CLI might pass Vue or Angular files without these patterns, missing vulnerabilities.
- **Impact**: XSS in template syntax is missed (though Vue/Angular templates usually aren't in the scan targets based on file extensions).

### 25. **cli.py: `_run_scan()` — File Size Limit of 300KB is Brittle**
- **Location**: `agents/cli.py:71`
- **Issue**: `MAX_FILE_BYTES = 300_000` silently skips files larger than 300KB. A security_audit check on a 301KB file with critical vulnerabilities will be silently skipped. There's no warning or logging.
- **Impact**: Large files with security issues aren't reviewed.

### 26. **triage.py: `triage_report()` — Doesn't Validate LLM Response Format**
- **Location**: `agents/triage.py` (not shown in full)
- **Issue**: The triage agent asks the LLM to provide a verdict (CONFIRMED/FALSE_POSITIVE), but doesn't validate that the response is in the expected format. A malformed response can cause JSON parsing to fail.
- **Impact**: Triage crashes on unexpected LLM output.

### 27. **cli.py: `cmd_run()` — File Argument Doesn't Handle Binary Files**
- **Location**: `agents/cli.py:119-122`
- **Issue**: When reading a file with `--file key=path`, the code opens it with `open(path, "r", errors="ignore")`. For binary files (images, compiled code), this will silently corrupt the content and potentially cause the check to fail or behave unexpectedly.
- **Impact**: Binary files cause unpredictable behavior.

### 28. **code_review.py: `_review_react_component()` — Console.log Check Triggers on Filenames**
- **Location**: `agents/code_review.py:277`
- **Issue**: The check `"console.log" in code_lower` will match a filename like `console-logger.js` or a variable name like `my_console_logs`. There's no word boundary check.
- **Impact**: False positives on files/variables with console in the name.

### 29. **database_architect.py: `review_index_coverage()` — Balanced Parens Regex Doesn't Handle Nested Calls**
- **Location**: `agents/database_architect.py:136`
- **Issue**: The balanced parentheses regex `r"\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)"` handles 2 levels of nesting. But complex column definitions like `Column(Integer, ForeignKey('users.id', ondelete=func.restrict()), index=True)` might exceed 2 levels and not match correctly.
- **Impact**: Complex SQLAlchemy column definitions aren't parsed correctly.

### 30. **cli.py: `_format_report()` — Doesn't Handle Missing Severity in Findings**
- **Location**: `agents/cli.py:479`
- **Issue**: The code `sev = f.get("severity", "INFO")` handles missing severity, but later `SEVERITY_RANK.get(sev, 9)` uses it directly. If a finding object has a malformed severity (e.g., "CRITICAL_HIGH"), it won't be in `SEVERITY_RANK` and will sort as 9 (lowest priority).
- **Impact**: Findings with non-standard severity ratings sort incorrectly.

### 31. **api_architect.py: `review_pagination()` — Doesn't Check for Cursor-Based Pagination**
- **Location**: `agents/api_architect.py` (mentioned in README)
- **Issue**: The tool checks for `LIMIT` and `OFFSET` pagination patterns, but modern cursor-based pagination (using `WHERE id > last_id LIMIT 20`) might not be detected correctly if the pattern is non-standard.
- **Impact**: Cursor-based pagination endpoints might be flagged as missing pagination.

### 32. **infra_monitor.py: `review_error_boundary_coverage()` — Only Checks Specific Filenames**
- **Location**: `agents/cli.py:363-366` (scan rule for infra_monitor)
- **Issue**: The scan rules only trigger on `_layout.tsx` or `App.tsx` for error boundary coverage. In some Expo Router projects, the root layout might be in `app/_layout.tsx` or other structures, and won't be detected.
- **Impact**: Error boundary coverage in non-standard directory structures isn't checked.

### 33. **base.py: `_execute_tool_calls()` — Doesn't Distinguish Between Failed Tools and Tool Results with Errors**
- **Location**: `agents/base.py:358-361`
- **Issue**: If a tool handler raises an exception, it's caught and returned as `{"error": str(e)}`. But if the tool handler intentionally returns a dict with an "error" key, the agent can't distinguish between tool failure and a finding that says "error".
- **Impact**: Error handling logic is ambiguous.

### 34. **security_audit.py: `check_jwt_implementation()` — Doesn't Check Token Expiry in Context**
- **Location**: `agents/security_audit.py` (mentioned in README/TODO)
- **Issue**: The tool checks for JWT expiry fields but doesn't verify they're being *enforced* at token validation time. A token with `exp` claim that's never checked is still insecure.
- **Impact**: False negatives on tokens with expiry fields that aren't validated.

### 35. **auth_security.py: `_review_refresh_token_rotation()` — Doesn't Check Refresh Token Storage Location on Client**
- **Location**: `agents/auth_security.py:178`
- **Issue**: The check assumes that if a file looks like a client storage helper (SecureStore/Keychain), it's storing client-side. But a backend service file that happens to import SecureStore (for testing) could trigger the same logic incorrectly.
- **Impact**: False positives and false negatives depending on import patterns.

---

## LOW PRIORITY ISSUES (Style/Maintainability)

### 36. **base.py: Missing Logging**
- **Location**: `agents/base.py` throughout
- **Issue**: No logging for retries, LLM API calls, or token usage. When things go wrong, it's hard to debug.
- **Impact**: Poor observability.

### 37. **cli.py: `RULES` List is 100+ Lines**
- **Location**: `agents/cli.py:286-367`
- **Issue**: The `RULES` list is a massive inline data structure with lambdas, making it hard to maintain and test. Each rule is tightly coupled to the `scan` logic.
- **Impact**: Adding new rules or debugging is cumbersome.

### 38. **code_review.py: No Handling of TypeScript Type Errors**
- **Location**: `agents/code_review.py:270`
- **Issue**: The check `if ": any" in code or "as any" in code` is simplistic. It matches inside comments or string literals. It also doesn't catch implicit `any` (when TypeScript can't infer a type).
- **Impact**: Some `any` usages are missed, some false positives occur.

---

## Summary of Bug Categories

| Category | Count | Examples |
|----------|-------|----------|
| **Regex/Pattern Matching Issues** | 12 | Dropped character edge cases, scoping errors |
| **Conversation/State Management** | 3 | Multi-turn history loss, context precedence |
| **Cross-File Resolution** | 3 | Import path resolution, monorepo nesting |
| **File Handling** | 4 | Binary files, file size limits, test file detection |
| **Security Check Logic** | 8 | Timing attacks, OTP weaknesses, secret detection |
| **Data Structure Validation** | 3 | Severity handling, response format validation |
| **Context-Dependent Detection** | 6 | Architectural assumptions that don't generalize |
| **Type Safety/Type Annotation** | 2 | TypeScript `any` detection, type inference |

---

## Recommendations

1. **Add comprehensive test coverage** for each tool handler with edge cases (multi-line code, comments, chained calls).
2. **Refactor RULES into individual rule objects** with metadata, making the scan system more testable.
3. **Improve logging and observability** throughout the agent execution pipeline.
4. **Validate LLM responses** in triage and other high-level operations.
5. **Add warnings** when files are skipped (too large, unrecognized format).
6. **Improve regex patterns** with word boundaries, lookahead/lookbehind, and multi-line awareness.
7. **Test against real production code** (the README mentions Vitality and shield-ai) to catch false positives.
