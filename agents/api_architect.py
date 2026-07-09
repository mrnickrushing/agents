"""
API Architect Agent — REST endpoint design, pagination, error shape, status codes.

Reviews the design-level conventions of an API (as opposed to CodeReviewAgent's
per-route implementation review): pagination affordances, error response
envelope consistency, status code correctness, and OpenAPI documentation.

Usage:
    from agents import APIArchitectAgent
    agent = APIArchitectAgent(api_key="sk-...")
    result = agent.run("Review this list endpoint for pagination")
    print(result.content)
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class APIArchitectAgent(BaseAgent):
    """
    REST API design specialist.

    Reviews pagination, error response shape, status code correctness, and
    can scaffold an OpenAPI stub for a set of endpoints.
    """

    name = "api_architect"
    description = "Reviews REST API design: pagination, error response shape, status code correctness, OpenAPI documentation."
    model = "gpt-5"

    system_prompt = """\
You are a REST API design specialist for solo full-stack operators. You review API-level design conventions, not implementation details:

YOUR DOMAIN:

1. PAGINATION
   - List endpoints return a bounded page, not the whole table
   - Response includes pagination metadata (nextCursor/hasMore, or page/totalCount for offset pagination)
   - Cursor pagination preferred for high-write tables (offset pagination degrades and can skip/duplicate rows under concurrent writes)

2. ERROR RESPONSE SHAPE
   - Errors return a consistent JSON envelope (e.g. { error: { code, message } }), not raw strings or ad-hoc shapes that differ per route
   - Stack traces and internal error details never reach the client in production
   - 4xx for client mistakes, 5xx for server failures — not 200 with an error field buried in the body

3. STATUS CODES
   - 201 Created (with Location header where relevant) for successful POST-create, not 200
   - 204 No Content for successful DELETE, not 200 with an empty body
   - 404 for missing resources, 403 for authz failures, 401 for missing/invalid auth — not a blanket 400/500

4. VERSIONING & NAMING
   - Consistent versioning strategy (URL prefix /api/v1/ is simplest and most common)
   - Resource-based, plural-noun paths (/users/:id, not /getUser)
   - Consistent casing (snake_case or camelCase, not mixed) across the response body

5. DOCUMENTATION
   - OpenAPI/Swagger spec present and kept in sync with actual routes

When reviewing, always cite the specific endpoint/response shape that's inconsistent and give the exact fix.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_pagination",
                "description": "Review a list endpoint for pagination affordances (bounded results, cursor/offset params, response metadata).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The list endpoint handler code"},
                        "endpoint": {"type": "string", "description": "The endpoint path, e.g. 'GET /api/v1/logs'"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_error_response_shape",
                "description": "Review error handling for a consistent JSON envelope and no leaked internals (stack traces).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The route/error-handler code to review"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "audit_status_codes",
                "description": "Audit HTTP status code usage for POST/DELETE/error responses.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The route handler code to audit"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "generate_openapi_stub",
                "description": "Generate a minimal OpenAPI 3.0 stub for a set of endpoints.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "API title"},
                        "endpoints": {"type": "string", "description": "Comma-separated 'METHOD /path' entries, e.g. 'GET /users, POST /users'"},
                    },
                    "required": ["title", "endpoints"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_pagination": self._review_pagination,
            "review_error_response_shape": self._review_error_response_shape,
            "audit_status_codes": self._audit_status_codes,
            "generate_openapi_stub": self._generate_openapi_stub,
        }

    def _review_pagination(self, code: str, endpoint: str = "") -> Dict[str, Any]:
        """Review pagination affordances on a list endpoint."""
        findings = []
        code_lower = code.lower()

        has_limit_param = bool(re.search(r"\blimit\b|\bpage\b|\bcursor\b|\boffset\b", code_lower))
        if not has_limit_param:
            findings.append({"severity": "HIGH", "issue": "No limit/page/cursor/offset parameter found — this endpoint likely returns the entire table", "fix": "Accept a limit (capped, e.g. max 100) and cursor or page param, and apply it to the query"})

        returns_array = bool(re.search(r"res\.json\(\s*\[|\.json\(\s*rows\)|\.json\(\s*results\)|\.json\(\s*items\)", code))
        has_meta = bool(re.search(r"hasMore|nextCursor|next_cursor|totalCount|total_count|has_next", code, re.IGNORECASE))
        if has_limit_param and returns_array and not has_meta:
            findings.append({"severity": "MEDIUM", "issue": "Paginated results returned with no pagination metadata (hasMore/nextCursor/totalCount) — the client can't tell if there's another page", "fix": "Include { data, hasMore, nextCursor } (or { data, page, totalCount }) in the response envelope"})

        return {"endpoint": endpoint, "findings": findings, "total_issues": len(findings)}

    def _review_error_response_shape(self, code: str) -> Dict[str, Any]:
        """Review error handling for a consistent envelope and no leaked internals."""
        findings = []

        if re.search(r"res\.(status\(\d+\)\.)?send\(\s*err(or)?\.(message|stack)\s*\)", code):
            findings.append({"severity": "HIGH", "issue": "Raw error message/stack sent directly to the client — can leak internal details (file paths, query structure, library versions)", "fix": "Log the full error server-side; send a generic, consistent error shape to the client"})
        if re.search(r"res\.json\(\s*err\s*\)|res\.send\(\s*err\s*\)", code):
            findings.append({"severity": "HIGH", "issue": "Raw error object sent directly to the client — likely includes a stack trace", "fix": "Send { error: { code, message } } built explicitly, never the raw error object"})

        # Comparing *all* res.json() call shapes (business responses included)
        # against a low distinctness threshold flagged nearly every route
        # file, since different endpoints legitimately return different
        # data — that's not an error-shape problem. Only compare the shape
        # of the error value itself: a plain string ({error: "msg"}) vs a
        # nested object ({error: {code, message}}) are genuinely different
        # contracts for whatever's parsing the response client-side.
        has_string_error = bool(re.search(r"error\s*:\s*[\"'`]", code))
        has_object_error = bool(re.search(r"error\s*:\s*\{", code))
        if has_string_error and has_object_error:
            findings.append({"severity": "LOW", "issue": "Error responses in this file use both a plain string (error: \"msg\") and a nested object (error: {...}) shape — inconsistent contract for whatever's parsing the response client-side", "fix": "Pick one error shape (e.g. { error: { code, message } }) and use it for every error response in this file"})

        return {"findings": findings, "total_issues": len(findings)}

    def _audit_status_codes(self, code: str) -> Dict[str, Any]:
        """Audit HTTP status code usage."""
        findings = []

        if re.search(r"router\.post\(|app\.post\(", code) and re.search(r"res\.status\(200\)\.json\(\s*\{[^}]*id", code):
            findings.append({"severity": "LOW", "issue": "POST that creates a resource returns 200 instead of 201", "fix": "Return res.status(201).json({...}) for successful resource creation"})

        if re.search(r"router\.delete\(|app\.delete\(", code) and re.search(r"res\.status\(200\)\.json\(\s*\{\}\s*\)|res\.status\(200\)\.send\(\)", code):
            findings.append({"severity": "LOW", "issue": "DELETE returns 200 with an empty body instead of 204", "fix": "Return res.status(204).send() for a successful delete with no body"})

        if re.search(r"res\.status\(200\)\.json\(\s*\{\s*error", code, re.IGNORECASE):
            findings.append({"severity": "MEDIUM", "issue": "Error response returned with status 200 — clients checking response.ok or status code will treat this as success", "fix": "Use an appropriate 4xx/5xx status code alongside the error body"})

        return {"findings": findings, "total_issues": len(findings)}

    def _generate_openapi_stub(self, title: str, endpoints: str) -> Dict[str, Any]:
        """Generate a minimal OpenAPI 3.0 stub."""
        paths: Dict[str, Any] = {}
        for entry in endpoints.split(","):
            entry = entry.strip()
            if not entry or " " not in entry:
                continue
            method, path = entry.split(" ", 1)
            path = path.strip()
            paths.setdefault(path, {})[method.strip().lower()] = {
                "summary": f"{method.strip().upper()} {path}",
                "responses": {"200": {"description": "Successful response"}},
            }

        spec = {
            "openapi": "3.0.3",
            "info": {"title": title, "version": "1.0.0"},
            "paths": paths,
        }
        return {"openapi_stub": spec, "endpoint_count": len(paths)}
