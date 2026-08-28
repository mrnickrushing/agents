"""Frontend performance and accessibility depth agent."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent
from agents.ui_generation import find_jsx_tags

# `loading="lazy"` and `srcSet` are browser features that email clients do not
# implement, so telling an email template to use them is noise, not a fix.
# These markers identify a module that builds or sends email HTML.
_EMAIL_HTML_MARKERS = re.compile(
    r"""
      \b(?:nodemailer|sendgrid|postmark|mailgun|SESClient|sendEmail)\b
    | \.emails\.send\s*\(
    | \bsendMail\s*\(
    | \bfrom\s+['"]resend['"]
    | \brequire\(\s*['"]resend['"]\s*\)
    | \b[A-Z0-9_]*(?:EMAIL|MAIL)[A-Z0-9_]*_HTML\b
    | \bcellpadding\s*=
    | \bcellspacing\s*=
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _builds_email_html(code: str) -> bool:
    """True when this module builds or sends email HTML rather than a page."""
    return bool(_EMAIL_HTML_MARKERS.search(code))


class FrontendPerformanceAgent(BaseAgent):
    name = "frontend_performance"
    description = (
        "Audits bundle, render, CWV, and advanced accessibility performance risks."
    )
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "audit_frontend_performance",
                "description": "Detect common bundle-size, render-efficiency, and accessibility anti-patterns.",
                "parameters": {
                    "type": "object",
                    "properties": {"code": {"type": "string"}},
                    "required": ["code"],
                },
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {"audit_frontend_performance": self._audit_frontend_performance}

    def _audit_frontend_performance(self, code: str) -> Dict[str, Any]:
        findings = []
        if re.search(r"import\s+[_\w{},*\s]+\s+from\s+['\"]lodash['\"]", code):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Whole lodash import may increase bundle size",
                    "fix": "Import only used functions (e.g., lodash/debounce).",
                }
            )
        if re.search(r"\.map\(\s*\([^)]*\)\s*=>\s*<", code) and not re.search(
            r"\bkey\s*=", code
        ):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "issue": "JSX list rendering has no key prop",
                    "fix": "Provide stable key props for list items.",
                }
            )
        # Email HTML is exempt: email clients ignore loading/srcSet, so these
        # hints would be dead markup in a message body (sugarhaus server.js
        # builds its order emails inline, 2026-08-28).
        email_html = _builds_email_html(code)

        # Per tag, not per file. Scanning the whole blob let one hinted image
        # vouch for every other one, so a hero with loading="eager" hid a bare
        # <img> beside it (Codex, agents#63) — and, before that, one lazy image
        # hid the rest.
        img_tags = (
            []
            if email_html
            else [full for _, _, full in find_jsx_tags(code, "img", re.IGNORECASE)]
        )

        # An explicit loading="eager" or fetchPriority="high" is a deliberate
        # decision, not an oversight: lazy-loading an above-the-fold or LCP
        # image makes load performance worse, so don't ask for it back.
        if [
            tag
            for tag in img_tags
            if not re.search(
                r"loading\s*=\s*['\"]lazy['\"]|loading\s*=\s*['\"]eager['\"]"
                r"|fetchPriority\s*=\s*['\"]high['\"]",
                tag,
                re.IGNORECASE,
            )
        ]:
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Image tag missing loading='lazy'",
                    "fix": "Add loading='lazy' for non-critical images.",
                }
            )
        if [
            tag
            for tag in img_tags
            if not re.search(r"\b(srcSet|width\s*=|height\s*=)", tag, re.IGNORECASE)
        ]:
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Image may be unoptimized (missing srcSet/width/height hints)",
                    "fix": "Provide responsive srcSet and explicit dimensions.",
                }
            )
        if re.search(r"<button[^>]*>\s*<(svg|i)\b", code) and not re.search(
            r"<button[^>]*aria-label=", code
        ):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "issue": "Icon-only button missing aria-label",
                    "fix": "Add aria-label describing button action.",
                }
            )
        if re.search(r"requestAnimationFrame|setInterval", code) and re.search(
            r"(offsetHeight|offsetWidth|getBoundingClientRect)", code
        ):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Animation loop reads layout metrics (possible layout thrashing)",
                    "fix": "Batch DOM reads/writes and avoid sync layout reads inside tight loops.",
                }
            )
        if re.search(r"modal|dialog", code, re.IGNORECASE) and not re.search(
            r"focus\(|aria-modal|role=['\"]dialog['\"]", code
        ):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Modal/dialog lacks visible focus management",
                    "fix": "Move focus into dialog and restore focus on close.",
                }
            )
        return {"findings": findings, "total_issues": len(findings)}
