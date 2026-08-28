"""Frontend performance and accessibility depth agent."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

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


def _template_literal_spans(code: str) -> List[Tuple[int, int]]:
    """(start, end) ranges covered by closed `...` template literals.

    Backticks only, and only when the literal actually closes. Treating ' and
    " as literal delimiters is unsafe without a real parser: an apostrophe in
    ordinary JSX text — `<p>Don't wait</p>` — would open a span that swallows
    everything after it, hiding real findings (Codex, agents#64). Generated
    markup is written as a template literal in practice, which is the case
    this needs to recognise.
    """
    spans: List[Tuple[int, int]] = []
    i = 0
    while i < len(code):
        if code[i] != "`":
            i += 1
            continue
        j = i + 1
        closed = False
        while j < len(code):
            if code[j] == "\\":
                j += 2
                continue
            if code[j] == "`":
                j += 1
                closed = True
                break
            j += 1
        if closed:
            spans.append((i, j))
            i = j
        else:
            i += 1  # unterminated: assume it was not a literal at all
    return spans


# Evidence the module hands HTML to the browser, which renders it — so the
# loading and dimension hints do apply to markup built in a string here.
_INJECTS_HTML = re.compile(
    r"\binnerHTML\b|\binsertAdjacentHTML\b|\bouterHTML\b|dangerouslySetInnerHTML",
)


# An absolutely-positioned image with all insets pinned takes its box from its
# containing block, so intrinsic width/height would be inert markup. `w-full
# h-full` alone is NOT enough: a percentage height resolves to auto unless the
# parent has a definite height, and the parent isn't visible from here
# (Codex, agents#64).
_FILLS_CONTAINER = re.compile(r"absolute[^\"'`]*inset-0")


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
        # An <img> written inside a string or template literal is markup this
        # module *generates* (an email body, an innerHTML fragment), not JSX it
        # renders, so browser loading hints don't apply to it.
        # Markup a module injects into the DOM is rendered by the browser, so
        # the hints do apply there — only skip generated markup that isn't.
        literal = [] if _INJECTS_HTML.search(code) else _template_literal_spans(code)
        img_tags = []
        if not email_html:
            cursor = 0
            for _, _, full in find_jsx_tags(code, "img", re.IGNORECASE):
                at = code.find(full, cursor)
                if at != -1:
                    cursor = at + 1
                    if any(start <= at < end for start, end in literal):
                        continue
                img_tags.append(full)

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
            and not _FILLS_CONTAINER.search(tag)
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
