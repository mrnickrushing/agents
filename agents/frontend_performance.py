"""Frontend performance and accessibility depth agent."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

from agents.base import BaseAgent
from agents.security_audit import _strip_js_comments
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


# Layout thrashing is a read and a write interleaved inside one frame
# callback, so that each pass dirties layout and then immediately forces it
# back to measure. Co-occurrence anywhere in a file is not that. chorechart's
# two bundles measure once in a click handler, pass plain numbers onward, and
# batch every write inside a double rAF -- the shape the fix text asks for --
# and the old file-level check reported both of them (2026-08-28).
#
# The read set below is deliberately unchanged, so what this reports is a
# strict subset of what the file-level check reported: it can only drop false
# positives, never introduce a finding that did not exist before.
_LAYOUT_READ = re.compile(r"offsetHeight|offsetWidth|getBoundingClientRect")

# A write that dirties layout, so a read after it in the same body has to
# force a synchronous reflow to answer.
_LAYOUT_WRITE = re.compile(
    r"""
      \.style\b
    | \.className\s*=
    | \.classList\s*\.\s*(?:add|remove|toggle)\s*\(
    | \.setAttribute\s*\(
    | \.(?:innerHTML|outerHTML|textContent|innerText)\s*=
    | \.(?:
          appendChild | append | prepend | insertBefore
        | insertAdjacentElement | insertAdjacentHTML
        | removeChild | replaceChildren | replaceChild | replaceWith | remove
      )\s*\(
    """,
    re.VERBOSE,
)

_FRAME_SCHEDULER = re.compile(r"\b(?:requestAnimationFrame|setInterval)\s*\(")

# `setInterval(tick, 16)` hands off to a function declared elsewhere in the
# file, so the body worth reading is not at the call site.
_CALLBACK_NAME = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*(?:,|$)")


def _balanced_span(text: str, start: int) -> int:
    """Index just past the bracket opened at `start`, or -1 if unbalanced.

    The paren-only `_balanced_call` helpers elsewhere in this package cannot
    walk a function body, which needs braces.
    """
    opener = text[start]
    closer = {"(": ")", "{": "}"}[opener]
    depth = 0
    quote = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'`":
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index + 1
    return -1


def _concise_arrow_body(code: str, start: int) -> str:
    """Text of a braceless arrow body — `() => el.style.top = el.offsetTop`.

    Ends at the first `;`, newline, or depth-0 `,`/closing bracket. Stopping at
    the line break keeps a body from running on into whatever follows and
    borrowing a write that is not the callback's.
    """
    depth = 0
    quote = None
    escaped = False
    for index in range(start, len(code)):
        char = code[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return code[start:index]
            depth -= 1
        elif depth == 0 and char in ";,\n":
            return code[start:index]
    return code[start:]


def _named_function_body(code: str, name: str) -> str:
    """Body of a same-file `function name()` or `name = function/arrow`."""
    escaped = re.escape(name)
    declaration = re.compile(
        rf"\bfunction\s+{escaped}\s*\("
        rf"|\b{escaped}\s*=\s*(?:async\s+)?(?:function\b\s*\w*\s*)?\("
    )
    for match in declaration.finditer(code):
        arguments = _balanced_span(code, code.index("(", match.end() - 1))
        if arguments == -1:
            continue
        arrow = re.compile(r"\s*=>").match(code, arguments)
        body = re.compile(r"\s*").match(code, arrow.end() if arrow else arguments)
        start = body.end()
        if start < len(code) and code[start] == "{":
            end = _balanced_span(code, start)
            if end != -1:
                return code[start:end]
            continue
        # A concise arrow has no brace to walk, and requiring one dropped a
        # genuine `const tick = () => el.style.width = el.offsetWidth` that the
        # old check reported (Codex, agents#70). Anything else that is not a
        # brace here is not this function's body at all -- skip it rather than
        # searching on for some unrelated later block.
        if arrow:
            return _concise_arrow_body(code, start)
    return ""


def _frame_callback_bodies(code: str) -> List[str]:
    """Text of every animation-frame and interval callback body in `code`."""
    bodies: List[str] = []
    for match in _FRAME_SCHEDULER.finditer(code):
        end = _balanced_span(code, match.end() - 1)
        if end == -1:
            continue
        arguments = code[match.end() : end - 1]
        if "function" in arguments or "=>" in arguments:
            bodies.append(arguments)
            continue
        named = _CALLBACK_NAME.match(arguments)
        if named:
            body = _named_function_body(code, named.group(1))
            if body:
                bodies.append(body)
    return bodies


def _thrashes_layout(code: str) -> bool:
    """True when one frame callback both reads and writes layout."""
    if not _FRAME_SCHEDULER.search(code) or not _LAYOUT_READ.search(code):
        return False
    # Comments are dropped first so a `)` or `}` inside one cannot throw off
    # the span walk, and so commented-out code is not read as a measurement.
    stripped = _strip_js_comments(code)
    return any(
        _LAYOUT_READ.search(body) and _LAYOUT_WRITE.search(body)
        for body in _frame_callback_bodies(stripped)
    )


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
        if _thrashes_layout(code):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Animation loop reads layout metrics (possible layout thrashing)",
                    "fix": "Batch DOM reads/writes and avoid sync layout reads inside tight loops.",
                }
            )
        # React Native has no focus() to call on a View and no ARIA attributes;
        # `accessibilityViewIsModal` (with `importantForAccessibility` on
        # Android) is how a native modal scopes the screen reader, and it is
        # the direct equivalent of the web focus trap this looks for
        # (cyberlab-terminal, 2026-08-28).
        if re.search(r"modal|dialog", code, re.IGNORECASE) and not re.search(
            r"focus\(|aria-modal|role=['\"]dialog['\"]"
            # accessibilityViewIsModal is the canonical scoping prop; the
            # Android form only counts at the value that actually hides the
            # background, since importantForAccessibility defaults to "auto".
            r"|accessibilityViewIsModal"
            r"|importantForAccessibility\s*=\s*['\"]no-hide-descendants['\"]",
            code,
        ):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Modal/dialog lacks visible focus management",
                    "fix": "Move focus into dialog and restore focus on close.",
                }
            )
        return {"findings": findings, "total_issues": len(findings)}
