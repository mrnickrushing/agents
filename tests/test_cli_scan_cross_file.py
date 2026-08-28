import json
import os

from agents.cli import _inline_local_imports
from agents.mobile_deploy import MobileDeployAgent


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def test_inline_local_imports_follows_alias_import_via_tsconfig(tmp_path):
    """A `@/lib/x` import should resolve using tsconfig's `paths` mapping
    (e.g. "@/*" -> "./app/*"), not assumed to sit at the project root —
    Expo Router projects commonly alias into the app/ subdirectory."""
    root = str(tmp_path)
    _write(os.path.join(root, "package.json"), "{}")
    _write(
        os.path.join(root, "tsconfig.json"),
        json.dumps({"compilerOptions": {"paths": {"@/*": ["./app/*"]}}}),
    )
    _write(
        os.path.join(root, "app", "lib", "revenuecat.ts"),
        "export function ensureRevenueCatConfigured() { Purchases.configure({ apiKey }); }\n"
        "export function hasPremium(info) { return info.entitlements.active['premium']; }\n",
    )
    caller_path = os.path.join(root, "app", "paywall.tsx")
    caller_content = (
        'import { hasPremium, purchasePackage } from "@/lib/revenuecat";\n'
        "async function buy(pkg) {\n"
        "  const info = await purchasePackage(pkg);\n"
        "  if (hasPremium(info)) { /* ... */ }\n"
        "}\n"
    )
    _write(caller_path, caller_content)

    combined = _inline_local_imports(caller_path, caller_content, root)

    assert "Purchases.configure" in combined
    assert "entitlements" in combined

    agent = MobileDeployAgent()
    result = agent._review_revenuecat_setup(combined)
    severities = [f["severity"] for f in result["findings"]]
    assert "HIGH" not in severities


def test_inline_local_imports_relative_path(tmp_path):
    root = str(tmp_path)
    _write(os.path.join(root, "package.json"), "{}")
    _write(os.path.join(root, "lib", "helper.ts"), "export const X = 1;\n")
    caller_path = os.path.join(root, "routes", "thing.ts")
    caller_content = 'import { X } from "../lib/helper";\n'
    _write(caller_path, caller_content)

    combined = _inline_local_imports(caller_path, caller_content, root)
    assert "export const X = 1;" in combined


def test_inline_local_imports_no_matching_import_is_noop(tmp_path):
    root = str(tmp_path)
    caller_path = os.path.join(root, "a.ts")
    content = "import { z } from 'zod';\nconst x = 1;\n"
    _write(caller_path, content)
    combined = _inline_local_imports(caller_path, content, root)
    assert combined == content


def test_inline_local_imports_python_package_resolves_to_init(tmp_path):
    """`from app.lib import apple` should resolve to app/lib/__init__.py
    (a package), not just app/lib.py (a same-named module) — and the
    inlined marker comment should use Python's "#" syntax, not "//"."""
    root = str(tmp_path)
    _write(
        os.path.join(root, "app", "lib", "__init__.py"),
        "def verify_apple_identity_token(): return jwks_verify()\n",
    )
    caller_path = os.path.join(root, "app", "auth.py")
    caller_content = "from app.lib import verify_apple_identity_token\n"
    _write(caller_path, caller_content)

    combined = _inline_local_imports(caller_path, caller_content, root)

    assert "jwks_verify" in combined
    assert "\n# --- imported from" in combined
    assert "// ---" not in combined


def test_nested_router_layout_sees_the_parent_layouts_error_boundary(tmp_path):
    """expo-router and the Next.js App Router nest layouts by file system,
    not imports: app/_layout.tsx wraps app/(tabs)/_layout.tsx without either
    file referencing the other. Judged alone, the nested layout looked like
    it was missing an ErrorBoundary the parent already provides — reported
    on both sugarhaus and VibeMaps (2026-08-28)."""
    from agents.cli import _ancestor_layout_sources
    from agents.infra_monitor import InfraMonitorAgent

    root = str(tmp_path)
    _write(
        os.path.join(root, "app", "_layout.tsx"),
        "import { ErrorBoundary } from '@/components/ErrorBoundary';\n"
        "export default function Root() { return <ErrorBoundary><Stack /></ErrorBoundary>; }\n",
    )
    nested_path = os.path.join(root, "app", "(tabs)", "_layout.tsx")
    nested = "export default function Tabs() { return <Tabs />; }\n"
    _write(nested_path, nested)

    agent = InfraMonitorAgent()
    alone = agent._review_error_boundary_coverage(nested)["findings"]
    assert any("No ErrorBoundary" in f["issue"] for f in alone)

    combined = nested + _ancestor_layout_sources(nested_path, root)
    with_parent = agent._review_error_boundary_coverage(combined)["findings"]
    assert not any("No ErrorBoundary" in f["issue"] for f in with_parent)


def test_nested_layout_is_still_flagged_when_no_ancestor_has_a_boundary(tmp_path):
    from agents.cli import _ancestor_layout_sources
    from agents.infra_monitor import InfraMonitorAgent

    root = str(tmp_path)
    _write(
        os.path.join(root, "app", "_layout.tsx"),
        "export default function Root() { return <Stack />; }\n",
    )
    nested_path = os.path.join(root, "app", "(tabs)", "_layout.tsx")
    nested = "export default function Tabs() { return <Tabs />; }\n"
    _write(nested_path, nested)

    combined = nested + _ancestor_layout_sources(nested_path, root)
    findings = InfraMonitorAgent()._review_error_boundary_coverage(combined)["findings"]
    assert any("No ErrorBoundary" in f["issue"] for f in findings)


def test_ancestor_layout_lookup_ignores_non_layout_files_and_the_root_layout(tmp_path):
    from agents.cli import _ancestor_layout_sources

    root = str(tmp_path)
    _write(
        os.path.join(root, "app", "_layout.tsx"),
        "import { ErrorBoundary } from '@/x';\n",
    )
    _write(os.path.join(root, "app", "index.tsx"), "export default function I() {}\n")

    # A screen is not a layout — nothing is pulled in for it.
    assert _ancestor_layout_sources(os.path.join(root, "app", "index.tsx"), root) == ""
    # The outermost layout has no ancestor layout above it.
    assert (
        _ancestor_layout_sources(os.path.join(root, "app", "_layout.tsx"), root) == ""
    )


def test_ancestor_layout_lookup_stops_at_the_repository_root(tmp_path):
    """A layout file outside `root` must not pull in layouts from above it."""
    from agents.cli import _ancestor_layout_sources

    _write(
        os.path.join(str(tmp_path), "outside_layout.tsx"),
        "import { ErrorBoundary } from '@/x';\n",
    )
    root = os.path.join(str(tmp_path), "repo")
    nested_path = os.path.join(root, "app", "(tabs)", "_layout.tsx")
    _write(nested_path, "export default function Tabs() {}\n")
    assert _ancestor_layout_sources(nested_path, root) == ""


def test_nextjs_app_router_layout_naming_is_supported(tmp_path):
    from agents.cli import _ancestor_layout_sources

    root = str(tmp_path)
    _write(
        os.path.join(root, "app", "layout.tsx"),
        "import { ErrorBoundary } from '@/x';\nexport default function L() {}\n",
    )
    nested_path = os.path.join(root, "app", "dashboard", "layout.tsx")
    _write(nested_path, "export default function D() {}\n")
    assert "ErrorBoundary" in _ancestor_layout_sources(nested_path, root)
