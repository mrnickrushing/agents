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
        "import { hasPremium, purchasePackage } from \"@/lib/revenuecat\";\n"
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
