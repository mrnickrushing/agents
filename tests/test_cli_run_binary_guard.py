"""Regression tests for `agents run --file` refusing binary input."""

import subprocess
import sys


def test_run_file_refuses_binary(tmp_path):
    binary = tmp_path / "asset.png"
    binary.write_bytes(b"PNG\x00\x00\x01\x00" + b"\xff" * 64)
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agents.cli",
            "run",
            "security_audit",
            "audit_xss_patterns",
            "--file",
            f"code={binary}",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "binary" in (proc.stdout + proc.stderr).lower()


def test_run_file_still_accepts_text(tmp_path):
    source = tmp_path / "route.js"
    source.write_text("router.get('/x', (req, res) => res.send(req.query.q));\n")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agents.cli",
            "run",
            "code_review",
            "review_express_route",
            "--file",
            f"code={source}",
            "--arg",
            "route_path=/x",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "total_issues" in proc.stdout
