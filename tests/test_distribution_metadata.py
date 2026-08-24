import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_has_pypi_metadata():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]

    assert project["name"] == "rushingtech-agents"
    assert project["version"] == "2.15.0"
    assert project["authors"][0]["name"] == "RushingTech"
    assert project["scripts"]["agents"] == "agents.cli:main"

    urls = project["urls"]
    assert urls["Homepage"] == "https://github.com/mrnickrushing/agents"
    assert urls["Repository"] == "https://github.com/mrnickrushing/agents"
    assert urls["Issues"] == "https://github.com/mrnickrushing/agents/issues"


def test_publish_workflow_builds_and_publishes():
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")

    assert 'tags:\n      - "v*"' in workflow
    assert "python -m build" in workflow
    assert "pypa/gh-action-pypi-publish@" in workflow
    assert "# release/v1" in workflow
    assert "generate_release_notes: true" in workflow
