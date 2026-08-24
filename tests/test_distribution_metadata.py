import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_has_pypi_metadata():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]

    assert project["name"] == "rushingtech-agents"
    assert project["version"] == "2.16.0"
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


def test_web_extra_includes_production_server():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    web = data["project"]["optional-dependencies"]["web"]
    assert any(dep.startswith("flask") for dep in web)
    assert any(dep.startswith("gunicorn") for dep in web)


def test_railway_config_targets_server_image_and_served_healthcheck():
    config = tomllib.loads((ROOT / "railway.toml").read_text(encoding="utf-8"))
    assert config["build"]["dockerfilePath"] == "Dockerfile.server"
    healthcheck = config["deploy"]["healthcheckPath"]
    # The path Railway probes must be one the service actually serves —
    # the same invariant config_audit enforces on every scanned project.
    server = (ROOT / "agents/server.py").read_text(encoding="utf-8")
    assert f'"{healthcheck}"' in server


def test_server_dockerfile_runs_service_as_non_root():
    dockerfile = (ROOT / "Dockerfile.server").read_text(encoding="utf-8")
    assert "USER agents" in dockerfile
    assert 'CMD ["agents", "serve"]' in dockerfile
    assert '".[web]"' in dockerfile
    assert "XDG_STATE_HOME=/data" in dockerfile


def test_container_workflow_publishes_both_images():
    workflow = (ROOT / ".github/workflows/publish-container.yml").read_text(
        encoding="utf-8"
    )
    assert workflow.count("docker/build-push-action@") == 2
    assert "file: Dockerfile.server" in workflow
    assert "ghcr.io/${{ github.repository }}-server" in workflow
