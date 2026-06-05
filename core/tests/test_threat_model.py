from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.threat_model import (
    blank_for_project,
    from_context_map,
    load_for_target,
    load_model,
    project_threat_model_paths,
    prompt_context,
    save_model,
)


def _project(tmp_path: Path, *, name: str = "demo", target: str | None = None):
    return SimpleNamespace(
        name=name,
        target=target or str(tmp_path / "target"),
        output_dir=str(tmp_path / "out"),
    )


def test_blank_model_roundtrips_to_json_and_markdown(tmp_path):
    project = _project(tmp_path)
    model = blank_for_project(project)
    json_path, markdown_path = project_threat_model_paths(project)

    save_model(model, json_path, markdown_path)

    loaded = load_model(json_path)
    assert loaded is not None
    assert loaded.project_name == "demo"
    assert "Injection and command execution" in loaded.in_scope_vuln_classes
    assert markdown_path.read_text(encoding="utf-8").startswith("# Threat Model")


def test_context_map_seeds_focus_areas_and_bug_shapes(tmp_path):
    project = _project(tmp_path)
    model = from_context_map(project, {
        "entry_points": [{"name": "POST /login", "file": "routes.py"}],
        "trust_boundaries": [{"name": "browser to API", "trust": "external"}],
        "sinks": [{"name": "subprocess.run", "file": "worker.py"}],
        "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No auth before shell execution",
            "severity": "critical",
        }],
        "hardcoded_secrets": [{
            "name": "MASTER_PASSWORD",
            "file": "auth.py",
            "line": 7,
        }],
    })

    assert "Entry point: POST /login (routes.py)" in model.focus_areas
    assert "Sensitive sink: subprocess.run (worker.py)" in model.focus_areas
    assert model.trust_boundaries == ["browser to API - external"]
    assert model.known_bug_shapes[0].endswith("No auth before shell execution (critical)")
    assert any("Hardcoded secret" in item for item in model.known_bug_shapes)


def test_prompt_context_escapes_control_characters(tmp_path):
    project = _project(tmp_path)
    model = blank_for_project(project)
    model.focus_areas = ["HTTP header\x1b[2J to sink"]

    rendered = prompt_context(model)

    assert "\x1b" not in rendered
    assert "\\x1b" in rendered


def test_load_for_target_does_not_use_unrelated_active_project(tmp_path):
    target = tmp_path / "target-a"
    other = tmp_path / "target-b"
    target.mkdir()
    other.mkdir()
    project = _project(tmp_path, target=str(other))

    class FakeManager:
        def find_project_for_target(self, _target):
            return None

        def get_active(self):
            return "active"

        def load(self, _name):
            return project

    with patch("core.project.project.ProjectManager", return_value=FakeManager()):
        assert load_for_target(target) is None
