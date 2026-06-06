from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.threat_model import (
    blank_for_project,
    diff_context_map,
    enrich_from_context_map,
    from_context_map,
    link_verified_outcomes,
    lint_model,
    load_for_target,
    load_model,
    project_threat_model_paths,
    prompt_context,
    render_report,
    save_model,
)
from core.verified_outcome.types import Oracle, OutcomeStatus, VerifiedOutcome


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
    assert model.version == 2
    assert model.data_flows[0]["id"] == "DF-001"
    assert model.threats[0]["status"] == "needs_evidence"
    assert model.threats[0]["risk_score"] >= 90
    assert any(c["id"] == "CTRL-004" for c in model.controls)


def test_prompt_context_escapes_control_characters(tmp_path):
    project = _project(tmp_path)
    model = blank_for_project(project)
    model.focus_areas = ["HTTP header\x1b[2J to sink"]

    rendered = prompt_context(model)

    assert "\x1b" not in rendered
    assert "\\x1b" in rendered


def test_lint_diff_and_report_surface_threat_model_health(tmp_path):
    project = _project(tmp_path)
    context_map = {
        "entry_points": [{"id": "EP-001", "name": "POST /login"}],
        "trust_boundaries": [{"id": "TB-001", "name": "browser to API"}],
        "sink_details": [{"id": "SINK-001", "type": "sql query", "file": "auth.py", "line": 12}],
        "unchecked_flows": [{
            "id": "UF-001",
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No parameter binding",
            "severity": "high",
        }],
    }
    model = from_context_map(project, context_map)

    issues = lint_model(model)
    drift = diff_context_map(model, {
        **context_map,
        "entry_points": context_map["entry_points"] + [{"id": "EP-002", "name": "GET /debug"}],
    })
    report = render_report(model, lint=issues, drift=drift)

    assert not any(i["severity"] == "error" for i in issues)
    assert drift["is_drifted"] is True
    assert "GET /debug" in "\n".join(drift["new_entry_points"])
    assert "Threat Model Report" in report
    assert "Top Threats" in report
    assert "██████" in report
    assert "__VERSION__" not in report


def test_verified_outcomes_update_matching_threat_status(tmp_path):
    project = _project(tmp_path)
    model = from_context_map(project, {
        "entry_points": [{"id": "EP-001", "name": "GET /hello"}],
        "sink_details": [{"id": "SINK-001", "type": "subprocess", "file": "hello.py"}],
        "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "severity": "critical",
        }],
    })
    outcome = VerifiedOutcome(
        finding_id="SINK-001",
        oracle=Oracle.SANDBOX,
        status=OutcomeStatus.VERIFIED,
        reproducible=True,
        evidence={"signal": "SIGABRT"},
        cwe_id="CWE-78",
        file="hello.py",
    )

    link_verified_outcomes(model, [outcome])

    assert model.threats[0]["status"] == "confirmed"
    assert model.threats[0]["evidence_ids"]
    assert any(ev["oracle"] == "sandbox" for ev in model.evidence)


def test_enrich_from_context_map_preserves_operator_prose_but_adds_v2_ledger(tmp_path):
    project = _project(tmp_path)
    model = blank_for_project(project)
    model.version = 1
    model.summary = "operator wording stays"
    model.focus_areas = ["keep this"]
    model.threats = []
    model.controls = []

    enrich_from_context_map(model, {
        "entry_points": [{"id": "EP-001", "name": "GET /search"}],
        "sink_details": [{"id": "SINK-001", "type": "template render", "file": "posts.py"}],
        "unchecked_flows": [{
            "entry_point": "EP-001",
            "sink": "SINK-001",
            "missing_boundary": "No escaping before template render",
            "severity": "critical",
        }],
    })

    assert model.version == 2
    assert model.summary == "operator wording stays"
    assert model.focus_areas == ["keep this"]
    assert model.threats
    assert model.threats[0]["category"] == "server_side_template_injection"
    assert model.controls


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
