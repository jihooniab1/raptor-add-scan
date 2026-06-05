"""Project-level threat model artefact.

The threat model is operator-owned context, not scanner output. It gives
RAPTOR a stable view of assets, trust boundaries, threat assumptions,
in-scope bug classes, out-of-scope noise, focus areas, and known bug shapes
before an LLM starts reading target code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from core.json import load_json, save_json
from core.security.log_sanitisation import escape_nonprintable

SCHEMA_VERSION = 1
JSON_FILENAME = "threat-model.json"
MARKDOWN_FILENAME = "THREAT_MODEL.md"


@dataclass
class ThreatModel:
    """Canonical project threat model.

    Kept deliberately simple: every list is prose-first so operators can keep
    it useful without fighting a giant schema, while the keys are stable enough
    for prompts, reports, and CI to consume.
    """

    project_name: str
    target: str
    summary: str = ""
    assets: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    trusted_inputs: list[str] = field(default_factory=list)
    untrusted_inputs: list[str] = field(default_factory=list)
    in_scope_vuln_classes: list[str] = field(default_factory=list)
    out_of_scope_vuln_classes: list[str] = field(default_factory=list)
    focus_areas: list[str] = field(default_factory=list)
    known_bug_shapes: list[str] = field(default_factory=list)
    verification_expectations: list[str] = field(default_factory=list)
    patch_validation_expectations: list[str] = field(default_factory=list)
    notes: str = ""
    source: str = "operator"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "project_name": self.project_name,
            "target": self.target,
            "summary": self.summary,
            "assets": list(self.assets),
            "entry_points": list(self.entry_points),
            "trust_boundaries": list(self.trust_boundaries),
            "trusted_inputs": list(self.trusted_inputs),
            "untrusted_inputs": list(self.untrusted_inputs),
            "in_scope_vuln_classes": list(self.in_scope_vuln_classes),
            "out_of_scope_vuln_classes": list(self.out_of_scope_vuln_classes),
            "focus_areas": list(self.focus_areas),
            "known_bug_shapes": list(self.known_bug_shapes),
            "verification_expectations": list(self.verification_expectations),
            "patch_validation_expectations": list(self.patch_validation_expectations),
            "notes": self.notes,
            "source": self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThreatModel":
        def _list(key: str) -> list[str]:
            return _coerce_str_list(data.get(key))

        now = datetime.now(timezone.utc).isoformat()
        return cls(
            version=int(data.get("version") or SCHEMA_VERSION),
            project_name=str(data.get("project_name") or ""),
            target=str(data.get("target") or ""),
            summary=str(data.get("summary") or ""),
            assets=_list("assets"),
            entry_points=_list("entry_points"),
            trust_boundaries=_list("trust_boundaries"),
            trusted_inputs=_list("trusted_inputs"),
            untrusted_inputs=_list("untrusted_inputs"),
            in_scope_vuln_classes=_list("in_scope_vuln_classes"),
            out_of_scope_vuln_classes=_list("out_of_scope_vuln_classes"),
            focus_areas=_list("focus_areas"),
            known_bug_shapes=_list("known_bug_shapes"),
            verification_expectations=_list("verification_expectations"),
            patch_validation_expectations=_list("patch_validation_expectations"),
            notes=str(data.get("notes") or ""),
            source=str(data.get("source") or "operator"),
            created_at=str(data.get("created_at") or now),
            updated_at=str(data.get("updated_at") or now),
        )


def project_threat_model_paths(project: Any) -> tuple[Path, Path]:
    """Return ``(json_path, markdown_path)`` for a project-like object."""
    output = Path(project.output_dir)
    return output / JSON_FILENAME, output / MARKDOWN_FILENAME


def blank_for_project(project: Any) -> ThreatModel:
    """Create an operator-editable starter model for ``project``."""
    return ThreatModel(
        project_name=project.name,
        target=project.target,
        summary=(
            "Document what we are protecting, who can influence inputs, "
            "and which bug classes matter for this target."
        ),
        assets=[
            "Primary application behaviour and data handled by the target",
            "Secrets, credentials, tokens, and deployment configuration",
            "Build, release, and dependency integrity",
        ],
        trusted_inputs=[
            "Explicitly list config, internal services, or authenticated actors that are trusted here",
        ],
        untrusted_inputs=[
            "External requests, files, messages, dependency metadata, and user-controlled payloads",
        ],
        in_scope_vuln_classes=[
            "Injection and command execution",
            "Authentication and authorisation bypass",
            "Unsafe deserialisation and parser confusion",
            "Memory corruption where native code or binaries are in scope",
            "Supply-chain and dependency compromise paths",
        ],
        out_of_scope_vuln_classes=[
            "Issues requiring already-compromised privileged operators unless stated otherwise",
            "Purely theoretical findings with no reachable attacker-controlled path",
        ],
        verification_expectations=[
            "Prefer oracle-backed evidence: sandbox replay, CodeQL proof/refutation, fuzzer crash, or live web confirmation",
            "A finding is not confirmed just because an LLM says it looks plausible",
        ],
        patch_validation_expectations=[
            "Replay the original proof of concept after a patch",
            "Run the relevant test/build path",
            "Run a short re-attack or variant-hunt pass for high-impact fixes",
        ],
    )


def from_context_map(project: Any, context_map: dict[str, Any]) -> ThreatModel:
    """Build a starter model from an ``/understand`` context-map."""
    model = blank_for_project(project)
    model.source = "context-map"
    model.entry_points = _summaries_from_entries(
        context_map.get("entry_points") or context_map.get("sources") or [],
        default_label="entry",
    )
    model.trust_boundaries = _summaries_from_entries(
        context_map.get("trust_boundaries") or [],
        default_label="boundary",
    )
    sinks = _summaries_from_entries(
        context_map.get("sink_details") or context_map.get("sinks") or [],
        default_label="sink",
    )
    model.focus_areas = derive_focus_areas(model.entry_points, sinks)
    unchecked_flows = _summaries_from_unchecked_flows(
        context_map.get("unchecked_flows") or [],
        context_map.get("entry_points") or [],
        context_map.get("sink_details") or [],
    )
    secrets = _summaries_from_entries(
        context_map.get("hardcoded_secrets") or [],
        default_label="secret",
    )
    model.focus_areas = _dedup(unchecked_flows + model.focus_areas + secrets)
    model.known_bug_shapes.extend(unchecked_flows)
    model.known_bug_shapes.extend(
        f"Hardcoded secret or backdoor credential: {s}" for s in secrets
    )
    if sinks:
        model.known_bug_shapes.extend(
            f"Trace attacker-controlled entry points into sink: {s}"
            for s in sinks[:12]
        )
    model.updated_at = datetime.now(timezone.utc).isoformat()
    return model


def derive_focus_areas(entry_points: Iterable[str], sinks: Iterable[str]) -> list[str]:
    """Return stable focus areas from mapped entries/sinks."""
    out: list[str] = []
    for value in list(entry_points)[:8]:
        out.append(f"Entry point: {value}")
    for value in list(sinks)[:8]:
        out.append(f"Sensitive sink: {value}")
    return _dedup(out)


def load_model(path: Path) -> Optional[ThreatModel]:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    return ThreatModel.from_dict(data)


def save_model(model: ThreatModel, json_path: Path, markdown_path: Path) -> None:
    model.updated_at = datetime.now(timezone.utc).isoformat()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(json_path, model.to_dict())
    markdown_path.write_text(render_markdown(model), encoding="utf-8")


def render_markdown(model: ThreatModel) -> str:
    """Render an operator-editable ``THREAT_MODEL.md``."""
    sections = [
        "# Threat Model",
        "",
        f"Project: {model.project_name}",
        f"Target: {model.target}",
        f"Source: {model.source}",
        f"Updated: {model.updated_at}",
        "",
        "## Summary",
        "",
        model.summary or "TBC.",
        "",
        _render_list("Assets", model.assets),
        _render_list("Entry Points", model.entry_points),
        _render_list("Trust Boundaries", model.trust_boundaries),
        _render_list("Trusted Inputs", model.trusted_inputs),
        _render_list("Untrusted Inputs", model.untrusted_inputs),
        _render_list("In Scope Vulnerability Classes", model.in_scope_vuln_classes),
        _render_list("Out Of Scope Vulnerability Classes", model.out_of_scope_vuln_classes),
        _render_list("Focus Areas", model.focus_areas),
        _render_list("Known Bug Shapes", model.known_bug_shapes),
        _render_list("Verification Expectations", model.verification_expectations),
        _render_list("Patch Validation Expectations", model.patch_validation_expectations),
    ]
    if model.notes.strip():
        sections.extend(["## Notes", "", model.notes.strip(), ""])
    return "\n".join(sections).rstrip() + "\n"


def prompt_context(model: ThreatModel, *, max_items: int = 8) -> str:
    """Compact trusted context block for LLM prompts."""
    lines = [
        "Project threat model context:",
        f"- Summary: {escape_nonprintable(model.summary or 'not documented')}",
    ]
    for label, values in (
        ("Assets", model.assets),
        ("Trusted inputs", model.trusted_inputs),
        ("Untrusted inputs", model.untrusted_inputs),
        ("In-scope vuln classes", model.in_scope_vuln_classes),
        ("Out-of-scope vuln classes", model.out_of_scope_vuln_classes),
        ("Focus areas", model.focus_areas),
        ("Known bug shapes", model.known_bug_shapes),
        ("Verification expectations", model.verification_expectations),
        ("Patch validation expectations", model.patch_validation_expectations),
    ):
        if values:
            lines.append(f"- {label}: {escape_nonprintable('; '.join(values[:max_items]))}")
    return "\n".join(lines)


def load_for_target(target: Path) -> Optional[ThreatModel]:
    """Find the project-owned threat model for ``target`` if one exists."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        project = mgr.find_project_for_target(str(target))
        if project is None:
            active = mgr.get_active()
            candidate = mgr.load(active) if active else None
            if candidate and _same_path(candidate.target, target):
                project = candidate
        if project is None:
            return None
        configured = getattr(project, "threat_model_path", "")
        json_path = Path(configured) if configured else project_threat_model_paths(project)[0]
        return load_model(json_path)
    except Exception:
        return None


def _render_list(title: str, values: list[str]) -> str:
    lines = [f"## {title}", ""]
    if values:
        lines.extend(f"- {v}" for v in values)
    else:
        lines.append("- TBC")
    lines.append("")
    return "\n".join(lines)


def _summaries_from_entries(entries: Any, *, default_label: str) -> list[str]:
    out: list[str] = []
    if not isinstance(entries, list):
        return out
    for i, entry in enumerate(entries):
        if isinstance(entry, str):
            out.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        name = (
            entry.get("name")
            or entry.get("id")
            or entry.get("entry")
            or entry.get("boundary")
            or entry.get("operation")
            or f"{default_label}-{i}"
        )
        location = entry.get("file") or entry.get("path") or entry.get("location")
        line = entry.get("line")
        trust = entry.get("trust") or entry.get("trust_level")
        summary = str(name)
        if location:
            summary += f" ({location})"
            if line and ":" not in str(location):
                summary += f":{line}"
        if trust:
            summary += f" - {trust}"
        out.append(summary)
    return _dedup(out)


def _summaries_from_unchecked_flows(
    flows: Any,
    entries: Any,
    sinks: Any,
) -> list[str]:
    if not isinstance(flows, list):
        return []
    entries_by_id = {
        str(e.get("id")): e for e in entries
        if isinstance(e, dict) and e.get("id")
    } if isinstance(entries, list) else {}
    sinks_by_id = {
        str(s.get("id")): s for s in sinks
        if isinstance(s, dict) and s.get("id")
    } if isinstance(sinks, list) else {}

    out: list[str] = []
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        entry_id = str(flow.get("entry_point") or "")
        sink_id = str(flow.get("sink") or "")
        entry = entries_by_id.get(entry_id, {})
        sink = sinks_by_id.get(sink_id, {})
        entry_label = entry_id
        if entry:
            method = entry.get("method")
            route = entry.get("path")
            if method and route:
                entry_label = f"{entry_id} {method} {route}"
        sink_label = sink_id
        if sink:
            loc = sink.get("file") or "?"
            line = sink.get("line")
            sink_type = sink.get("type") or "sink"
            sink_label = f"{sink_id} {sink_type} at {loc}{':' + str(line) if line else ''}"
        issue = flow.get("missing_boundary") or flow.get("notes") or "unchecked flow"
        severity = flow.get("severity")
        label = f"{entry_label} -> {sink_label}: {issue}"
        if severity:
            label += f" ({severity})"
        out.append(label)
    return _dedup(out)


def _same_path(left: str, right: Path) -> bool:
    try:
        return Path(left).expanduser().resolve() == right.expanduser().resolve()
    except Exception:
        return str(left) == str(right)


def _dedup(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = str(v).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _coerce_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
