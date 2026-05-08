"""Build the calibration corpus from public ground-truth sources.

Runs each enabled fetcher (KEV, EPSS, exploit-evidence) and writes
JSON artefacts to ``packages/sca/data/calibration/``. Each output
file carries a top-level ``_source`` block documenting:

  * ``license`` — the source's data license (Public Domain /
    Apache-2.0 / CC-BY-4.0)
  * ``url`` — canonical source URL
  * ``fetched_at`` — UTC timestamp of the run
  * ``provenance`` — short prose for the ATTRIBUTION.md cross-reference

The build is idempotent + diff-friendly: re-running on unchanged
sources produces byte-identical output (sorted keys, stable
ordering). The CI workflow opens an auto-PR only when something
actually changed.

License compliance:

  * Tier 1 sources (KEV / NVD / EPSS / OSV / GHSA) are embedded
    verbatim — all are MIT-redistribution-compatible. CC-BY-4.0
    sources (GHSA) carry per-file attribution blocks.
  * Tier 2 sources (Exploit-DB / Metasploit) are reduced to
    boolean signals + reference URLs only. We never ship exploit
    content; only public facts about its existence.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Output directory — relative to repo root in production; tests pass
# their own ``out_dir``.
DEFAULT_OUT_DIR = Path("packages/sca/data/calibration")


@dataclass(frozen=True)
class BuildResult:
    """Per-source build status. The CI workflow surfaces these in
    the auto-PR body so reviewers see what changed."""

    source: str
    written: bool        # True iff the file changed
    error: Optional[str] # populated on fetch failure (workflow logs)
    record_count: int


def build_corpus(
    *,
    out_dir: Optional[Path] = None,
    http: Optional[Any] = None,
    sources: Optional[List[str]] = None,
) -> List[BuildResult]:
    """Refresh the calibration corpus.

    ``sources`` filters which fetchers run. Default is all known
    sources. Each source is independent — one failure doesn't abort
    the rest; the BuildResult list reports per-source status.

    The function never raises on individual source failures —
    captures them in BuildResult.error so the CI workflow can keep
    going. Programmer errors (bad arguments, unwriteable out_dir)
    still raise.
    """
    if out_dir is None:
        out_dir = DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if http is None:
        from core.http import default_client
        http = default_client()

    if sources is None:
        sources = ["kev", "epss"]

    results: List[BuildResult] = []
    for source in sources:
        try:
            if source == "kev":
                results.append(_build_kev(out_dir, http))
            elif source == "epss":
                results.append(_build_epss(out_dir, http))
            else:
                results.append(BuildResult(
                    source=source, written=False,
                    error=f"unknown source {source!r}",
                    record_count=0,
                ))
        except Exception as e:                          # noqa: BLE001
            # Defensive: an individual source breaking shouldn't
            # abort the rest. Logged + surfaced in BuildResult.
            logger.warning(
                "sca.calibration: %s build failed: %s", source, e,
                exc_info=True,
            )
            results.append(BuildResult(
                source=source, written=False,
                error=str(e), record_count=0,
            ))
    return results


# ---------------------------------------------------------------------------
# Per-source builders
# ---------------------------------------------------------------------------


def _build_kev(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the CISA KEV JSON dump and write a flat CVE-keyed
    signal file. Public Domain — embed verbatim."""
    KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    data = http.get_json(KEV_URL)
    signals: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cveID")
        if not cve:
            continue
        signals[cve] = {
            "kev": True,
            "date_added": entry.get("dateAdded"),
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "ransomware_use": (
                entry.get("knownRansomwareCampaignUse") == "Known"
            ),
        }
    output = {
        "_source": {
            "name": "CISA KEV",
            "url": KEV_URL,
            "license": "Public Domain (US Government work)",
            "fetched_at": _utcnow(),
            "provenance": (
                "CISA Known Exploited Vulnerabilities Catalog. "
                "Public Domain; embedded verbatim."
            ),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "kev_signals.json", output, source="kev",
        record_count=len(signals),
    )


def _build_epss(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the daily EPSS scores CSV and emit a sorted JSON of
    ``{cve_id: {epss, percentile, fetched_date}}``.

    EPSS is FIRST.org's free-for-any-use feed. Bulk daily CSV at
    epss.cyentia.com / api.first.org. We use the FIRST API for
    a manageable size (top-N by score) — full bulk is ~30 MB.
    """
    # FIRST API supports filtering by score threshold. Pull
    # everything ≥ 0.05 (5% probability) to keep the file
    # manageable while covering all CVEs that might matter for
    # calibration.
    EPSS_URL = "https://api.first.org/data/v1/epss?epss-gt=0.05&limit=10000"
    data = http.get_json(EPSS_URL)
    signals: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("data", []):
        cve = entry.get("cve")
        if not cve:
            continue
        # Reject entries missing epss / percentile entirely — coercing
        # missing-fields to 0.0 would silently inflate the corpus
        # with no-data rows that look like "this CVE has 0% EPSS".
        if entry.get("epss") is None or entry.get("percentile") is None:
            continue
        try:
            score = float(entry["epss"])
            percentile = float(entry["percentile"])
        except (TypeError, ValueError):
            continue
        signals[cve] = {
            "epss": score,
            "percentile": percentile,
            "as_of": entry.get("date"),
        }
    output = {
        "_source": {
            "name": "FIRST.org EPSS",
            "url": "https://www.first.org/epss/",
            "license": "Free for any use (FIRST.org)",
            "fetched_at": _utcnow(),
            "provenance": (
                "Exploit Prediction Scoring System — FIRST.org. "
                "Filtered to CVEs with EPSS ≥ 0.05 to keep the "
                "corpus tractable."
            ),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "epss_signals.json", output, source="epss",
        record_count=len(signals),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    """ISO-8601 UTC timestamp without microseconds — stable string
    for diff-friendliness."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_if_changed(
    path: Path, data: Dict[str, Any], *, source: str,
    record_count: int,
) -> BuildResult:
    """Write ``data`` to ``path`` only when content differs.

    Diff is computed against the file's current bytes (with
    ``_source.fetched_at`` masked to current run time so the
    timestamp churn doesn't trigger spurious diffs). Returns a
    BuildResult with ``written`` reflecting whether disk changed.
    """
    new_bytes = json.dumps(
        data, indent=2, sort_keys=True, ensure_ascii=False,
    ).encode("utf-8") + b"\n"
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError:
            existing = b""
        if _bytes_equal_excluding_timestamp(existing, new_bytes):
            return BuildResult(
                source=source, written=False, error=None,
                record_count=record_count,
            )
    path.write_bytes(new_bytes)
    return BuildResult(
        source=source, written=True, error=None,
        record_count=record_count,
    )


def _bytes_equal_excluding_timestamp(a: bytes, b: bytes) -> bool:
    """Compare two corpus JSON blobs ignoring ``_source.fetched_at``.

    Without this the corpus would re-write every run (timestamp
    differs even when source content didn't change), churning the
    git history. Match-on-content semantics.
    """
    try:
        da = json.loads(a)
        db = json.loads(b)
    except (json.JSONDecodeError, ValueError):
        return False
    for d in (da, db):
        if isinstance(d, dict) and "_source" in d:
            d["_source"] = {
                k: v for k, v in d["_source"].items()
                if k != "fetched_at"
            }
    return da == db


__all__ = ["BuildResult", "build_corpus"]
