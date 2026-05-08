"""Tests for the calibration corpus build pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from packages.sca.calibration.build import (
    _bytes_equal_excluding_timestamp,
    _build_kev,
    _build_epss,
    _write_if_changed,
    build_corpus,
)


class _StubHttp:
    """Returns canned responses for known URLs; raises for unknown."""

    def __init__(self, responses: Dict[str, Any]) -> None:
        self._responses = responses

    def get_json(self, url: str) -> Any:
        if url not in self._responses:
            raise AssertionError(f"unexpected URL: {url}")
        return self._responses[url]


# ---------------------------------------------------------------------------
# KEV builder
# ---------------------------------------------------------------------------


def test_build_kev_writes_signal_file(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json": {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-12345",
                    "dateAdded": "2024-08-01",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2024-99999",
                    "dateAdded": "2024-09-15",
                    "vendorProject": "Foo",
                    "product": "Bar",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        },
    })
    result = _build_kev(tmp_path, http)
    assert result.source == "kev"
    assert result.written is True
    assert result.record_count == 2
    data = json.loads((tmp_path / "kev_signals.json").read_text())
    assert "_source" in data
    assert data["_source"]["license"] == \
        "Public Domain (US Government work)"
    assert data["signals"]["CVE-2024-12345"]["kev"] is True
    assert data["signals"]["CVE-2024-12345"]["ransomware_use"] is True
    assert data["signals"]["CVE-2024-99999"]["ransomware_use"] is False


def test_build_kev_skips_entries_without_cveid(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json": {
            "vulnerabilities": [
                {"cveID": "CVE-2024-X"},
                {"vendorProject": "Foo"},  # no cveID
                {"cveID": ""},
            ],
        },
    })
    result = _build_kev(tmp_path, http)
    assert result.record_count == 1


def test_build_kev_idempotent_on_second_run(tmp_path: Path) -> None:
    """Running twice with the same upstream content produces no
    second write — the diff-friendly guard works."""
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-X", "dateAdded": "2024-01-01",
             "vendorProject": "A", "product": "B"},
        ],
    }
    http = _StubHttp({
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json": payload,
    })
    r1 = _build_kev(tmp_path, http)
    r2 = _build_kev(tmp_path, http)
    assert r1.written is True
    assert r2.written is False


# ---------------------------------------------------------------------------
# EPSS builder
# ---------------------------------------------------------------------------


def test_build_epss_writes_signal_file(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://api.first.org/data/v1/epss?epss-gt=0.05&limit=10000": {
            "data": [
                {"cve": "CVE-2024-1", "epss": "0.85",
                 "percentile": "0.99", "date": "2024-09-01"},
                {"cve": "CVE-2024-2", "epss": "0.10",
                 "percentile": "0.5", "date": "2024-09-01"},
            ],
        },
    })
    result = _build_epss(tmp_path, http)
    assert result.record_count == 2
    data = json.loads((tmp_path / "epss_signals.json").read_text())
    assert data["_source"]["license"].startswith("Free")
    assert data["signals"]["CVE-2024-1"]["epss"] == 0.85


def test_build_epss_skips_malformed_scores(tmp_path: Path) -> None:
    http = _StubHttp({
        "https://api.first.org/data/v1/epss?epss-gt=0.05&limit=10000": {
            "data": [
                {"cve": "CVE-2024-OK", "epss": "0.5", "percentile": "0.9"},
                {"cve": "CVE-2024-BAD", "epss": "not-a-number"},
                {"cve": "CVE-2024-NO-EPSS"},
            ],
        },
    })
    result = _build_epss(tmp_path, http)
    assert result.record_count == 1


# ---------------------------------------------------------------------------
# build_corpus orchestrator
# ---------------------------------------------------------------------------


def test_build_corpus_filters_by_sources(tmp_path: Path) -> None:
    """``sources=["kev"]`` runs KEV only; EPSS not attempted."""
    http = _StubHttp({
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json": {"vulnerabilities": []},
    })
    results = build_corpus(out_dir=tmp_path, http=http, sources=["kev"])
    assert [r.source for r in results] == ["kev"]


def test_build_corpus_unknown_source_returns_error(tmp_path: Path) -> None:
    results = build_corpus(
        out_dir=tmp_path, http=_StubHttp({}),
        sources=["bogus"],
    )
    assert len(results) == 1
    assert results[0].source == "bogus"
    assert results[0].error is not None
    assert "unknown source" in results[0].error


def test_build_corpus_one_source_failing_doesnt_abort_others(
    tmp_path: Path,
) -> None:
    """A network failure on KEV doesn't prevent EPSS from running."""
    class _OneFailHttp:
        def get_json(self, url: str):
            if "cisa.gov" in url:
                raise RuntimeError("KEV simulated outage")
            if "first.org" in url:
                return {"data": [
                    {"cve": "CVE-2024-X", "epss": "0.5",
                     "percentile": "0.9", "date": "2024-09-01"},
                ]}
            raise AssertionError(f"unexpected URL: {url}")

    results = build_corpus(
        out_dir=tmp_path, http=_OneFailHttp(),
        sources=["kev", "epss"],
    )
    by_src = {r.source: r for r in results}
    assert by_src["kev"].error is not None
    assert by_src["epss"].written is True
    # EPSS file landed even though KEV blew up.
    assert (tmp_path / "epss_signals.json").exists()


# ---------------------------------------------------------------------------
# Diff-friendliness
# ---------------------------------------------------------------------------


def test_bytes_equal_excluding_timestamp_ignores_fetched_at() -> None:
    a = json.dumps({
        "_source": {"name": "X", "fetched_at": "2024-01-01T00:00:00Z"},
        "signals": {"CVE-2024-1": {"kev": True}},
    }, sort_keys=True).encode()
    b = json.dumps({
        "_source": {"name": "X", "fetched_at": "2024-09-01T12:34:56Z"},
        "signals": {"CVE-2024-1": {"kev": True}},
    }, sort_keys=True).encode()
    assert _bytes_equal_excluding_timestamp(a, b)


def test_bytes_equal_excluding_timestamp_detects_real_change() -> None:
    a = json.dumps({
        "_source": {"name": "X", "fetched_at": "2024-01-01T00:00:00Z"},
        "signals": {"CVE-2024-1": {"kev": True}},
    }, sort_keys=True).encode()
    b = json.dumps({
        "_source": {"name": "X", "fetched_at": "2024-01-01T00:00:00Z"},
        "signals": {"CVE-2024-1": {"kev": True}, "CVE-2024-2": {"kev": True}},
    }, sort_keys=True).encode()
    assert not _bytes_equal_excluding_timestamp(a, b)


def test_write_if_changed_skips_unchanged(tmp_path: Path) -> None:
    payload = {
        "_source": {"name": "X", "fetched_at": "2024-01-01T00:00:00Z"},
        "signals": {"CVE-2024-1": {"kev": True}},
    }
    r1 = _write_if_changed(
        tmp_path / "x.json", payload, source="x", record_count=1,
    )
    assert r1.written is True
    # Re-write with a different fetched_at — should be a no-op.
    payload2 = json.loads(json.dumps(payload))  # deep copy
    payload2["_source"]["fetched_at"] = "2024-12-31T23:59:59Z"
    r2 = _write_if_changed(
        tmp_path / "x.json", payload2, source="x", record_count=1,
    )
    assert r2.written is False
