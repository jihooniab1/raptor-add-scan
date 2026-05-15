"""Tests for the wheel-matrix builder + cross-check engine."""

from __future__ import annotations

from packages.sca.platform_matrix import PlatformPair, ProjectPlatformMatrix
from packages.sca.platform_matrix.glibc_db import LibcVersion
from packages.sca.wheel_compat.compat import (
    check_compat, wheel_matrix_for_version,
)


class _StubPyPI:
    """Returns the canned metadata dict for matching name lookups."""
    def __init__(self, packages: dict):
        self._p = packages

    def get_metadata(self, name: str):
        return self._p.get(name)


def _pair(arch: str, family: str, ver: tuple) -> PlatformPair:
    return PlatformPair(
        arch=arch, libc=LibcVersion(family, ver),
        source="test",
    )


# ---------------------------------------------------------------------------
# wheel_matrix_for_version
# ---------------------------------------------------------------------------

def test_wheel_matrix_for_version_extracts_tags() -> None:
    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0.tar.gz"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "z3-solver", "4.16.0.0")
    assert wm is not None
    assert wm.has_sdist is True
    assert len(wm.wheel_tags) == 2
    arches = sorted(t.arch for t in wm.wheel_tags)
    assert arches == ["aarch64", "x86_64"]


def test_wheel_matrix_unknown_version_none() -> None:
    pypi = _StubPyPI({"foo": {"releases": {"1.0": []}}})
    assert wheel_matrix_for_version(pypi, "foo", "9.9.9") is None


def test_wheel_matrix_pkg_not_on_pypi_none() -> None:
    pypi = _StubPyPI({})
    assert wheel_matrix_for_version(pypi, "ghost", "1.0") is None


# ---------------------------------------------------------------------------
# check_compat — the z3-solver canonical case
# ---------------------------------------------------------------------------

def test_z3_solver_aarch64_bookworm_libc_too_new() -> None:
    """The canonical bite: z3-solver==4.16.0.0 ships
    manylinux_2_38_aarch64 + manylinux_2_17_x86_64. A
    bookworm-based devcontainer (glibc 2.36) on aarch64 has no
    fit; x86_64 fits the 2_17 fallback."""
    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "z3-solver", "4.16.0.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("x86_64", "glibc", (2, 36)))
    matrix.add(_pair("aarch64", "glibc", (2, 36)))
    verdicts = check_compat(matrix, wm)
    by_arch = {v.pair.arch: v for v in verdicts}
    assert by_arch["x86_64"].verdict == "ok"
    assert by_arch["aarch64"].verdict == "libc_too_new"
    assert "glibc 2.38" in by_arch["aarch64"].reason
    assert "glibc 2.36" in by_arch["aarch64"].reason


def test_compat_ok_when_libc_satisfied() -> None:
    """A trixie-based devcontainer (glibc 2.39) satisfies
    manylinux_2_38 on aarch64."""
    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "z3-solver", "4.16.0.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 39)))
    verdicts = check_compat(matrix, wm)
    assert verdicts[0].verdict == "ok"


def test_compat_pure_python_ok_everywhere() -> None:
    """A pure-Python ``any`` wheel satisfies every platform pair."""
    pypi = _StubPyPI({
        "requests": {
            "releases": {
                "2.31.0": [
                    {"filename": "requests-2.31.0-py3-none-any.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "requests", "2.31.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("x86_64", "glibc", (2, 31)))
    matrix.add(_pair("aarch64", "glibc", (2, 28)))
    matrix.add(_pair("ppc64le", "glibc", (2, 17)))
    verdicts = check_compat(matrix, wm)
    assert all(v.verdict == "ok" for v in verdicts)


def test_compat_arch_gap() -> None:
    """Package ships only x86_64 wheels + no sdist; aarch64 has
    no installable option."""
    pypi = _StubPyPI({
        "amdonly": {
            "releases": {
                "1.0": [
                    {"filename":
                     "amdonly-1.0-py3-none-manylinux_2_17_x86_64.whl"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "amdonly", "1.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 31)))
    verdicts = check_compat(matrix, wm)
    assert verdicts[0].verdict == "arch_gap"


def test_compat_sdist_only_when_no_wheel_for_arch() -> None:
    """No matching wheel but sdist exists → sdist_only (needs
    build env in the install path)."""
    pypi = _StubPyPI({
        "amdonly": {
            "releases": {
                "1.0": [
                    {"filename":
                     "amdonly-1.0-py3-none-manylinux_2_17_x86_64.whl"},
                    {"filename": "amdonly-1.0.tar.gz"},
                ],
            },
        },
    })
    wm = wheel_matrix_for_version(pypi, "amdonly", "1.0")
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 31)))
    verdicts = check_compat(matrix, wm)
    assert verdicts[0].verdict == "sdist_only"


def test_compat_uninstallable_no_wheels_no_sdist() -> None:
    pypi = _StubPyPI({
        "ghost": {"releases": {"1.0": []}},
    })
    wm = wheel_matrix_for_version(pypi, "ghost", "1.0")
    assert wm is None  # no version data → no compat answer


# ---------------------------------------------------------------------------
# find_compatible_version — recommendation engine
# ---------------------------------------------------------------------------

def test_find_compatible_version_walks_back_to_z3_pre_2_38() -> None:
    """The canonical z3-solver case: 4.16.0.0 needs glibc 2.38 on
    aarch64; an earlier version with manylinux_2_34 wheels would
    satisfy a glibc 2.36 base. The recommendation engine finds
    that earlier version."""
    from packages.sca.wheel_compat.compat import find_compatible_version

    pypi = _StubPyPI({
        "z3-solver": {
            "releases": {
                "4.16.0.0": [
                    {"filename":
                     "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl"},
                ],
                "4.15.8.0": [
                    {"filename":
                     "z3_solver-4.15.8.0-py3-none-manylinux_2_34_aarch64.whl"},
                ],
                "4.15.0.0": [
                    {"filename":
                     "z3_solver-4.15.0.0-py3-none-manylinux_2_17_aarch64.whl"},
                ],
            },
        },
    })
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 36)))
    rec = find_compatible_version(pypi, "z3-solver", matrix)
    # Highest-compatible: 4.15.8.0 (manylinux_2_34 fits glibc 2.36).
    assert rec == "4.15.8.0"


def test_find_compatible_version_none_when_no_match() -> None:
    """Every released version requires too-new libc → no
    recommendation."""
    from packages.sca.wheel_compat.compat import find_compatible_version

    pypi = _StubPyPI({
        "newpkg": {
            "releases": {
                "2.0.0": [{"filename":
                          "newpkg-2.0.0-py3-none-manylinux_2_38_aarch64.whl"}],
                "1.0.0": [{"filename":
                          "newpkg-1.0.0-py3-none-manylinux_2_39_aarch64.whl"}],
            },
        },
    })
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("aarch64", "glibc", (2, 36)))
    assert find_compatible_version(pypi, "newpkg", matrix) is None


def test_find_compatible_version_skips_pre_releases() -> None:
    """Pre-release versions (``rc1``, ``b1``, ``.dev0``) are
    skipped — operators want stable recs."""
    from packages.sca.wheel_compat.compat import find_compatible_version

    pypi = _StubPyPI({
        "preview": {
            "releases": {
                "2.0.0rc1": [{"filename":
                              "preview-2.0.0rc1-py3-none-any.whl"}],
                "1.0.0": [{"filename":
                           "preview-1.0.0-py3-none-any.whl"}],
            },
        },
    })
    matrix = ProjectPlatformMatrix()
    matrix.add(_pair("x86_64", "glibc", (2, 36)))
    assert find_compatible_version(pypi, "preview", matrix) == "1.0.0"
