"""Walk a project's Dockerfile FROM / GHA runs-on / devcontainer
image refs and aggregate the (arch, libc) combinations the
project actually runs on.

Output: :class:`ProjectPlatformMatrix` — a set of
:class:`PlatformPair` tuples. Each pair represents one
(architecture, libc family + version) combo that any installed
Python wheel must satisfy.

The matrix is the *input* to :mod:`packages.sca.wheel_compat`'s
cross-check: for each pair in the matrix, does the candidate
PyPI package have an installable wheel?

Discovery sources (in walk order):

1. **Dockerfiles** — ``FROM <image>:<tag>`` lines. The
   :mod:`packages.sca.platform_matrix.glibc_db` table maps known
   images to libc versions. ``--platform=linux/<arch>`` flags on
   ``FROM`` constrain the architecture set.

2. **.devcontainer/devcontainer.json** — ``image:`` field or
   ``build.dockerfile`` pointer. Same libc resolution as Dockerfile.

3. **GitHub Actions** — ``.github/workflows/*.yml`` ``runs-on:``
   values. Standard runner labels map to known platforms. Matrix
   strategies (``strategy.matrix.platform``) multiply the set.

If no signal is found, the matrix defaults to
``{(x86_64, glibc 2.17)}`` (the manylinux2014 baseline — what
PyPI's source-build runners use). This is conservative: it
under-flags compat issues for arch-restricted projects that
hadn't declared their arch explicitly.

Architecture canonicalisation:
* ``amd64`` / ``x86_64`` / ``linux/amd64``  → ``x86_64``
* ``arm64`` / ``aarch64`` / ``linux/arm64`` → ``aarch64``
* ``armv7`` / ``arm/v7`` / ``linux/arm/v7``  → ``armv7l``
* ``i386`` / ``386``                          → ``i686``
* ``ppc64le`` / ``s390x`` pass through.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Set

from packages.sca.platform_matrix.glibc_db import (
    LibcVersion,
    lookup_distro_libc,
    lookup_runner_libc,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PlatformPair:
    """One (arch, libc) combo a Python wheel must install on."""

    arch: str                  # "x86_64" | "aarch64" | "armv7l" | "i686" | …
    libc: Optional[LibcVersion]
    # Source-trace for diagnostics ("Dockerfile FROM python:3.13-bookworm",
    # "GHA runs-on: ubuntu-22.04", etc.). Not used by the compat
    # checker; surfaces in operator-facing reports so a flagged
    # incompat says WHERE the platform came from.
    source: str = ""

    def as_str(self) -> str:
        libc = self.libc.as_str() if self.libc else "no-libc"
        return f"{self.arch}/{libc}"


@dataclass
class ProjectPlatformMatrix:
    """The set of (arch, libc) pairs the project supports."""

    pairs: Set[PlatformPair] = field(default_factory=set)

    def add(self, pair: PlatformPair) -> None:
        self.pairs.add(pair)

    def __bool__(self) -> bool:
        return bool(self.pairs)

    def __iter__(self):
        return iter(self.pairs)

    def __len__(self) -> int:
        return len(self.pairs)


# ---------------------------------------------------------------------------
# Architecture canonicalisation
# ---------------------------------------------------------------------------

_ARCH_ALIASES = {
    "x86_64": "x86_64", "amd64": "x86_64", "linux/amd64": "x86_64",
    "aarch64": "aarch64", "arm64": "aarch64", "linux/arm64": "aarch64",
    "linux/aarch64": "aarch64",
    "armv7l": "armv7l", "armv7": "armv7l", "linux/arm/v7": "armv7l",
    "arm/v7": "armv7l",
    "i686": "i686", "i386": "i686", "386": "i686", "linux/386": "i686",
    "ppc64le": "ppc64le", "linux/ppc64le": "ppc64le",
    "s390x": "s390x", "linux/s390x": "s390x",
}


def _canonical_arch(arch_ref: str) -> str:
    """Normalise platform / arch strings to canonical names.
    Unknown forms pass through unchanged."""
    return _ARCH_ALIASES.get(arch_ref, arch_ref)


# ---------------------------------------------------------------------------
# Dockerfile FROM parsing
# ---------------------------------------------------------------------------

_FROM_RE = re.compile(
    r"^\s*FROM\s+"                   # FROM keyword
    r"(?:--platform=(\S+)\s+)?"       # optional --platform=...
    r"(\S+)"                          # image[:tag][@digest]
    r"(?:\s+AS\s+\S+)?\s*$",          # optional AS stage
    re.MULTILINE | re.IGNORECASE,
)


def _from_image_to_distro(image_ref: str) -> Optional[str]:
    """Strip digest + reduce to a distro-lookup key.

    Examples:
      ``python:3.13-bookworm@sha256:abc`` → ``python:3.13-bookworm``
      ``debian:bookworm`` → ``debian:bookworm``
      ``mcr.microsoft.com/devcontainers/python:1-3.12-bookworm`` →
        ``python:1-3.12-bookworm`` (registry+namespace stripped)
    """
    # Strip digest.
    ref = image_ref.split("@", 1)[0]
    # Strip registry / namespace prefix to leave the trailing
    # ``name:tag`` form. The glibc DB tolerates the Python-image
    # codename suffix.
    if "/" in ref:
        ref = ref.rsplit("/", 1)[-1]
    return ref


def _walk_dockerfile(
    path: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Parse FROM lines + add discovered (arch, libc) pairs."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("platform_matrix: failed to read %s: %s", path, e)
        return

    for match in _FROM_RE.finditer(text):
        platform_flag = match.group(1)  # may be None
        image_ref = match.group(2)
        # Skip multi-stage FROM-AS references (``FROM build AS rt``
        # where ``build`` is a prior stage name, not an image).
        if ":" not in image_ref and "/" not in image_ref:
            # No tag + no registry — looks like a stage name. The
            # ``FROM stage AS new_stage`` pattern is the case.
            continue
        # Strip variant suffixes like ``-slim``, ``-alpine`` keep
        # the distro lookup focused: ``python:3.13-slim-bookworm``
        # is bookworm-based.
        distro_key = _from_image_to_distro(image_ref)
        libc = lookup_distro_libc(distro_key or image_ref)
        if libc is None:
            logger.debug(
                "platform_matrix: unknown libc for image %r (from %s)",
                image_ref, path,
            )
            # Still register the platform pair so the matrix
            # records that we walked the file; libc=None means
            # "we couldn't determine the libc, don't gate on it".
        if platform_flag:
            archs = [_canonical_arch(platform_flag)]
        else:
            # No --platform → image is multi-arch by convention.
            # Use the project's default multi-arch set (x86_64 +
            # aarch64, the two GHA + Apple-Silicon default targets).
            archs = ["x86_64", "aarch64"]
        for arch in archs:
            matrix.add(PlatformPair(
                arch=arch, libc=libc,
                source=f"Dockerfile FROM {image_ref} in {path.name}",
            ))


# ---------------------------------------------------------------------------
# devcontainer.json
# ---------------------------------------------------------------------------

def _walk_devcontainer(
    path: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Parse a ``devcontainer.json`` and lift the ``image:`` /
    ``build.dockerfile`` reference into the matrix.

    devcontainer.json technically supports comments (JSONC); we
    try standard JSON first and fall back to a comment-strip pass.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("platform_matrix: failed to read %s: %s", path, e)
        return

    # Strip // line comments + /* block comments */ before parsing.
    import json
    text_stripped = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text_stripped = re.sub(r"/\*.*?\*/", "", text_stripped, flags=re.DOTALL)
    try:
        data = json.loads(text_stripped)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return

    image = data.get("image")
    if isinstance(image, str):
        distro_key = _from_image_to_distro(image)
        libc = lookup_distro_libc(distro_key or image)
        for arch in ("x86_64", "aarch64"):
            matrix.add(PlatformPair(
                arch=arch, libc=libc,
                source=f"devcontainer.json image: {image}",
            ))

    build = data.get("build")
    if isinstance(build, dict):
        dockerfile_rel = build.get("dockerfile")
        if isinstance(dockerfile_rel, str):
            dockerfile_path = (path.parent / dockerfile_rel).resolve()
            if dockerfile_path.exists():
                _walk_dockerfile(dockerfile_path, matrix)


# ---------------------------------------------------------------------------
# GHA workflows
# ---------------------------------------------------------------------------

def _walk_gha_workflows(
    target: Path, matrix: ProjectPlatformMatrix,
) -> None:
    """Walk ``.github/workflows/*.yml`` for ``runs-on:`` values.

    Tolerates the two common shapes:
      * scalar:   ``runs-on: ubuntu-22.04``
      * matrix:   ``runs-on: ${{ matrix.os }}`` with
                   ``strategy.matrix.os: [ubuntu-22.04, ubuntu-24.04]``

    We use a permissive regex rather than a YAML parser so a
    grammar-incomplete workflow (operator typo, in-flight edit)
    doesn't take down the discovery pass.
    """
    workflows_dir = target / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return

    runs_on_re = re.compile(r"^\s*runs-on:\s*([^\n#]+)", re.MULTILINE)
    matrix_os_re = re.compile(
        r"^\s*os:\s*\[\s*([^\]]+)\s*\]", re.MULTILINE,
    )

    for wf in workflows_dir.glob("*.yml"):
        try:
            text = wf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Collect all bare runs-on: values (scalar form).
        for m in runs_on_re.finditer(text):
            value = m.group(1).strip().strip("'\"")
            if "${{" in value:
                # Variable reference — look for matrix.os list.
                for mm in matrix_os_re.finditer(text):
                    items = [
                        s.strip().strip("'\"")
                        for s in mm.group(1).split(",")
                    ]
                    for item in items:
                        _add_runner(item, matrix, wf)
                continue
            _add_runner(value, matrix, wf)


def _add_runner(
    runner_ref: str,
    matrix: ProjectPlatformMatrix,
    workflow: Path,
) -> None:
    """Resolve a runner label to a PlatformPair + add to matrix.

    Standard GHA runners are x86_64-only today (no aarch64 hosted
    runners in the free tier as of 2026; that may change).
    Windows / macOS runners get libc=None.
    """
    libc = lookup_runner_libc(runner_ref)
    if runner_ref.startswith("windows-"):
        matrix.add(PlatformPair(
            arch="x86_64", libc=None,
            source=f"GHA runs-on: {runner_ref} in {workflow.name}",
        ))
        return
    if runner_ref.startswith("macos-"):
        # Modern macOS runners are aarch64 (Apple Silicon).
        arch = "aarch64"
        matrix.add(PlatformPair(
            arch=arch, libc=None,
            source=f"GHA runs-on: {runner_ref} in {workflow.name}",
        ))
        return
    if libc is None:
        logger.debug(
            "platform_matrix: unknown libc for runner %r in %s",
            runner_ref, workflow,
        )
    matrix.add(PlatformPair(
        arch="x86_64", libc=libc,
        source=f"GHA runs-on: {runner_ref} in {workflow.name}",
    ))


# ---------------------------------------------------------------------------
# Top-level discovery
# ---------------------------------------------------------------------------

_DOCKERFILE_NAMES_RE = re.compile(r"^(Dockerfile|.*\.dockerfile)$|^Containerfile$")


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile."):
        return True
    if name.endswith(".dockerfile"):
        return True
    return False


def _iter_dockerfiles(target: Path) -> Iterable[Path]:
    for p in target.rglob("*"):
        if not p.is_file():
            continue
        if _is_dockerfile(p):
            # Skip SCA / build output directories.
            parts = p.parts
            if any(part in (
                "out", ".out", "node_modules", ".venv", "venv",
                ".tox", "__pycache__", ".git",
            ) for part in parts):
                continue
            yield p


def discover_platform_matrix(target: Path) -> ProjectPlatformMatrix:
    """Walk ``target`` for Dockerfile / devcontainer / GHA-workflow
    signals and return the aggregated platform matrix.

    If no signals are found, returns a default of
    ``{(x86_64, glibc 2.17)}`` — the manylinux2014 baseline, which
    is the PyPI-side floor for x86_64 wheels.
    """
    matrix = ProjectPlatformMatrix()

    for dockerfile in _iter_dockerfiles(target):
        _walk_dockerfile(dockerfile, matrix)

    devcontainer = target / ".devcontainer" / "devcontainer.json"
    if devcontainer.exists():
        _walk_devcontainer(devcontainer, matrix)

    _walk_gha_workflows(target, matrix)

    if not matrix.pairs:
        # Conservative default — matches the dominant "Linux x86_64,
        # manylinux2014 baseline" assumption that PyPI source builds use.
        matrix.add(PlatformPair(
            arch="x86_64",
            libc=LibcVersion("glibc", (2, 17)),
            source="default (no platform signals found)",
        ))

    return matrix
