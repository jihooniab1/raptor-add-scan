"""pip resolver wrapper.

Uses ``pip-compile`` (from pip-tools) when available, falling back to
``pip install --dry-run`` otherwise. ``pip-compile`` is the canonical
way to deterministically resolve a ``requirements.in``-style spec into
a fully-pinned ``requirements.txt`` without actually installing
anything; ``pip install --dry-run`` (pip 23.0+) is the lighter
alternative when pip-tools isn't installed.

Neither path executes install hooks — pip doesn't run them on
``--dry-run`` for wheel-only deps, and we don't allow source-dist
fallback (``--only-binary=:all:`` where supported).

PEP 668 (externally-managed-environment) handling
-------------------------------------------------
Most modern Linux distros ship the system Python marked
"externally-managed" (``/usr/lib/python*/EXTERNALLY-MANAGED``). When
pip detects that marker it refuses operations to protect distro state
— even ``--dry-run`` is blocked. raptor-sca scans run on operator
systems; if the system pip refuses, we fall back to creating an
ephemeral venv under the project tree and re-running the resolver
with the venv's pip (which doesn't have the marker). Per-run cost is
~3-5s for venv create + pip-tools install. The venv lives at
``<project>/.raptor-sca-venv-{pid}/`` and is removed after the run.
Sandbox writes are confined to the project tree already so this lands
in the only writeable surface available to us.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


def _real_python() -> str:
    """Return the realpath of the running Python interpreter.

    ``sys.executable`` may live under ``$HOME`` (e.g. pyenv, asdf,
    user-installed Python) — but the sandbox uses ``fake_home=True``
    which hides ``$HOME`` from the child. Resolving the symlink chain
    to the underlying binary (typically under ``/usr/bin/``) makes the
    interpreter reachable inside the sandbox.
    """
    return os.path.realpath(sys.executable)


# Marker substrings pip prints when it hits PEP 668. Lower-cased
# match — pip's exact wording has shifted across releases.
_PEP668_MARKERS = (
    "externally-managed-environment",
    "this environment is externally managed",
)


def _is_pep668_failure(stderr: str) -> bool:
    """Detect pip's PEP 668 refusal in captured stderr."""
    if not stderr:
        return False
    low = stderr.lower()
    return any(m in low for m in _PEP668_MARKERS)


class PipResolver:
    """``pip-compile`` (preferred) or ``pip install --dry-run`` wrapper."""

    ecosystem = "PyPI"
    # pypi.org for JSON metadata, files.pythonhosted.org for the
    # actual wheels pip-compile / pip download for resolution.
    # Some org pip configs use a private mirror; the sandbox will
    # surface that as a proxy refusal, which is the right failure
    # mode (reveals an unallowed dep source).
    proxy_hosts = ("pypi.org", "files.pythonhosted.org")

    def is_available(self) -> bool:
        # pip itself ships with every Python install; require a usable
        # one to claim availability.
        return _check_tool(["pip", "--version"])

    def matches(self, project_dir: Path) -> bool:
        # pip is the fallback resolver for the PyPI ecosystem — it
        # matches anything with a pip-style manifest. PoetryResolver
        # is registered before pip and steals projects with a
        # ``[tool.poetry]`` section in pyproject.toml.
        return _find_pip_manifest(project_dir) is not None

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="pip not found in PATH",
            )

        manifest = _find_pip_manifest(project_dir)
        if manifest is None:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=("no requirements*.txt or pyproject.toml in "
                       f"{project_dir}"),
            )

        # Prefer pip-compile when present — it's deterministic and
        # produces a clean fully-pinned output we return as the lockfile.
        if _check_tool(["pip-compile", "--version"]):
            return self._run_pip_compile(project_dir, manifest, timeout)
        # Fallback: pip install --dry-run. Returns success/failure but
        # no lockfile artefact (pip writes to site-packages on success;
        # --dry-run prevents that).
        return self._run_pip_dry(project_dir, manifest, timeout)

    # ----- internals -----

    def _run_pip_compile(
        self, project_dir: Path, manifest: Path, timeout: int,
    ) -> ResolverResult:
        rel_manifest = str(manifest.relative_to(project_dir))
        cmd = ["pip-compile", "--quiet", "--output-file", "-", rel_manifest]
        try:
            proc = _run(cmd, cwd=project_dir, timeout=timeout,
                        proxy_hosts=self.proxy_hosts)
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"pip-compile timed out after {timeout}s",
            )

        # PEP 668 retry: pip-compile invokes pip under the hood; if the
        # system Python is externally-managed, that fails. Recover via
        # ephemeral venv where the marker doesn't apply.
        if proc.returncode != 0 and _is_pep668_failure(proc.stderr):
            return self._run_pip_compile_in_venv(
                project_dir, rel_manifest, timeout,
            )

        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                        or "pip-compile exited non-zero"),
                raw_output=raw,
            )
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=proc.stdout.encode("utf-8"),
            raw_output=raw,
        )

    def _run_pip_dry(
        self, project_dir: Path, manifest: Path, timeout: int,
    ) -> ResolverResult:
        rel_manifest = str(manifest.relative_to(project_dir))
        cmd = [
            "pip", "install", "--dry-run", "--quiet",
            "-r", rel_manifest,
            "--only-binary=:all:",     # avoid sdist setup.py runs
        ]
        try:
            proc = _run(cmd, cwd=project_dir, timeout=timeout,
                        proxy_hosts=self.proxy_hosts)
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"pip install --dry-run timed out after {timeout}s",
            )

        # PEP 668 retry — see _run_pip_compile.
        if proc.returncode != 0 and _is_pep668_failure(proc.stderr):
            return self._run_pip_dry_in_venv(
                project_dir, rel_manifest, timeout,
            )

        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                        or "pip install --dry-run exited non-zero"),
                raw_output=raw,
            )
        # No lockfile to read; success is the signal.
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=None,
            raw_output=raw,
        )

    # --- PEP 668 venv fallback -----------------------------------------

    def _venv_dir(self, project_dir: Path) -> Path:
        """Per-run venv path — pid suffix prevents concurrent collisions."""
        import os as _os
        return project_dir / f".raptor-sca-venv-{_os.getpid()}"

    def _create_venv(
        self, project_dir: Path, timeout: int,
    ) -> "tuple[Optional[Path], Optional[str]]":
        """Create an ephemeral venv inside ``project_dir``.

        Returns ``(venv_dir, None)`` on success, or ``(None, error)``
        with a human-readable failure reason. Caller is responsible for
        cleanup via :meth:`_cleanup_venv` once done.
        """
        venv_dir = self._venv_dir(project_dir)
        # Stale venv from a crashed prior run with the same PID — wipe.
        if venv_dir.exists():
            shutil.rmtree(venv_dir, ignore_errors=True)
        try:
            proc = _run(
                [_real_python(), "-m", "venv",
                 "--without-pip",
                 venv_dir.name],
                cwd=project_dir, timeout=timeout,
                proxy_hosts=(),  # venv create is local-only
            )
        except subprocess.TimeoutExpired:
            return None, f"venv create timed out after {timeout}s"
        if proc.returncode != 0:
            return None, (proc.stderr.strip() or "venv create failed")
        # Bootstrap pip into the new venv via ensurepip — avoids needing
        # network for the pip install itself.
        venv_python = venv_dir / "bin" / "python"
        if not venv_python.exists():
            # Windows / unusual layout — give up cleanly.
            return None, f"venv python missing at {venv_python}"
        try:
            proc = _run(
                [str(venv_python), "-m", "ensurepip", "--upgrade", "--quiet"],
                cwd=project_dir, timeout=timeout,
                proxy_hosts=(),  # ensurepip is local-only
            )
        except subprocess.TimeoutExpired:
            return None, f"ensurepip timed out after {timeout}s"
        if proc.returncode != 0:
            return None, (proc.stderr.strip() or "ensurepip failed")
        return venv_dir, None

    def _cleanup_venv(self, venv_dir: Path) -> None:
        """Best-effort venv removal. Errors are logged, not raised —
        leaving a stale venv is preferable to crashing the resolver."""
        try:
            shutil.rmtree(venv_dir, ignore_errors=True)
        except Exception as e:                      # noqa: BLE001
            logger.debug("sca.pip: venv cleanup failed for %s: %s",
                         venv_dir, e)

    def _run_pip_compile_in_venv(
        self, project_dir: Path, rel_manifest: str, timeout: int,
    ) -> ResolverResult:
        """Retry pip-compile in an ephemeral venv after PEP 668 refusal."""
        venv_dir, err = self._create_venv(project_dir, timeout)
        if venv_dir is None:
            return ResolverResult(
                ecosystem=self.ecosystem, success=False, available=True,
                error=f"PEP 668 fallback failed: {err}",
            )
        try:
            venv_python = venv_dir / "bin" / "python"
            # Install pip-tools into the venv. Network call — proxy
            # already restricts to the PyPI hosts.
            try:
                proc = _run(
                    [str(venv_python), "-m", "pip", "install", "--quiet",
                     "pip-tools"],
                    cwd=project_dir, timeout=timeout,
                    proxy_hosts=self.proxy_hosts,
                )
            except subprocess.TimeoutExpired:
                return ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=f"venv pip-tools install timed out after {timeout}s",
                )
            if proc.returncode != 0:
                return ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=("venv pip-tools install failed: "
                           + (proc.stderr.strip() or "exit non-zero")),
                )
            venv_pipcompile = venv_dir / "bin" / "pip-compile"
            try:
                proc = _run(
                    [str(venv_pipcompile), "--quiet",
                     "--output-file", "-", rel_manifest],
                    cwd=project_dir, timeout=timeout,
                    proxy_hosts=self.proxy_hosts,
                )
            except subprocess.TimeoutExpired:
                return ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=f"venv pip-compile timed out after {timeout}s",
                )
            raw = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode != 0:
                return ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=("venv pip-compile failed: "
                           + (proc.stderr.strip() or "exit non-zero")),
                    raw_output=raw,
                )
            return ResolverResult(
                ecosystem=self.ecosystem, success=True, available=True,
                proposed_lockfile=proc.stdout.encode("utf-8"),
                raw_output=raw,
            )
        finally:
            self._cleanup_venv(venv_dir)

    def _run_pip_dry_in_venv(
        self, project_dir: Path, rel_manifest: str, timeout: int,
    ) -> ResolverResult:
        """Retry pip --dry-run in an ephemeral venv after PEP 668."""
        venv_dir, err = self._create_venv(project_dir, timeout)
        if venv_dir is None:
            return ResolverResult(
                ecosystem=self.ecosystem, success=False, available=True,
                error=f"PEP 668 fallback failed: {err}",
            )
        try:
            venv_python = venv_dir / "bin" / "python"
            try:
                proc = _run(
                    [str(venv_python), "-m", "pip", "install",
                     "--dry-run", "--quiet",
                     "-r", rel_manifest,
                     "--only-binary=:all:"],
                    cwd=project_dir, timeout=timeout,
                    proxy_hosts=self.proxy_hosts,
                )
            except subprocess.TimeoutExpired:
                return ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=f"venv pip --dry-run timed out after {timeout}s",
                )
            raw = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode != 0:
                return ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=("venv pip --dry-run failed: "
                           + (proc.stderr.strip() or "exit non-zero")),
                    raw_output=raw,
                )
            return ResolverResult(
                ecosystem=self.ecosystem, success=True, available=True,
                proposed_lockfile=None,
                raw_output=raw,
            )
        finally:
            self._cleanup_venv(venv_dir)


def _find_pip_manifest(project_dir: Path) -> Optional[Path]:
    """Return the path to a top-level pip-style manifest, if any."""
    candidates = [
        project_dir / "requirements.txt",
        project_dir / "requirements-dev.txt",
        project_dir / "requirements.in",
        project_dir / "pyproject.toml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


__all__ = ["PipResolver"]
