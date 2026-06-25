#!/usr/bin/env python3
"""Run KNighter's ``src/main.py`` with the no-API shim pre-installed.

KNighter's modules import the LLM client with ``from model import …``,
which Python resolves against the script directory (``src/``) first.
PYTHONPATH cannot override that, so we pre-register our shim in
``sys.modules['model']`` before exec'ing ``main.py`` — KNighter's
subsequent imports become no-ops that pick up our module.

Usage:

    python3 launcher.py --knighter-dir /path/to/KNighter [main.py args...]

Or equivalently (the wrapper script does this for you):

    ./run-knighter-noapi.sh --knighter-dir /path/to/KNighter gen \\
        --commit_file=commits.txt --config_file=config.yaml
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import List, Optional


SHIM_DIR = Path(__file__).resolve().parent


def _parse_launcher_args(argv: List[str]) -> tuple[Optional[Path], List[str]]:
    """Extract our two own flags (``--knighter-dir``, ``--help``) from
    the argv; everything else passes through to KNighter's ``main.py``.

    We deliberately don't use argparse: KNighter's main.py is Fire-CLI
    and any argparse here would either swallow Fire flags or require
    us to mirror Fire's grammar. A tiny manual parse is simpler and
    keeps unknown flags moving downstream untouched.
    """
    knighter_dir: Optional[Path] = None
    passthrough: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help") and not passthrough:
            # Help requested before any positional — show our help and
            # exit. (After a positional like "gen", treat --help as
            # KNighter's and pass through.)
            _print_help()
            sys.exit(0)
        if a == "--knighter-dir" and i + 1 < len(argv):
            knighter_dir = Path(argv[i + 1]).expanduser().resolve()
            i += 2
            continue
        if a.startswith("--knighter-dir="):
            knighter_dir = Path(a.split("=", 1)[1]).expanduser().resolve()
            i += 1
            continue
        passthrough.append(a)
        i += 1
    return knighter_dir, passthrough


def _resolve_knighter_dir(cli_value: Optional[Path]) -> Path:
    """Precedence: ``--knighter-dir`` -> ``$KNIGHTER_DIR`` -> sibling
    ``../KNighter`` relative to this launcher. Last resort raises with
    an actionable message.
    """
    if cli_value is not None:
        if not (cli_value / "src" / "main.py").exists():
            sys.exit(
                f"✗ --knighter-dir does not contain src/main.py: {cli_value}"
            )
        return cli_value

    env = os.environ.get("KNIGHTER_DIR")
    if env:
        p = Path(env).expanduser().resolve()
        if (p / "src" / "main.py").exists():
            return p
        sys.exit(f"✗ $KNIGHTER_DIR set but src/main.py is missing: {p}")

    guess = (SHIM_DIR.parent / "KNighter").resolve()
    if (guess / "src" / "main.py").exists():
        return guess

    sys.exit(
        "✗ KNighter checkout not found. Pass --knighter-dir, set "
        "$KNIGHTER_DIR, or place a sibling 'KNighter' directory next "
        "to KNighter_noapi/."
    )


def _install_shim() -> None:
    """Pre-register our ``model.py`` in ``sys.modules['model']`` so
    KNighter's ``from model import init_llm`` resolves here.

    We use ``importlib`` rather than a relative import because the
    target module name in KNighter's namespace is the bare ``model``
    — not ``KNighter_noapi.model``. Pre-injecting ``sys.modules`` is
    the standard pattern for this kind of import override.
    """
    shim_path = SHIM_DIR / "model.py"
    spec = importlib.util.spec_from_file_location("model", shim_path)
    if spec is None or spec.loader is None:  # pragma: no cover
        sys.exit(f"✗ Could not load shim from {shim_path}")
    module = importlib.util.module_from_spec(spec)
    # Insert BEFORE exec so the shim's own ``logger`` etc. resolve
    # against the registered module.
    sys.modules["model"] = module
    spec.loader.exec_module(module)


def _exec_knighter_main(knighter_dir: Path, args: List[str]) -> None:
    """Mimic ``python3 src/main.py <args>`` from the KNighter root.

    Three things matter:

      1. **cwd** — KNighter reads ``prompt_template/``, ``checker_database/``,
         ``src/targets/`` via relative paths; we chdir so those work.
      2. **sys.path[0]** — when Python invokes ``script.py`` directly,
         it inserts the script's directory at sys.path[0]. ``from model
         import …`` from inside ``src/`` only finds our shim because we
         pre-installed it in ``sys.modules`` (step _install_shim); the
         path insert lets KNighter's OTHER intra-src imports still work
         (``from global_config import …`` etc.).
      3. **sys.argv** — Fire reads argv directly, so we rebuild it to
         look like a direct ``python3 src/main.py`` call.
    """
    main_py = knighter_dir / "src" / "main.py"
    os.chdir(knighter_dir)
    sys.path.insert(0, str(main_py.parent))
    sys.argv = [str(main_py)] + args
    code = compile(main_py.read_text(encoding="utf-8"),
                   str(main_py), "exec")
    # noqa: S102 (exec) — intended: we are explicitly running a known
    # script under our shim. Equivalent to ``python3 src/main.py``.
    exec(code, {"__name__": "__main__", "__file__": str(main_py)})


def _print_help() -> None:
    print(
        "KNighter no-API launcher — runs KNighter via Claude Code (`claude -p`)\n"
        "instead of an API key.\n\n"
        "Usage:\n"
        "  python3 launcher.py [--knighter-dir PATH] <knighter args...>\n"
        "  ./run-knighter-noapi.sh [--knighter-dir PATH] <knighter args...>\n\n"
        "Examples:\n"
        "  python3 launcher.py --knighter-dir ../KNighter gen \\\n"
        "      --commit_file=commits.txt --config_file=config.yaml\n"
        "  python3 launcher.py scan --config_file=config.yaml\n\n"
        "All args after launcher flags pass through to KNighter's "
        "src/main.py.\n\n"
        "Resolution order for KNighter location:\n"
        "  --knighter-dir > $KNIGHTER_DIR > ../KNighter\n"
    )


def main() -> None:
    knighter_dir_arg, passthrough = _parse_launcher_args(sys.argv[1:])
    knighter_dir = _resolve_knighter_dir(knighter_dir_arg)
    _install_shim()
    _exec_knighter_main(knighter_dir, passthrough)


if __name__ == "__main__":
    main()
