"""End-to-end shim verification: KNighter agent.patch2pattern via claude -p.

Self-installs the no-API shim (so we don't need the launcher for this
one-off test), bootstraps KNighter's global_config, then calls
KNighter's own agent.patch2pattern on a real ext4 fix patch.

A successful run proves:
  * Shim's invoke_llm replaces KNighter's invoke_llm cleanly
  * Real claude -p subprocess fires with KNighter's actual prompt template
  * Response makes it back into KNighter's state, written to result_dir
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


SHIM_DIR = Path(__file__).resolve().parent.parent
KNIGHTER_DIR = Path(os.environ.get(
    "KNIGHTER_DIR", "/home/user/men_wanted/agent/KNighter"
)).resolve()


def _install_shim() -> None:
    """Pre-register our model shim BEFORE KNighter imports it."""
    shim_path = SHIM_DIR / "model.py"
    spec = importlib.util.spec_from_file_location("model", shim_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["model"] = module
    spec.loader.exec_module(module)


def main() -> int:
    config_path = Path(sys.argv[1] if len(sys.argv) > 1
                       else "test_config.yaml").resolve()
    patch_path = Path(sys.argv[2] if len(sys.argv) > 2
                      else "sample_patch.diff").resolve()

    # Step 1: shim before any KNighter import.
    _install_shim()

    # Step 2: make KNighter's src/ importable.
    sys.path.insert(0, str(KNIGHTER_DIR / "src"))
    os.chdir(KNIGHTER_DIR)  # so prompt_template/ resolves

    # Step 3: bootstrap KNighter's global_config.
    from global_config import global_config
    global_config.setup(str(config_path))

    # Step 4: KNighter's agent. The `import agent` here will resolve
    # `from model import invoke_llm` against our shim because
    # `sys.modules['model']` was set above.
    import agent

    patch_text = Path(patch_path).read_text(encoding="utf-8")
    out_id = "ext4-noapi-smoke"
    print(f"[test] patch2pattern on {patch_path} via claude -p shim...",
          flush=True)
    pattern = agent.patch2pattern(out_id, iter=0, patch_info=patch_text)
    if not pattern:
        print("[test] FAILED — empty response from invoke_llm")
        return 1
    print("\n[test] === pattern returned (first 60 lines) ===")
    print("\n".join(pattern.splitlines()[:60]))
    print("\n[test] === end ===")
    print(f"[test] pattern bytes: {len(pattern)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
