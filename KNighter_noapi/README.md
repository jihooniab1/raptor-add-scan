# KNighter_noapi

Run KNighter via Claude Code (`claude -p`) instead of API keys.

For users on a **Claude Pro / Max / Team subscription**: KNighter's
LLM calls (patch → pattern → plan → checker → refinement) draw from
your Claude Code quota. No `llm_keys.yaml`, no OpenAI/Anthropic key
required.

For users on a **metered API key in Claude Code**: this gains nothing
over upstream KNighter — `claude -p` bills the same as a direct API
call. Use upstream KNighter with the API key directly.

## How it works

KNighter's `src/agent.py` etc. import the LLM client via
`from model import …`. This package ships a drop-in `model.py`
replacement that routes every call through `claude -p`. A small
`launcher.py` pre-registers our shim in `sys.modules['model']`
before exec'ing KNighter's `src/main.py`, so KNighter's imports
resolve to our shim instead of its own API-backed module.

```
KNighter src/main.py
    └─ from model import init_llm     ─┐
KNighter src/agent.py                   │   resolves to
    └─ from model import invoke_llm    ─┴─► KNighter_noapi/model.py
                                                  │
                                                  └─► subprocess: claude -p "<prompt>"
                                                                      │
                                                                      └─► Claude Code subscription
```

## Prerequisites

- **Claude Code CLI** on PATH (`claude --version` should work).
- **KNighter checkout** as a sibling directory, or `$KNIGHTER_DIR`
  pointing at one, or pass `--knighter-dir <path>`.
- **KNighter's runtime deps** (pydriller, GitPython, PyYAML, loguru,
  fire, tree-sitter, torch, …). Install with
  `pip install -r /path/to/KNighter/requirements.txt`. The shim
  does NOT need `openai`, `anthropic`, or `google-genai` — those
  imports live in upstream `model.py`, which the shim replaces.
- **For `scan` / full validation only**: an LLVM source tree built
  the way KNighter expects (via `scripts/setup_llvm.py`). Apt-installed
  `llvm-18-dev` is NOT sufficient — KNighter writes plugins into the
  LLVM source tree and rebuilds.

## Usage

```bash
# Synthesis (only stage that actually uses the LLM)
./run-knighter-noapi.sh --knighter-dir /path/to/KNighter \
    gen --commit_file=commits.txt --config_file=config.yaml

# Or via python directly:
python3 launcher.py --knighter-dir /path/to/KNighter \
    gen --commit_file=commits.txt --config_file=config.yaml

# Scan (no LLM calls; needs LLVM source tree)
./run-knighter-noapi.sh --knighter-dir /path/to/KNighter \
    scan --config_file=config.yaml
```

Set `$KNIGHTER_DIR` once and drop the `--knighter-dir` flag thereafter:

```bash
export KNIGHTER_DIR=/path/to/KNighter
./run-knighter-noapi.sh gen --commit_file=commits.txt \
    --config_file=config.yaml
```

## Configuration

KNighter still reads its YAML config — the shim only replaces LLM
transport. A minimal `config.yaml`:

```yaml
result_dir: "/abs/path/to/results"
LLVM_dir: "/abs/path/to/llvm-source-tree"   # only matters for scan
checker_nums: 1
linux_dir: "/abs/path/to/linux"
key_file: "/abs/path/to/stub_llm_keys.yaml" # any file containing {}
model: "claude-code"                         # cosmetic; shim ignores it
```

The `key_file` MUST exist (KNighter's `global_config._load_keys`
calls `exit(-1)` on a missing file). It can be a single-line `{}`.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `KNIGHTER_DIR` | `../KNighter` | Path to upstream KNighter checkout |
| `KNIGHTER_NOAPI_TIMEOUT` | `600` | Per-call `claude -p` timeout (s) |

## Cost behavior

Each KNighter run is LLM-heavy. Rough numbers for `gen` on a small
corpus: ~3 LLM calls per commit (patch→pattern, pattern→plan,
plan→checker), times `checker_nums`. For 20 commits with
`checker_nums: 1` that's ~60 `claude -p` calls. On a subscription
this costs nothing in $ but does count toward your weekly / 5-hour
quota. Start with `checker_nums: 1` and a small `commits.txt` to
validate the pipeline before scaling up.

## Limitations

- **Embeddings are stubbed.** Upstream uses OpenAI ada-002 (1536-d)
  for example similarity in `checker_example.choose_example`. The
  shim returns a hash-derived pseudo-embedding — deterministic but
  not semantic. Few-shot example selection becomes effectively a
  hash-based picker; checker quality during synthesis drops slightly.
- **`temperature`, `max_tokens`, `model` are accepted but ignored.**
  `claude -p` uses whatever model your Claude Code session is
  configured for. The shim logs what KNighter requested so you can
  debug if behavior surprises.
- **Per-call session overhead.** `claude -p` spins a fresh Claude
  Code session per call. This is slower than a direct API call and
  may accumulate context-setup tokens against your quota.
- **`scan` mode untested via this shim.** It doesn't call any LLMs,
  so the shim is a no-op there, but the LLVM source-tree prereq for
  scan is unchanged from upstream — solve it with KNighter's
  `scripts/setup_llvm.py`.

## Verification

A real end-to-end test against an ext4 fix lives under `test-ext4/`:

```bash
cd test-ext4
python3 run_patch2pattern.py test_config.yaml sample_patch.diff
```

This calls KNighter's actual `agent.patch2pattern` with a real ext4
null-ptr-deref fix patch. A successful run prints the LLM-generated
bug-pattern description and writes it under
`results/ext4-noapi-smoke/prompt_history/0/`.

## File layout

```
KNighter_noapi/
├── __init__.py
├── README.md                # this file
├── launcher.py              # wrapper that exec's KNighter's main.py
├── model.py                 # drop-in for KNighter's src/model.py
├── run-knighter-noapi.sh    # convenience wrapper around launcher.py
└── test-ext4/               # end-to-end verification harness
    ├── commits.txt
    ├── run_patch2pattern.py
    ├── sample_patch.diff
    ├── stub_llm_keys.yaml
    └── test_config.yaml
```
