"""Drop-in replacement for KNighter's ``src/model.py``.

Mirrors the upstream module's public API exactly so KNighter's
``from model import init_llm``, ``from model import invoke_llm``, etc.
resolve here when the launcher pre-registers us in ``sys.modules``.

LLM calls are routed through Claude Code's print mode (``claude -p``),
which honours whatever auth Claude Code is configured with — a
subscription quota or an API key. No ``llm_keys.yaml`` is consulted.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional


logger = logging.getLogger("knighter_noapi")
if not logger.handlers:
    # Stay quiet by default; KNighter installs its own root handler.
    # ``logger.info`` calls still propagate when the user has logging
    # enabled at INFO or below.
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Symbols KNighter imports / touches at module scope
# ---------------------------------------------------------------------------


# KNighter's upstream ``model.py`` exposes ``clients`` as a module-level
# dict and ``model_config`` for prompt parameters. We expose the same
# names so any code that pokes at them (tests, debugging glue) keeps
# working — the shim just doesn't populate ``clients`` with real SDK
# objects.
clients: Dict[str, Any] = {}

model_config: Dict[str, Any] = {
    "model": "claude-code",
    "temperature": 1.0,
    "max_tokens": 16000,
}


# Subprocess timeout for a single ``claude -p`` call. KNighter prompts
# can be large; Claude Code's print mode is slower than a direct API
# call because it spins a fresh session per call. 600s is generous;
# override with ``KNIGHTER_NOAPI_TIMEOUT``.
_DEFAULT_TIMEOUT_S = int(os.environ.get("KNIGHTER_NOAPI_TIMEOUT", "600"))

# Maximum bytes of stderr to surface on failure — claude -p stderr can
# be voluminous (auth nags, MCP startup, etc.); cap it so the operator
# sees the actionable bit without scrolling.
_STDERR_TAIL_BYTES = 4096


# ---------------------------------------------------------------------------
# Public API — exact upstream signatures
# ---------------------------------------------------------------------------


def init_llm() -> None:
    """No-op equivalent of upstream ``init_llm``.

    Upstream reads ``llm_keys.yaml`` and constructs OpenAI / Anthropic /
    Gemini SDK clients; we don't need any of that because every call
    goes through the ``claude`` CLI. We still perform one sanity check
    — that ``claude`` is on PATH — so the user gets an actionable error
    here rather than a mysterious subprocess failure deep inside
    KNighter's first ``invoke_llm`` call.
    """
    if shutil.which("claude") is None:
        raise RuntimeError(
            "KNighter_noapi requires the `claude` CLI on PATH "
            "(Claude Code). Install it from "
            "https://docs.claude.com/en/docs/claude-code and re-run."
        )
    logger.info(
        "KNighter_noapi active: LLM calls routed via `claude -p` "
        "(model=%s)", model_config["model"],
    )


def get_client_and_model(model_name: str) -> tuple:
    """Upstream returns ``(client, actual_model)`` so callers can
    dispatch on client type. We return a sentinel client object and
    pass the model name through unchanged. ``invoke_llm`` doesn't use
    the return value (it talks to ``claude`` directly), but anything
    else that calls ``get_client_and_model`` still gets a non-crashing
    result.
    """
    return ("claude-code", model_name)


def invoke_llm(
    prompt: str,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
    max_tokens: Optional[int] = None,
) -> Optional[str]:
    """Route the prompt through ``claude -p`` and return the answer.

    Signature is identical to upstream so KNighter's call sites
    (``agent.py`` patch->pattern, pattern->plan, plan->checker,
    refinement, repair) work unchanged.

    ``temperature`` / ``model`` / ``max_tokens`` are accepted for
    signature compatibility. ``claude -p`` does not expose them as
    flags in the same way the API does — the model is whichever one
    the user's Claude Code session is configured to use. We log what
    was requested so debugging is possible if behavior surprises.
    """
    _ = max_tokens  # accepted for upstream parity; unused.

    requested_model = model or model_config["model"]
    requested_temp = (
        temperature if temperature is not None else model_config["temperature"]
    )
    logger.info(
        "invoke_llm: model=%s temperature=%.2f prompt_bytes=%d",
        requested_model, requested_temp, len(prompt),
    )

    # Mirror upstream's prompt-size guard. The byte estimate is rough
    # (~4 bytes/token) but matches what upstream uses for the same
    # guard, so behavior at the boundary is consistent.
    if len(prompt) > 400_000:
        logger.warning(
            "Prompt too long (%d bytes); skipping per upstream policy.",
            len(prompt),
        )
        return None

    cmd = ["claude", "-p", prompt]
    try:
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use
        # ``cmd`` is a Python list (no shell), prompt is the user/KNighter
        # payload. Same trust posture as KNighter passing the prompt to
        # an SDK call — we are the in-process middleware.
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_DEFAULT_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error(
            "`claude -p` timed out after %ds; returning None.",
            _DEFAULT_TIMEOUT_S,
        )
        return None
    except FileNotFoundError:
        # Defence in depth — init_llm should have caught this, but
        # if KNighter never called init_llm (some test paths skip it)
        # we still want an actionable message.
        raise RuntimeError(
            "`claude` CLI not found on PATH. Install Claude Code "
            "and ensure `claude` is reachable."
        )

    if proc.returncode != 0:
        stderr_tail = (proc.stderr or "")[-_STDERR_TAIL_BYTES:]
        logger.error(
            "`claude -p` exited %d. stderr tail:\n%s",
            proc.returncode, stderr_tail.rstrip(),
        )
        return None

    answer = (proc.stdout or "").strip()
    # Preserve upstream's <think>...</think> stripping for reasoning
    # models — Claude Code may emit them when extended-thinking is on.
    if answer and "<think>" in answer:
        answer = answer.split("</think>")[-1].strip()

    if not answer:
        logger.warning("`claude -p` returned empty stdout (rc=0).")
        return None
    return answer


# ---------------------------------------------------------------------------
# Embeddings stub
# ---------------------------------------------------------------------------


# Upstream KNighter uses OpenAI ``text-embedding-ada-002`` (1536-dim)
# for cosine-similarity over checker examples in
# ``checker_example.choose_example``. ``claude -p`` does not expose an
# embeddings endpoint, so we return a deterministic pseudo-embedding.
# Effect on KNighter: ``choose_example`` becomes effectively a hash-
# based picker rather than semantic — the few-shot examples it serves
# are deterministic but less semantically relevant. KNighter still
# runs; checker quality is slightly degraded for the gen stage.
_EMBED_DIM = 1536


def _hash_embedding(text: str) -> List[float]:
    """Deterministic [-1, 1] vector derived from a SHA-256 walk of the
    text. Lets cosine similarity at least be stable across calls (same
    text => same neighbour ranking) even though it has no semantic
    signal.
    """
    import hashlib
    vec: List[float] = []
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).digest()
    i = 0
    while len(vec) < _EMBED_DIM:
        # Re-hash chained blocks so we generate ample bytes.
        block = hashlib.sha256(digest + i.to_bytes(4, "big")).digest()
        for b in block:
            vec.append((b / 127.5) - 1.0)  # byte -> [-1, 1]
            if len(vec) >= _EMBED_DIM:
                break
        i += 1
    return vec


def get_embeddings(text: str) -> List[float]:
    """Return a 1536-d hash-derived pseudo-embedding so KNighter's
    cosine-similarity calls don't crash. NOT a real semantic
    embedding — see module-level note.
    """
    return _hash_embedding(text)


# ---------------------------------------------------------------------------
# Small helpers KNighter imports from model
# ---------------------------------------------------------------------------


def num_tokens_from_string(string: str) -> int:
    """Upstream's rough estimator — kept verbatim for parity."""
    return len(string) // 4
