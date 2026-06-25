"""KNighter no-API — run KNighter via Claude Code (`claude -p`) instead
of direct API keys.

For users on a Claude Pro / Max / Team subscription: KNighter's LLM
calls (patch -> pattern, pattern -> plan, plan -> checker, refinement)
go through `claude -p`, drawing from the subscription quota. No
`llm_keys.yaml` and no OpenAI/Anthropic/Gemini key required.

For users on a metered API key: this gains nothing over the upstream
KNighter — `claude -p` bills the same as a direct API call.
"""
