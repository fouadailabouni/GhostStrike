# AI Co-Pilot

An optional Manual ↔ AI toggle in the GUI. A specialized agent persona reasons
about a plain-language task and drives modules on your behalf.

## Personas (`CyberToolkit/ai_engine/agents/`)

| Agent | Focus |
|---|---|
| `red_team_agent.py` | Offensive assessment workflow |
| `blue_team_agent.py` | Defensive analysis |
| `web_pentest_agent.py` | Web application testing |
| `bug_bounty_agent.py` | Bug bounty workflow |
| `dfir_agent.py` | Digital forensics / incident response |
| `reverse_eng_agent.py` | Reverse engineering |
| `wifi_agent.py` | Wireless assessment |
| `ctf_agent.py` | CTF-style challenges |
| `purple_team_agent.py` | Joint red/blue workflow |
| `nlp_router_agent.py` | Routes a plain-language request to the right persona/module |
| `output_analyst_agent.py` | Interprets raw module/tool output |

All eleven share a common base class (`base_agent.py`).

## How a request becomes a module run

1. You describe a task in plain language to the active persona.
2. The agent proposes a module + arguments via `ai_engine/tools/module_runner.py`.
3. The proposed call goes through the **exact same `gs_policy_gate` check** a
   manual run does — trust level, scope, environment, per-module approval.
   There is no separate, more permissive execution path for AI-driven calls.
4. A module without confirmed policy-gate wiring is refused, not attempted.

## Autonomy

Implemented, not just conceptual: `GhostStrikeRunner` (`ai_engine/tools/module_runner.py`)
takes an `autonomy_tier` of `observe`, `recommend`, or `operate` (default
`recommend`), and every module call is gated by it independently of the
policy gate:

- **`observe`** — the agent's proposed action is reported
  ("PROPOSED (not executed)...") but never run.
- **`recommend`** — the action requires an `approval_callback`; with none
  wired up, it's refused.
- **`operate`** — proceeds without asking only for modules that don't need
  approval (`SAFE_ENUM`/`VALIDATION` trust with no `policy.yaml` override);
  anything `HIGH_IMPACT`/`LAB_ONLY`, or explicitly on the approval list,
  still requires `approval_callback` even in `operate` mode.

This autonomy check and the `gs_policy_gate` check are independent layers —
passing one never substitutes for the other.

## Credentials and redaction

- API keys resolve from `lib/vault.sh` or an `ANTHROPIC_API_KEY` /
  `OPENAI_API_KEY` environment variable.
- Outbound data to the LLM provider is redacted before it leaves the machine.
  Treat this as a boundary that's still being hardened — verify what's
  actually redacted for your use case before sending sensitive scan output
  through a cloud provider, and prefer a local model (Ollama, LM Studio, or
  another OpenAI-compatible local endpoint) when the engagement data is
  sensitive enough that you wouldn't want it leaving the machine at all.

## Local-first AI (no cloud required)

Cloud AI is optional, not mandatory. Set `ai_engine.backend` to `"local"` in
settings.json (or construct `GhostStrikeModelProvider(backend=ModelBackend.LOCAL)`
directly) to route through any OpenAI-API-compatible local server — Ollama's
`/v1` endpoint by default (`http://localhost:11434/v1`, override via
`GHOSTSTRIKE_LOCAL_AI_URL` or `local_base_url`), or LM Studio, or another
compatible server. No API key is required for the common case of a local
server with auth disabled.

Verified live against a real running Ollama server — both a plain
completion and a full tool-call round trip (the model correctly chose a
tool and produced valid arguments), not just that the client constructs
without error. Four models were pulled and confirmed via Ollama's own
`/api/tags` capabilities list:

| Tag | Size | Capabilities |
|---|---|---|
| `llama3.1:8b` | 4.9 GB | completion, **tools** (default — see below) |
| `llama3.2:3b` | 2.0 GB | completion, **tools** |
| `qwen2.5:7b` | 4.7 GB | completion, **tools** |
| `gemma2:9b` | 5.4 GB | completion only — no tools |

Use the exact tag (including the `:size` suffix — Ollama does not resolve
a bare family name like `llama3.1` to whichever tag you've pulled) via
`model_name` in settings.json. `llama3.1:8b` is the default because the AI
Co-Pilot is tool-calling-heavy (agents drive modules via `tool_calls`), and
`gemma2` is the one model of the four that doesn't report tool-calling
support at all — confirmed by Ollama's own API, not assumed.

**Offline mode**: set `GHOSTSTRIKE_OFFLINE=true` and any attempt to
construct a cloud (`claude`/`openai`) backend raises immediately rather
than making an outbound call — only `local` is permitted. This is the
actual enforcement point for "cloud AI should never be mandatory," not
just a documentation claim.

## MCP server

`CyberToolkit/ai_engine/mcp_server/` exposes engagement data to external MCP
clients over stdio (no network transport): `list_engagements`,
`get_engagement`, `list_findings`, `get_finding`, `get_attack_graph`,
`get_repro_score`. All read-only — write tools are intentionally not exposed
yet.