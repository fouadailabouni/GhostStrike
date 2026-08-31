"""
GhostStrike AI Engine — Model Provider
=======================================
Unified gateway over Anthropic Claude and OpenAI GPT-4o.
Operators set the active back-end through settings.json → ai_engine.backend.

Supported back-ends
-------------------
  claude  – Anthropic Claude 3.x / 4.x  (vault id "ai_anthropic_api_key", falls back to ANTHROPIC_API_KEY)
  openai  – OpenAI GPT-4o / o1 family   (vault id "ai_openai_api_key", falls back to OPENAI_API_KEY)

API keys are resolved from GhostStrike's hardened credential vault
(lib/vault.sh) first, not a plaintext env var or config file the way the
original PhantomOps source did this. The env var remains a fallback so
operators who haven't migrated a key into the vault yet aren't blocked.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


class ModelBackend(str, Enum):
    CLAUDE = "claude"
    OPENAI = "openai"


_DEFAULT_MODELS: Dict[ModelBackend, str] = {
    ModelBackend.CLAUDE: "claude-sonnet-4-6",
    ModelBackend.OPENAI: "gpt-4o",
}

_VAULT_CREDENTIAL_IDS: Dict[ModelBackend, str] = {
    ModelBackend.CLAUDE: "ai_anthropic_api_key",
    ModelBackend.OPENAI: "ai_openai_api_key",
}

_ENV_VAR_NAMES: Dict[ModelBackend, str] = {
    ModelBackend.CLAUDE: "ANTHROPIC_API_KEY",
    ModelBackend.OPENAI: "OPENAI_API_KEY",
}


def _bash_scripts_dir() -> Path:
    # ai_engine/model_provider.py -> CyberToolkit -> GhostStrike -> bash_scripts_for_pentest
    return Path(__file__).resolve().parent.parent.parent / "bash_scripts_for_pentest"


def _to_wsl_path(path: str) -> str:
    norm = path.replace("\\", "/")
    return re.sub(r"^([A-Za-z]):", lambda m: f"/mnt/{m.group(1).lower()}", norm)


def get_api_key_from_vault(vault_id: str, vault_key: Optional[str] = None) -> str:
    """
    Retrieve a credential from lib/vault.sh's encrypted store.

    ``vault_key`` is the vault *master* password for this session (distinct
    from the API key itself) — normally supplied by the GUI once, after
    prompting the operator, and passed down here rather than read from a
    real tty (vault.sh supports this explicitly via the GS_VAULT_KEY env
    var, so no interactive `/dev/tty` prompt is needed for a GUI caller).
    Returns "" if the vault, the credential, or the master key isn't
    available -- callers should fall back to the plain env var in that case.
    """
    if not vault_key:
        return ""
    base = _bash_scripts_dir()
    common_sh = base / "lib" / "common.sh"
    vault_sh = base / "lib" / "vault.sh"
    if not vault_sh.exists():
        return ""
    common_wsl = _to_wsl_path(str(common_sh))
    vault_wsl = _to_wsl_path(str(vault_sh))
    script = (
        f'export GS_VAULT_KEY={_shell_quote(vault_key)}; '
        f'source "{common_wsl}" >/dev/null 2>&1; '
        f'source "{vault_wsl}" >/dev/null 2>&1; '
        f'gs_vault_get {_shell_quote(vault_id)} 2>/dev/null'
    )
    try:
        result = subprocess.run(
            ["wsl", "bash", "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


def _shell_quote(value: str) -> str:
    # Minimal single-quote shell escaping -- vault ids/keys are operator-set,
    # not attacker-controlled, but never trust that they don't contain a quote.
    return "'" + value.replace("'", "'\\''") + "'"


class GhostStrikeModelProvider:
    """
    Central model gateway for the GhostStrike AI engine.

    All agents call ``complete()`` or ``stream_complete()`` — they never
    touch the underlying SDK directly so the back-end can be swapped in
    settings.json without touching any agent code.
    """

    def __init__(
        self,
        backend: ModelBackend = ModelBackend.CLAUDE,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        vault_master_key: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 8192,
    ) -> None:
        self.backend     = ModelBackend(backend)
        self.model_name  = model_name or _DEFAULT_MODELS[self.backend]
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.key_source  = "explicit"

        if api_key:
            self._api_key = api_key
        else:
            # 1. Try the hardened vault first (needs the session's vault master
            #    key -- normally supplied by the GUI, or GS_VAULT_KEY in the
            #    environment for CLI/headless use).
            vault_key = vault_master_key or os.getenv("GS_VAULT_KEY", "")
            self._api_key = get_api_key_from_vault(
                _VAULT_CREDENTIAL_IDS[self.backend], vault_key
            )
            self.key_source = "vault" if self._api_key else self.key_source
            # 2. Fall back to the plain env var so operators who haven't
            #    migrated a key into the vault yet aren't blocked.
            if not self._api_key:
                self._api_key = os.getenv(_ENV_VAR_NAMES[self.backend], "")
                self.key_source = "env" if self._api_key else "none"

        self._client = self._build_client()

    # ── Client construction ───────────────────────────────────────────────

    def _build_client(self) -> Any:
        if not self._api_key:
            key_name = _ENV_VAR_NAMES[self.backend]
            vault_id = _VAULT_CREDENTIAL_IDS[self.backend]
            raise RuntimeError(
                f"No API key for {self.backend.value}. Store one in the vault "
                f"(gs_vault_store {vault_id} ...) and supply the vault master key, "
                f"or set {key_name} as a fallback env var."
            )
        if self.backend == ModelBackend.CLAUDE:
            try:
                import anthropic
                return anthropic.Anthropic(api_key=self._api_key)
            except ImportError:
                raise RuntimeError("Run: pip install anthropic")
        else:
            try:
                from openai import OpenAI
                return OpenAI(api_key=self._api_key)
            except ImportError:
                raise RuntimeError("Run: pip install openai")

    # ── Public API ────────────────────────────────────────────────────────

    def complete(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        system_prompt: Optional[str] = None,
    ) -> Dict:
        """
        Send a completion request.  Returns normalised dict:

        {
            "content":       str,
            "tool_calls":    list[dict] | None,
            "finish_reason": "stop" | "tool_calls" | "length",
            "usage":         {"input_tokens": int, "output_tokens": int},
        }
        """
        if self.backend == ModelBackend.CLAUDE:
            return self._claude_complete(messages, tools, system_prompt)
        return self._openai_complete(messages, tools, system_prompt)

    def stream_complete(
        self,
        messages: List[Dict],
        system_prompt: Optional[str] = None,
    ) -> Generator[str, None, None]:
        """Yield text chunks as they arrive (non-tool path only)."""
        if self.backend == ModelBackend.CLAUDE:
            yield from self._claude_stream(messages, system_prompt)
        else:
            yield from self._openai_stream(messages, system_prompt)

    # ── Claude ────────────────────────────────────────────────────────────

    def _claude_complete(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]],
        system_prompt: Optional[str],
    ) -> Dict:
        claude_tools = []
        if tools:
            for t in tools:
                fn = t.get("function", t)
                claude_tools.append({
                    "name":         fn["name"],
                    "description":  fn.get("description", ""),
                    "input_schema": fn.get("parameters", {
                        "type": "object", "properties": {}
                    }),
                })

        kwargs: Dict[str, Any] = {
            "model":       self.model_name,
            "max_tokens":  self.max_tokens,
            "temperature": self.temperature,
            "messages":    self._to_claude_messages(messages),
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if claude_tools:
            kwargs["tools"] = claude_tools

        resp = self._client.messages.create(**kwargs)

        text_out  = ""
        tool_calls: List[Dict] = []
        for block in resp.content:
            if hasattr(block, "text"):
                text_out += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id":   block.id,
                    "name": block.name,
                    "args": block.input,
                })

        finish = "tool_calls" if tool_calls else (
            "length" if resp.stop_reason == "max_tokens" else "stop"
        )
        return {
            "content":       text_out,
            "tool_calls":    tool_calls or None,
            "finish_reason": finish,
            "usage": {
                "input_tokens":  resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            },
        }

    def _claude_stream(
        self, messages: List[Dict], system_prompt: Optional[str]
    ) -> Generator[str, None, None]:
        kwargs: Dict[str, Any] = {
            "model":      self.model_name,
            "max_tokens": self.max_tokens,
            "messages":   self._to_claude_messages(messages),
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        with self._client.messages.stream(**kwargs) as stream:
            for chunk in stream.text_stream:
                yield chunk

    def _to_claude_messages(self, messages: List[Dict]) -> List[Dict]:
        """
        Convert our internal message format to Claude's API format.

        Key rules:
        - ``tool`` role messages → user messages with ``tool_result`` blocks.
          Multiple consecutive tool messages are merged into ONE user message
          (Claude rejects two consecutive user messages).
        - ``assistant`` messages with tool_calls → content blocks with ``tool_use``.
        - ``system`` role is handled via the top-level ``system`` kwarg, not here.
        """
        out: List[Dict] = []
        i = 0
        while i < len(messages):
            m = messages[i]
            role = m["role"]

            if role == "system":
                i += 1
                continue

            # Collect a run of consecutive tool-result messages and merge them
            if role == "tool":
                tool_result_blocks: List[Dict] = []
                while i < len(messages) and messages[i]["role"] == "tool":
                    tm = messages[i]
                    tool_result_blocks.append({
                        "type":        "tool_result",
                        "tool_use_id": tm.get("tool_call_id", ""),
                        "content":     str(tm.get("content", "")),
                    })
                    i += 1
                out.append({"role": "user", "content": tool_result_blocks})
                continue

            if role == "assistant" and m.get("tool_calls"):
                blocks: List[Dict] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m["tool_calls"]:
                    blocks.append({
                        "type":  "tool_use",
                        "id":    tc["id"],
                        "name":  tc["name"],
                        "input": tc.get("args", {}),
                    })
                out.append({"role": "assistant", "content": blocks})
                i += 1
                continue

            out.append({"role": role, "content": m.get("content", "")})
            i += 1
        return out

    # ── OpenAI ────────────────────────────────────────────────────────────

    def _to_openai_messages(self, messages: List[Dict], system_prompt: Optional[str]) -> List[Dict]:
        """
        Convert our internal format to OpenAI's expected message format.

        - assistant tool_calls: must be {type:"function", function:{name, arguments:str}}
        - tool results: role="tool" with tool_call_id (already correct)
        - prepend system message if provided
        """
        out: List[Dict] = []
        if system_prompt:
            out.append({"role": "system", "content": system_prompt})
        for m in messages:
            role = m["role"]
            if role == "assistant" and m.get("tool_calls"):
                oai_calls = []
                for tc in m["tool_calls"]:
                    oai_calls.append({
                        "id":   tc["id"],
                        "type": "function",
                        "function": {
                            "name":      tc["name"],
                            "arguments": json.dumps(tc.get("args", {})),
                        },
                    })
                out.append({
                    "role":       "assistant",
                    "content":    m.get("content") or None,
                    "tool_calls": oai_calls,
                })
            elif role == "tool":
                out.append({
                    "role":         "tool",
                    "tool_call_id": m.get("tool_call_id", ""),
                    "content":      str(m.get("content", "")),
                })
            else:
                out.append({"role": role, "content": m.get("content", "")})
        return out

    def _openai_complete(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]],
        system_prompt: Optional[str],
    ) -> Dict:
        oai_msgs = self._to_openai_messages(messages, system_prompt)

        kwargs: Dict[str, Any] = {
            "model":       self.model_name,
            "messages":    oai_msgs,
            "max_tokens":  self.max_tokens,
            "temperature": self.temperature,
        }
        if tools:
            kwargs["tools"]       = tools
            kwargs["tool_choice"] = "auto"

        resp   = self._client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        msg    = choice.message

        tool_calls: List[Dict] = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                tool_calls.append({
                    "id":   tc.id,
                    "name": tc.function.name,
                    "args": json.loads(tc.function.arguments or "{}"),
                })

        return {
            "content":       msg.content or "",
            "tool_calls":    tool_calls or None,
            "finish_reason": choice.finish_reason or "stop",
            "usage": {
                "input_tokens":  resp.usage.prompt_tokens if resp.usage else 0,
                "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
            },
        }

    def _openai_stream(
        self, messages: List[Dict], system_prompt: Optional[str]
    ) -> Generator[str, None, None]:
        oai_msgs = self._to_openai_messages(messages, system_prompt)
        for chunk in self._client.chat.completions.create(
            model=self.model_name,
            messages=oai_msgs,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            stream=True,
        ):
            delta = chunk.choices[0].delta if chunk.choices else None
            if delta and delta.content:
                yield delta.content

    # ── Factory ───────────────────────────────────────────────────────────

    @classmethod
    def from_settings(cls, settings: Dict, vault_master_key: Optional[str] = None) -> "GhostStrikeModelProvider":
        """
        Construct from GhostStrike settings.json dict.

        Deliberately does NOT read an api_key field out of settings.json --
        that's the plaintext-config-file pattern the original PhantomOps
        source used for this, and it's weaker than the vault. Pass
        ``vault_master_key`` (from the GUI's session-cached vault unlock)
        so the key is resolved from lib/vault.sh instead.
        """
        cfg = settings.get("ai_engine", {})
        try:
            backend = ModelBackend(cfg.get("backend", "claude"))
        except ValueError:
            backend = ModelBackend.CLAUDE
        return cls(
            backend=backend,
            model_name=cfg.get("model_name"),
            vault_master_key=vault_master_key,
            temperature=float(cfg.get("temperature", 0.2)),
            max_tokens=int(cfg.get("max_tokens", 8192)),
        )

    def label(self) -> str:
        return f"{self.backend.value.upper()} / {self.model_name}"
