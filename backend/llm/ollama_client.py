"""
OmniWatch Local LLM Client — Ollama / Phi-3-Mini
Air-gapped replacement for the Anthropic API.

All inference runs entirely on-device via the Ollama daemon
(http://localhost:11434 by default). No data leaves the facility.

Scoreboard 2 metrics are printed to stdout after every call:
  [SCOREBOARD-2] TTFT: 0.381s | Tokens: 143 | Speed: 18.4 tok/s | Model: phi3:mini
"""

import json
import logging
import os
import time
from typing import AsyncIterator

import httpx

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "phi3:mini")

# Timeout for the initial connection; individual token chunks have no timeout
# because streaming can legitimately be slow on CPU-only inference.
_CONNECT_TIMEOUT = 10.0
_READ_TIMEOUT    = 120.0


class OllamaUnavailableError(RuntimeError):
    """Raised when the Ollama daemon cannot be reached."""


class OllamaClient:
    """
    Thin async HTTP client for the Ollama /api/chat endpoint.

    Two public methods:
      generate_triage()  — JSON-mode call for structured TriageResult output
      generate_report()  — Streaming call for free-text IR markdown reports
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model:    str = OLLAMA_MODEL,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model    = model
        self._chat_url = f"{self.base_url}/api/chat"

    # ── Triage (JSON mode) ────────────────────────────────────────────────────

    async def generate_triage(
        self,
        user_prompt:   str,
        system_prompt: str,
    ) -> dict:
        """
        Send a triage prompt and return a parsed JSON dict.

        Ollama's `format: "json"` forces the model to produce valid JSON on
        every response — equivalent to Claude's tool_use constraint.

        Returns the parsed dict on success, or a fallback error dict on failure.
        Prints Scoreboard 2 latency metrics to stdout.
        """
        payload = {
            "model":  self.model,
            "format": "json",
            "stream": True,
            "messages": [
                {"role": "system",  "content": system_prompt},
                {"role": "user",    "content": user_prompt},
            ],
            "options": {
                "temperature": 0.1,   # near-deterministic for security triage
                "num_predict": 1024,
            },
        }

        t_start      = time.perf_counter()
        t_first_tok  = None
        token_count  = 0
        full_text    = []

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=_CONNECT_TIMEOUT, read=_READ_TIMEOUT, write=10.0, pool=5.0)
            ) as client:
                async with client.stream("POST", self._chat_url, json=payload) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        raise OllamaUnavailableError(
                            f"Ollama returned HTTP {resp.status_code}: {body[:200]}"
                        )

                    async for raw_line in resp.aiter_lines():
                        if not raw_line.strip():
                            continue
                        try:
                            chunk = json.loads(raw_line)
                        except json.JSONDecodeError:
                            continue

                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            if t_first_tok is None:
                                t_first_tok = time.perf_counter()
                            full_text.append(token)
                            token_count += 1

                        if chunk.get("done"):
                            break

        except httpx.ConnectError as exc:
            raise OllamaUnavailableError(
                f"Cannot reach Ollama at {self.base_url}. "
                "Is `ollama serve` running? Is phi3:mini pulled?"
            ) from exc

        t_end = time.perf_counter()
        self._print_scoreboard(t_start, t_first_tok, t_end, token_count, "triage/json")

        raw_json = "".join(full_text).strip()
        try:
            return json.loads(raw_json)
        except json.JSONDecodeError as exc:
            logger.warning("Ollama returned non-JSON for triage: %s …", raw_json[:120])
            return {"_parse_error": str(exc), "_raw": raw_json[:500]}

    # ── Report generation (streaming text) ───────────────────────────────────

    async def generate_report(
        self,
        user_prompt:   str,
        system_prompt: str,
    ) -> str:
        """
        Send a report prompt and return the complete markdown string.
        Uses streaming so Scoreboard 2 can capture TTFT accurately.
        """
        payload = {
            "model":  self.model,
            "stream": True,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "options": {
                "temperature": 0.3,
                "num_predict": 2048,
            },
        }

        t_start     = time.perf_counter()
        t_first_tok = None
        token_count = 0
        chunks      = []

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=_CONNECT_TIMEOUT, read=_READ_TIMEOUT, write=10.0, pool=5.0)
            ) as client:
                async with client.stream("POST", self._chat_url, json=payload) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        raise OllamaUnavailableError(
                            f"Ollama returned HTTP {resp.status_code}: {body[:200]}"
                        )

                    async for raw_line in resp.aiter_lines():
                        if not raw_line.strip():
                            continue
                        try:
                            chunk = json.loads(raw_line)
                        except json.JSONDecodeError:
                            continue

                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            if t_first_tok is None:
                                t_first_tok = time.perf_counter()
                            chunks.append(token)
                            token_count += 1

                        if chunk.get("done"):
                            break

        except httpx.ConnectError as exc:
            raise OllamaUnavailableError(
                f"Cannot reach Ollama at {self.base_url}."
            ) from exc

        t_end = time.perf_counter()
        self._print_scoreboard(t_start, t_first_tok, t_end, token_count, "report/text")

        return "".join(chunks).strip()

    # ── Scoreboard 2 ──────────────────────────────────────────────────────────

    def _print_scoreboard(
        self,
        t_start:     float,
        t_first_tok: float | None,
        t_end:       float,
        tokens:      int,
        mode:        str,
    ) -> None:
        total_s = t_end - t_start
        ttft    = (t_first_tok - t_start) if t_first_tok else total_s
        speed   = tokens / total_s if total_s > 0 else 0.0
        print(
            f"[SCOREBOARD-2] TTFT: {ttft:.3f}s | Tokens: {tokens} | "
            f"Speed: {speed:.1f} tok/s | Total: {total_s:.3f}s | "
            f"Mode: {mode} | Model: {self.model}",
            flush=True,
        )


# ── Module-level singleton (imported by engine.py and ai_analyst.py) ──────────
_client: OllamaClient | None = None


def get_client() -> OllamaClient:
    global _client
    if _client is None:
        _client = OllamaClient()
    return _client
