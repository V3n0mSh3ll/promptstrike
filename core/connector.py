"""
Multi-provider API connector.

Handles request construction, retry logic, exponential backoff on
rate limits, response parsing, and request-level statistics for
every supported provider format (OpenAI, Gemini, Anthropic, Cohere,
Ollama, and generic OpenAI-compatible endpoints).
"""
from __future__ import annotations

import json
import random
import time
from typing import Any, Dict, List, Optional

import requests

from utils.config import PROVIDERS

__all__ = ["APIConnector"]

_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "PromptStrike/1.0 Security Scanner",
    "python-requests/2.31.0",
]


class APIConnector:
    """Thread-safe HTTP client for LLM chat-completion APIs."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self.provider: str = config.get("target", "provider")
        self.api_key: str = config.get("target", "api_key")
        self.api_url: str = config.get("target", "api_url")
        self.model: str = config.get("target", "model")
        self.max_tokens: int = config.get("target", "max_tokens")
        self.temperature: float = config.get("target", "temperature")
        self.timeout: int = config.get("attack", "timeout")
        self.retries: int = config.get("attack", "retries")
        self.verbose: bool = config.get("output", "verbose")
        self.proxy_cfg: Dict[str, Any] = config.get("proxy")

        prov = PROVIDERS.get(self.provider, PROVIDERS["custom"])
        self.fmt: str = prov.get("format", "openai")

        self._stats: Dict[str, int] = {"requests": 0, "errors": 0, "tokens": 0, "rate_limits": 0}
        self.session = requests.Session()
        self._init_session(prov)

    # ------------------------------------------------------------------
    # Session bootstrap
    # ------------------------------------------------------------------

    def _init_session(self, prov: Dict[str, Any]) -> None:
        if not self.api_url:
            self.api_url = prov["url"]
        if prov["auth_header"] and self.api_key:
            self.session.headers[prov["auth_header"]] = f"{prov['auth_prefix']}{self.api_key}"
        if self.config.get("stealth", "rotate_user_agent"):
            self.session.headers["User-Agent"] = random.choice(_USER_AGENTS)
        px = self.proxy_cfg
        if px and px.get("enabled") and px.get("proxy_url"):
            self.session.proxies = {"http": px["proxy_url"], "https": px["proxy_url"]}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_prompt(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Send a single prompt and return parsed content + metadata."""
        self._stats["requests"] += 1

        for attempt in range(self.retries):
            try:
                if self.config.get("stealth", "rotate_user_agent"):
                    self.session.headers["User-Agent"] = random.choice(_USER_AGENTS)

                body = self._build_payload(prompt, system_prompt, conversation)
                url = self._resolve_url()

                if self.verbose:
                    print(f"    [DBG] POST {url} (attempt {attempt + 1})")

                t0 = time.time()
                resp = self.session.post(url, json=body, timeout=self.timeout)
                elapsed = round(time.time() - t0, 2)

                if resp.status_code == 429:
                    self._stats["rate_limits"] += 1
                    if self.config.get("stealth", "backoff_on_429"):
                        wait = min(
                            self.config.get("stealth", "backoff_multiplier") ** (attempt + 1),
                            self.config.get("stealth", "max_backoff"),
                        )
                        time.sleep(wait)
                        continue
                    return self._err("rate_limited", resp.status_code, elapsed)

                if resp.status_code != 200:
                    self._stats["errors"] += 1
                    if attempt < self.retries - 1:
                        time.sleep(1)
                        continue
                    return self._err("http_error", resp.status_code, elapsed)

                result = self._parse(resp.json())
                result.update(
                    elapsed=elapsed,
                    status_code=resp.status_code,
                    attempt=attempt + 1,
                    raw_response=resp.json(),
                )
                self._stats["tokens"] += result.get("tokens", 0)
                return result

            except requests.exceptions.Timeout:
                self._stats["errors"] += 1
                if attempt < self.retries - 1:
                    time.sleep(1)
                    continue
                return self._err("timeout", 0, self.timeout)

            except requests.exceptions.ConnectionError:
                self._stats["errors"] += 1
                if attempt < self.retries - 1:
                    time.sleep(2)
                    continue
                return self._err("connection_error", 0, 0)

            except Exception as exc:
                self._stats["errors"] += 1
                return self._err(f"exception: {exc}", 0, 0)

        return self._err("max_retries", 0, 0)

    def test_connection(self) -> bool:
        """Verify that the configured endpoint responds."""
        print(f"  Testing connection to {self.provider} ({self.model})...")
        r = self.send_prompt("Say 'connected' if you can read this.")
        if r.get("error"):
            print(f"  [FAIL] {r['error']}")
            return False
        if r.get("content"):
            print(f"  [OK] Response: {r['content'][:80]}...")
            return True
        print("  [FAIL] No response")
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Return cumulative request statistics."""
        s = self._stats
        total = max(s["requests"], 1)
        return {
            "total_requests": s["requests"],
            "total_errors": s["errors"],
            "total_tokens": s["tokens"],
            "rate_limit_hits": s["rate_limits"],
            "success_rate": round((s["requests"] - s["errors"]) / total * 100, 1),
        }

    # ------------------------------------------------------------------
    # Payload construction (one builder per API format)
    # ------------------------------------------------------------------

    def _build_payload(
        self,
        prompt: str,
        sys_prompt: Optional[str] = None,
        convo: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        f = self.fmt

        if f in ("openai", "cohere"):
            msgs: List[Dict[str, str]] = []
            if sys_prompt:
                msgs.append({"role": "system", "content": sys_prompt})
            if convo:
                msgs.extend(convo)
            msgs.append({"role": "user", "content": prompt})
            payload: Dict[str, Any] = {"model": self.model, "messages": msgs}
            if f == "openai":
                payload["max_tokens"] = self.max_tokens
                payload["temperature"] = self.temperature
            return payload

        if f == "gemini":
            contents: List[Dict[str, Any]] = []
            if convo:
                for m in convo:
                    role = "user" if m["role"] == "user" else "model"
                    contents.append({"role": role, "parts": [{"text": m["content"]}]})
            contents.append({"role": "user", "parts": [{"text": prompt}]})
            payload = {"contents": contents}
            if sys_prompt:
                payload["systemInstruction"] = {"parts": [{"text": sys_prompt}]}
            payload["generationConfig"] = {
                "maxOutputTokens": self.max_tokens,
                "temperature": self.temperature,
            }
            return payload

        if f == "anthropic":
            msgs = list(convo) if convo else []
            msgs.append({"role": "user", "content": prompt})
            payload = {"model": self.model, "messages": msgs, "max_tokens": self.max_tokens}
            if sys_prompt:
                payload["system"] = sys_prompt
            return payload

        if f == "ollama":
            msgs = []
            if sys_prompt:
                msgs.append({"role": "system", "content": sys_prompt})
            if convo:
                msgs.extend(convo)
            msgs.append({"role": "user", "content": prompt})
            return {"model": self.model, "messages": msgs, "stream": False}

        msgs = []
        if sys_prompt:
            msgs.append({"role": "system", "content": sys_prompt})
        if convo:
            msgs.extend(convo)
        msgs.append({"role": "user", "content": prompt})
        return {"model": self.model, "messages": msgs, "max_tokens": self.max_tokens}

    # ------------------------------------------------------------------
    # URL resolution and response parsing
    # ------------------------------------------------------------------

    def _resolve_url(self) -> str:
        if self.fmt == "gemini":
            return self.api_url.format(model=self.model) + f"?key={self.api_key}"
        return self.api_url

    def _parse(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract content and token count from provider-specific JSON."""
        try:
            if self.fmt == "openai":
                c = data["choices"][0]["message"]["content"]
                t = data.get("usage", {}).get("total_tokens", 0)
                return {"content": c, "tokens": t,
                        "finish_reason": data["choices"][0].get("finish_reason", ""), "error": None}

            if self.fmt == "gemini":
                c = data["candidates"][0]["content"]["parts"][0]["text"]
                t = data.get("usageMetadata", {}).get("totalTokenCount", 0)
                return {"content": c, "tokens": t,
                        "finish_reason": data["candidates"][0].get("finishReason", ""), "error": None}

            if self.fmt == "anthropic":
                c = data["content"][0]["text"]
                u = data.get("usage", {})
                t = u.get("input_tokens", 0) + u.get("output_tokens", 0)
                return {"content": c, "tokens": t,
                        "finish_reason": data.get("stop_reason", ""), "error": None}

            if self.fmt == "cohere":
                c = data.get("message", {}).get("content", [{}])[0].get("text", "")
                tk = data.get("usage", {}).get("tokens", {})
                t = tk.get("input_tokens", 0) + tk.get("output_tokens", 0)
                return {"content": c, "tokens": t,
                        "finish_reason": data.get("finish_reason", ""), "error": None}

            if self.fmt == "ollama":
                c = data.get("message", {}).get("content", "")
                t = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
                return {"content": c, "tokens": t, "finish_reason": "stop", "error": None}

            if "choices" in data:
                c = data["choices"][0].get("message", {}).get("content", "")
            elif "response" in data:
                c = data["response"]
            elif "output" in data:
                c = data["output"]
            else:
                c = json.dumps(data)
            return {"content": c, "tokens": 0, "finish_reason": "", "error": None}

        except (KeyError, IndexError, TypeError) as exc:
            return {"content": json.dumps(data), "tokens": 0,
                    "finish_reason": "", "error": f"parse_error: {exc}"}

    def _err(self, error_type: str, status_code: int, elapsed: float) -> Dict[str, Any]:
        return {
            "content": "", "tokens": 0, "finish_reason": "",
            "error": error_type, "status_code": status_code,
            "elapsed": elapsed, "attempt": self.retries, "raw_response": None,
        }
