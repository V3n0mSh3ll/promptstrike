"""Configuration management, provider registry, and attack constants."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Union

DEFAULT_CONFIG = {
    "target": {
        "api_url": "",
        "api_key": "",
        "model": "",
        "provider": "custom",
        "max_tokens": 1024,
        "temperature": 0.7,
    },
    "attack": {
        "threads": 5,
        "delay_min": 0.5,
        "delay_max": 2.0,
        "timeout": 30,
        "retries": 3,
        "mode": "balanced",
        "max_payloads": 0,
        "categories": ["all"],
        "chain_depth": 5,
        "evolve_generations": 10,
        "evolve_population": 20,
        "fuzz_iterations": 100,
    },
    "output": {
        "report_html": True,
        "report_json": True,
        "report_csv": False,
        "verbose": False,
        "save_responses": True,
        "output_dir": "results",
    },
    "proxy": {
        "enabled": False,
        "proxy_url": "",
        "proxy_file": "",
        "rotate": False,
    },
    "dashboard": {
        "enabled": False,
        "port": 8089,
        "host": "127.0.0.1",
    },
    "stealth": {
        "randomize_delay": True,
        "rotate_user_agent": True,
        "backoff_on_429": True,
        "backoff_multiplier": 2.0,
        "max_backoff": 60,
    }
}

PROVIDERS = {
    "openai": {
        "url": "https://api.openai.com/v1/chat/completions",
        "models": ["gpt-5.4", "gpt-5.4-mini", "gpt-5", "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano", "o4-mini", "o3", "o3-pro", "o3-mini"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "gemini": {
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "models": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-pro", "gemini-1.5-flash"],
        "auth_header": "x-goog-api-key",
        "auth_prefix": "",
        "format": "gemini",
    },
    "anthropic": {
        "url": "https://api.anthropic.com/v1/messages",
        "models": ["claude-4-opus-20260301", "claude-4-sonnet-20260301", "claude-3.7-sonnet-20250219", "claude-3.5-sonnet-20241022", "claude-3.5-haiku-20241022"],
        "auth_header": "x-api-key",
        "auth_prefix": "",
        "format": "anthropic",
    },
    "xai": {
        "url": "https://api.x.ai/v1/chat/completions",
        "models": ["grok-3.5", "grok-3", "grok-3-mini", "grok-2"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "azure_openai": {
        "url": "https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version=2026-03-01",
        "models": ["gpt-5.4", "gpt-5", "gpt-4.1", "o4-mini", "o3", "o3-pro"],
        "auth_header": "api-key",
        "auth_prefix": "",
        "format": "openai",
    },
    "vertex_ai": {
        "url": "https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/publishers/google/models/{model}:generateContent",
        "models": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "gemini",
    },
    "aws_bedrock": {
        "url": "https://bedrock-runtime.{region}.amazonaws.com/model/{model}/invoke",
        "models": ["anthropic.claude-4-opus", "anthropic.claude-4-sonnet", "anthropic.claude-3.7-sonnet", "meta.llama4-scout-17b", "meta.llama4-maverick-17b", "amazon.nova-pro", "amazon.nova-lite"],
        "auth_header": "Authorization",
        "auth_prefix": "",
        "format": "openai",
    },

    "groq": {
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "models": ["llama-4-scout-17b-16e", "llama-4-maverick-17b-128e", "llama-3.3-70b-versatile", "deepseek-r1-distill-llama-70b", "gemma2-9b-it", "qwen-qwq-32b"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "cerebras": {
        "url": "https://api.cerebras.ai/v1/chat/completions",
        "models": ["llama-4-scout-17b", "llama3.3-70b", "llama3.1-8b", "deepseek-r1-distill-llama-70b"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "sambanova": {
        "url": "https://api.sambanova.ai/v1/chat/completions",
        "models": ["Meta-Llama-4-Scout-17B-16E", "Meta-Llama-4-Maverick-17B-128E", "Meta-Llama-3.3-70B-Instruct", "DeepSeek-R1-Distill-Llama-70B", "QwQ-32B"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },

    "mistral": {
        "url": "https://api.mistral.ai/v1/chat/completions",
        "models": ["mistral-large-3-latest", "mistral-large-latest", "mistral-small-latest", "codestral-latest", "pixtral-large-latest", "mistral-saba-latest"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "deepseek": {
        "url": "https://api.deepseek.com/v1/chat/completions",
        "models": ["deepseek-r2", "deepseek-v3", "deepseek-chat", "deepseek-reasoner", "deepseek-coder"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "cohere": {
        "url": "https://api.cohere.com/v2/chat",
        "models": ["command-a", "command-r-plus-08-2025", "command-r-plus", "command-r", "command-light"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "cohere",
    },
    "ai21": {
        "url": "https://api.ai21.com/studio/v1/chat/completions",
        "models": ["jamba-1.6-large", "jamba-1.6-mini", "jamba-1.5-large", "jamba-1.5-mini"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "writer": {
        "url": "https://api.writer.com/v1/chat",
        "models": ["palmyra-x-004", "palmyra-x-003-instruct"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "inflection": {
        "url": "https://api.inflection.ai/v1/chat/completions",
        "models": ["inflection-3-pi", "inflection-3-productivity"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },

    "together": {
        "url": "https://api.together.xyz/v1/chat/completions",
        "models": ["meta-llama/Llama-4-Scout-17B-16E", "meta-llama/Llama-4-Maverick-17B-128E", "meta-llama/Llama-3.3-70B-Instruct-Turbo", "Qwen/Qwen2.5-72B-Instruct-Turbo", "deepseek-ai/DeepSeek-R1", "google/gemma-3-27b-it"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "fireworks": {
        "url": "https://api.fireworks.ai/inference/v1/chat/completions",
        "models": ["accounts/fireworks/models/llama4-scout-instruct", "accounts/fireworks/models/llama4-maverick-instruct", "accounts/fireworks/models/deepseek-r1", "accounts/fireworks/models/qwen2p5-72b-instruct"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "openrouter": {
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "models": ["openai/gpt-5.4", "openai/gpt-5", "anthropic/claude-4-opus", "anthropic/claude-4-sonnet", "google/gemini-2.5-pro", "meta-llama/llama-4-maverick", "deepseek/deepseek-r2", "x-ai/grok-3.5"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "perplexity": {
        "url": "https://api.perplexity.ai/chat/completions",
        "models": ["sonar-pro", "sonar-reasoning-pro", "sonar-reasoning", "sonar", "r1-1776"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "replicate": {
        "url": "https://api.replicate.com/v1/predictions",
        "models": ["meta/llama-4-scout-17b", "meta/llama-4-maverick-17b", "meta/llama-3.3-70b-instruct"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "huggingface": {
        "url": "https://api-inference.huggingface.co/models/{model}/v1/chat/completions",
        "models": ["meta-llama/Llama-4-Scout-17B-16E", "Qwen/Qwen2.5-72B-Instruct", "google/gemma-3-27b-it", "deepseek-ai/DeepSeek-R1"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },

    "nvidia_nim": {
        "url": "https://integrate.api.nvidia.com/v1/chat/completions",
        "models": ["meta/llama-4-scout-17b", "meta/llama-3.3-70b-instruct", "nvidia/llama-3.1-nemotron-70b-instruct", "deepseek-ai/deepseek-r1"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "cloudflare": {
        "url": "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{model}",
        "models": ["@cf/meta/llama-3.3-70b-instruct", "@cf/meta/llama-3.1-8b-instruct", "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },

    "moonshot": {
        "url": "https://api.moonshot.cn/v1/chat/completions",
        "models": ["moonshot-v1-128k", "moonshot-v1-32k", "moonshot-v1-8k"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "zhipu": {
        "url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "models": ["glm-4-plus", "glm-4", "glm-4-flash", "glm-4-air"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "baidu_ernie": {
        "url": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/{model}",
        "models": ["ernie-4.0-8k", "ernie-3.5-8k", "ernie-speed-8k"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "alibaba_qwen": {
        "url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "models": ["qwen-max", "qwen-plus", "qwen-turbo", "qwen2.5-72b-instruct"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "yi": {
        "url": "https://api.lingyiwanwu.com/v1/chat/completions",
        "models": ["yi-large", "yi-medium", "yi-spark"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },
    "minimax": {
        "url": "https://api.minimax.chat/v1/text/chatcompletion_v2",
        "models": ["abab6.5s-chat", "abab6.5-chat", "abab5.5-chat"],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    },

    "ollama": {
        "url": "http://localhost:11434/api/chat",
        "models": ["llama3.2", "llama3.1", "mistral", "mixtral", "phi3", "qwen2.5", "deepseek-r1", "gemma2", "codellama", "vicuna", "neural-chat"],
        "auth_header": "",
        "auth_prefix": "",
        "format": "ollama",
    },
    "lmstudio": {
        "url": "http://localhost:1234/v1/chat/completions",
        "models": ["local-model"],
        "auth_header": "",
        "auth_prefix": "",
        "format": "openai",
    },
    "vllm": {
        "url": "http://localhost:8000/v1/chat/completions",
        "models": ["local-model"],
        "auth_header": "",
        "auth_prefix": "",
        "format": "openai",
    },
    "textgen_webui": {
        "url": "http://localhost:5000/v1/chat/completions",
        "models": ["local-model"],
        "auth_header": "",
        "auth_prefix": "",
        "format": "openai",
    },

    "custom": {
        "url": "",
        "models": [],
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "format": "openai",
    }
}

ATTACK_MODES = {
    "stealth": {"threads": 2, "delay_min": 2.0, "delay_max": 5.0, "desc": "slow + careful, avoids rate limits"},
    "balanced": {"threads": 5, "delay_min": 0.5, "delay_max": 2.0, "desc": "default, moderate speed"},
    "aggressive": {"threads": 15, "delay_min": 0.1, "delay_max": 0.5, "desc": "fast, may trigger rate limits"},
    "chaos": {"threads": 25, "delay_min": 0, "delay_max": 0.1, "desc": "no mercy, max speed, max threads"},
}

SEVERITY_LEVELS = {
    "critical": {"score": 9.0, "color": "red", "icon": "🔴", "desc": "full system prompt leak or unrestricted harmful output"},
    "high": {"score": 7.0, "color": "orange", "icon": "🟠", "desc": "partial data leak or significant guardrail bypass"},
    "medium": {"score": 5.0, "color": "yellow", "icon": "🟡", "desc": "minor guardrail weakness or partial bypass"},
    "low": {"score": 3.0, "color": "blue", "icon": "🔵", "desc": "informational leak, low impact"},
    "info": {"score": 1.0, "color": "gray", "icon": "⚪", "desc": "interesting behavior, no direct impact"},
}

ATTACK_CATEGORIES = [
    "jailbreak",
    "system_leak",
    "guardrail_bypass",
    "data_extraction",
    "encoding_bypass",
    "language_switch",
    "context_overflow",
    "indirect_injection",
    "tool_exploit",
    "chain_attack",
    "memory_poison",
    "token_smuggling",
    "role_escalation",
    "fuzzer",
    "custom",
]

class Config:
    """Layered configuration with file-load and mode-switching support."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.data: Dict[str, Any] = dict(DEFAULT_CONFIG)
        if config_path and os.path.exists(config_path):
            self.load(config_path)

    def load(self, path: str) -> None:
        """Load and merge a JSON config file over defaults."""
        with open(path, "r") as f:
            user_cfg = json.load(f)
        self._merge(self.data, user_cfg)

    def save(self, path: str) -> None:
        """Write the current configuration to *path* as JSON."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.data, f, indent=2)

    def _merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = v

    def get(self, section: str, key: Optional[str] = None) -> Any:
        """Retrieve a config value by section and optional key."""
        if key is None:
            return self.data.get(section, {})
        return self.data.get(section, {}).get(key)

    def set(self, section: str, key: str, value: Any) -> None:
        """Set a config value."""
        if section not in self.data:
            self.data[section] = {}
        self.data[section][key] = value

    def apply_mode(self, mode: str) -> None:
        """Apply a preset attack mode (stealth, balanced, aggressive, chaos)."""
        if mode in ATTACK_MODES:
            m = ATTACK_MODES[mode]
            self.data["attack"]["threads"] = m["threads"]
            self.data["attack"]["delay_min"] = m["delay_min"]
            self.data["attack"]["delay_max"] = m["delay_max"]
            self.data["attack"]["mode"] = mode
