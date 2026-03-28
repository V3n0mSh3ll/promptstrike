# Changelog

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-03-20

### Added
- 15 attack module categories with 614+ payloads
- Genetic payload evolution engine with 8 mutation operators
- Chain attack pipeline (leak → analyze → craft → exploit)
- Multi-threaded attack execution with configurable concurrency
- CVSS-style severity scoring with remediation suggestions
- 35 LLM provider connectors (OpenAI, Gemini, Claude, Grok, Groq, Mistral,
  DeepSeek, Cohere, AI21, Together, Fireworks, OpenRouter, Perplexity,
  Replicate, HuggingFace, NVIDIA NIM, Cloudflare, Cerebras, SambaNova,
  Azure OpenAI, Vertex AI, AWS Bedrock, Moonshot, Zhipu, Baidu, Alibaba,
  Yi, MiniMax, Ollama, LM Studio, vLLM, text-generation-webui, custom)
- 20+ PII/credential detection patterns (API keys, tokens, connection strings)
- Response fingerprinting for vendor-specific refusal detection
- Shannon entropy analysis for obfuscation detection
- Code execution risk scanner
- Professional HTML report generation with severity cards
- JSON export sorted by severity
- 4 attack modes: stealth, balanced, aggressive, chaos
- Rate-limit handling with exponential backoff
- User-Agent rotation and proxy support (HTTP/SOCKS)
- Interactive CLI with target setup wizard
- Full CLI with 20+ flags for automation
- 159-test verification suite
