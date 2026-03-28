"""
Token boundary analysis and payload generation.

Generates payloads that exploit tokeniser edge-cases: special
control tokens, zero-width Unicode characters, homoglyph
substitution, and encoding-boundary tricks.
"""
from __future__ import annotations

import base64
import codecs
from typing import Dict, List

__all__ = ["TokenAnalyzer"]

SPECIAL_TOKENS: List[str] = [
    "[INST]", "[/INST]", "[SYS]", "[/SYS]",
    "<|system|>", "<|user|>",
    "<|assistant|>", "<|endoftext|>",
    "[PAD]", "[EOS]", "[BOS]", "[CLS]", "[SEP]", "[MASK]",
]

_ZWCHARS: Dict[str, str] = {
    "zwj":       "\u200d",
    "zwnj":      "\u200c",
    "soft_hyph":  "\u00ad",
    "bom":       "\ufeff",
    "rtl":       "\u202e",
    "lro":       "\u202d",
    "zwsp":      "\u200b",
}


class TokenAnalyzer:
    """Generate payloads targeting tokeniser boundaries and Unicode tricks."""

    def generate_token_payloads(self, base_payload: str) -> List[str]:
        """Produce a list of token-boundary exploit variants."""
        payloads: List[str] = []

        for token in SPECIAL_TOKENS:
            payloads.append(f"{token} {base_payload}")
            payloads.append(f"{base_payload} {token}")

        for name, zw in _ZWCHARS.items():
            words = base_payload.split()
            payloads.append(zw.join(words))

        words = base_payload.split()
        if len(words) >= 3:
            mid = " ".join(words[1:-1])
            b64 = base64.b64encode(mid.encode()).decode()
            payloads.append(f"{words[0]} [base64:{b64}] {words[-1]}")
            payloads.append(f"{words[0]} [hex:{mid.encode().hex()}] {words[-1]}")
            payloads.append(f"{words[0]} [rot13:{codecs.encode(mid, 'rot_13')}] {words[-1]}")

        alternated = "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(base_payload)
        )
        payloads.append(alternated)

        homoglyphs = {"a": "\u0430", "e": "\u0435", "o": "\u043e",
                      "p": "\u0440", "c": "\u0441", "x": "\u0445"}
        subbed = base_payload
        for latin, cyrillic in homoglyphs.items():
            subbed = subbed.replace(latin, cyrillic, 1)
        if subbed != base_payload:
            payloads.append(subbed)

        payloads.append(base_payload.replace(" ", "\u00a0"))
        payloads.append(base_payload.replace(" ", "\u2003"))

        return payloads

    def detect_token_boundaries(self, text: str) -> List[Dict[str, str]]:
        """Detect suspicious zero-width characters and special tokens."""
        findings: List[Dict[str, str]] = []
        for name, zw in _ZWCHARS.items():
            if zw in text:
                findings.append({"type": "zero_width_char", "char": name, "count": str(text.count(zw))})
        for token in SPECIAL_TOKENS:
            if token in text:
                findings.append({"type": "special_token", "token": token})
        return findings
