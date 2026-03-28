"""ASCII banner and section formatting for terminal output."""
from __future__ import annotations

import random
import time
from typing import Optional

from utils.colors import BR, C, DIM, M, R, RST, Y

__all__ = ["print_banner", "print_separator", "print_header", "BANNER", "TAGLINES"]

BANNER = f"""{BR}{R}
  ██████╗ ██████╗  ██████╗ ███╗   ███╗██████╗ ████████╗
  ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝
  ██████╔╝██████╔╝██║   ██║██╔████╔██║██████╔╝   ██║
  ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝    ██║
  ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║        ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝        ╚═╝
  {M}███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
  ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
  ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{RST}

  {DIM}AI Prompt Injection Scanner{RST}
  {DIM}v1.0.0 | by Muhammad Abid (@V3n0mSh3ll){RST}
  {DIM}github.com/V3n0mSh3ll/promptstrike{RST}
"""

TAGLINES = [
    "Breaking AI guardrails since 2025",
    "Your AI is not as safe as you think",
    "Every model has a weakness",
    "Injecting prompts, extracting secrets",
    "Zero-day prompt exploits on demand",
    "15 attack vectors. 500+ payloads. 0 mercy.",
    "AI red teaming. Automated.",
    "If it responds, it can be exploited",
]


def print_banner(animate: bool = True) -> None:
    """Display the ASCII art banner with optional line-by-line animation."""
    if animate:
        for line in BANNER.split("\n"):
            print(line)
            time.sleep(0.02)
    else:
        print(BANNER)
    print(f"  {Y}>{RST} {DIM}{random.choice(TAGLINES)}{RST}\n")


def print_separator(char: str = "─", length: int = 60) -> None:
    print(f"  {DIM}{char * length}{RST}")


def print_header(title: str) -> None:
    print()
    print_separator()
    print(f"  {BR}{C}{title}{RST}")
    print_separator()
    print()
