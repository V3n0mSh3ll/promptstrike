"""Terminal color helpers and formatted print functions."""
from __future__ import annotations

__all__ = [
    "R", "G", "Y", "C", "M", "W", "B", "DIM", "BR", "RST",
    "p_info", "p_ok", "p_fail", "p_warn", "p_vuln", "p_critical",
    "p_attack", "p_result", "p_debug", "severity_color",
]

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    R, G, Y, C, M, W, B = Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.CYAN, Fore.MAGENTA, Fore.WHITE, Fore.BLUE
    DIM, BR, RST = Style.DIM, Style.BRIGHT, Style.RESET_ALL
except ImportError:
    R = G = Y = C = M = W = B = DIM = BR = RST = ""


def p_info(msg: str) -> None:
    print(f"  {C}[*]{RST} {msg}")


def p_ok(msg: str) -> None:
    print(f"  {G}[+]{RST} {msg}")


def p_fail(msg: str) -> None:
    print(f"  {R}[-]{RST} {msg}")


def p_warn(msg: str) -> None:
    print(f"  {Y}[!]{RST} {msg}")


def p_vuln(msg: str) -> None:
    print(f"  {BR}{R}[VULN]{RST} {msg}")


def p_critical(msg: str) -> None:
    print(f"  {BR}{M}[CRITICAL]{RST} {msg}")


def p_attack(msg: str) -> None:
    print(f"  {M}[>]{RST} {msg}")


def p_result(msg: str) -> None:
    print(f"  {BR}{G}[\u2713]{RST} {msg}")


def p_debug(msg: str, verbose: bool = False) -> None:
    if verbose:
        print(f"  {DIM}[D] {msg}{RST}")


def severity_color(sev: str) -> str:
    """Return the ANSI color code for a given severity level."""
    return {
        "critical": f"{BR}{R}", "high": R, "medium": Y,
        "low": C, "info": DIM,
    }.get(sev.lower(), RST)
