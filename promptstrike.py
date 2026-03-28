#!/usr/bin/env python3
"""PromptStrike - AI Prompt Injection Testing Framework.

Entry point for both CLI and interactive modes.  Run with ``--help``
for usage, or launch without arguments for interactive setup.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.colors import (
    BR, C, DIM, G, M, R, RST, Y,
    p_attack, p_critical, p_debug, p_fail, p_info, p_ok,
    p_result, p_vuln, p_warn, severity_color,
)
from utils.banner import print_banner, print_separator, print_header
from utils.config import Config, PROVIDERS, ATTACK_MODES, ATTACK_CATEGORIES
from core.engine import AttackEngine
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.markdown_report import generate_markdown_report


def get_input(prompt_text: str, default: Optional[str] = None) -> Optional[str]:
    suffix = f" [{default}]" if default else ""
    val = input(f"  {C}>{RST} {prompt_text}{suffix}: ").strip()
    return val if val else default


def setup_target_interactive() -> Config:
    print_header("TARGET SETUP")

    print(f"  {BR}Select Provider:{RST}")
    providers = list(PROVIDERS.keys())
    for i, p in enumerate(providers, 1):
        models = ", ".join(PROVIDERS[p]["models"][:3])
        print(f"    {Y}[{i}]{RST} {p:10s} {DIM}({models}){RST}")

    choice = get_input("Provider", "1")
    try:
        provider = providers[int(choice) - 1]
    except (ValueError, IndexError):
        provider = "custom"

    if provider == "ollama":
        api_key = ""
        api_url = get_input("API URL", PROVIDERS[provider]["url"])
    elif provider == "custom":
        api_url = get_input("API URL (full endpoint)")
        api_key = get_input("API Key")
    else:
        api_key = get_input("API Key")
        api_url = PROVIDERS[provider]["url"]

    if PROVIDERS[provider]["models"]:
        print(f"\n  {BR}Available Models:{RST}")
        for i, m in enumerate(PROVIDERS[provider]["models"], 1):
            print(f"    {Y}[{i}]{RST} {m}")
        model_choice = get_input("Model", "1")
        try:
            model = PROVIDERS[provider]["models"][int(model_choice) - 1]
        except (ValueError, IndexError):
            model = model_choice
    else:
        model = get_input("Model name")

    config = Config()
    config.set("target", "provider", provider)
    config.set("target", "api_key", api_key)
    config.set("target", "api_url", api_url)
    config.set("target", "model", model)

    return config


def interactive_menu(config: Config) -> None:
    while True:
        print()
        print(f"  {BR}{'=' * 50}{RST}")
        print(f"  {BR}{M}  PROMPTSTRIKE - ATTACK MENU{RST}")
        print(f"  {BR}{'=' * 50}{RST}")
        print(f"    {Y}[1]{RST}  Full Scan (all 500+ payloads)")
        print(f"    {Y}[2]{RST}  Jailbreak Attack")
        print(f"    {Y}[3]{RST}  System Prompt Extraction")
        print(f"    {Y}[4]{RST}  Guardrail Bypass")
        print(f"    {Y}[5]{RST}  Encoding Bypass (base64/hex/rot13)")
        print(f"    {Y}[6]{RST}  Multi-Language Bypass")
        print(f"    {Y}[7]{RST}  Data Extraction")
        print(f"    {Y}[8]{RST}  Context Overflow")
        print(f"    {Y}[9]{RST}  Indirect Injection")
        print(f"    {Y}[10]{RST} Token Smuggling")
        print(f"    {Y}[11]{RST} Role Escalation")
        print(f"    {Y}[12]{RST} Chain Attack (auto multi-step)")
        print(f"    {Y}[13]{RST} Payload Evolution (genetic)")
        print(f"    {Y}[14]{RST} Fuzzer (random mutations)")
        print(f"    {Y}[15]{RST} Custom Payloads")
        print(f"    {DIM}─────────────────────────────────{RST}")
        print(f"    {Y}[S]{RST}  Settings")
        print(f"    {Y}[T]{RST}  Test Connection")
        print(f"    {Y}[0]{RST}  Exit")
        print(f"  {BR}{'=' * 50}{RST}")

        choice = get_input("Select attack")
        if not choice:
            continue

        engine = AttackEngine(config)

        category_map = {
            "1": None,
            "2": "jailbreak",
            "3": "system_leak",
            "4": "guardrail_bypass",
            "5": "encoding_bypass",
            "6": "language_switch",
            "7": "data_extraction",
            "8": "context_overflow",
            "9": "indirect_injection",
            "10": "token_smuggling",
            "11": "role_escalation",
        }

        try:
            if choice == "0":
                p_info("Exiting PromptStrike...")
                break
            elif choice == "1":
                results = engine.run_scan()
            elif choice in category_map and choice != "1":
                cat = category_map[choice]
                results = engine.run_single_category(cat)
            elif choice == "12":
                results = engine.run_chain_attack()
            elif choice == "13":
                cat = get_input("Category to evolve", "jailbreak")
                results = engine.run_evolve(cat)
            elif choice == "14":
                try:
                    iters = int(get_input("Iterations", "100") or "100")
                except ValueError:
                    p_fail("Invalid number. Using default 100.")
                    iters = 100
                cat = get_input("Category to fuzz", "jailbreak")
                results = engine.run_fuzz(cat, iters)
            elif choice == "15":
                payload_file = get_input("Path to custom payload file (JSON)")
                if payload_file and os.path.exists(payload_file):
                    with open(payload_file) as f:
                        custom_payloads = json.load(f)
                    results = engine.run_scan(payloads=custom_payloads)
                else:
                    p_fail("File not found")
                    continue
            elif choice.lower() == "s":
                settings_menu(config)
                continue
            elif choice.lower() == "t":
                engine.connector.test_connection()
                continue
            else:
                p_warn("Invalid choice")
                continue

            save = get_input("Save report? (y/n)", "y")
            if save and save.lower() == "y":
                save_reports(engine, config)

        except KeyboardInterrupt:
            p_warn("\nAttack interrupted by user")
            save = get_input("Save partial results? (y/n)", "y")
            if save and save.lower() == "y":
                save_reports(engine, config)
        except Exception as e:
            p_fail(f"Error: {str(e)}")


def settings_menu(config: Config) -> None:
    print_header("SETTINGS")
    print(f"    {Y}[1]{RST} Attack Mode: {config.get('attack', 'mode')}")
    print(f"    {Y}[2]{RST} Threads: {config.get('attack', 'threads')}")
    print(f"    {Y}[3]{RST} Max Payloads: {config.get('attack', 'max_payloads')} (0=unlimited)")
    print(f"    {Y}[4]{RST} Verbose: {config.get('output', 'verbose')}")
    print(f"    {Y}[5]{RST} Output Dir: {config.get('output', 'output_dir')}")
    print(f"    {Y}[6]{RST} Evolution Generations: {config.get('attack', 'evolve_generations')}")
    print(f"    {Y}[7]{RST} Proxy: {'Enabled' if config.get('proxy', 'enabled') else 'Disabled'}")
    print(f"    {Y}[0]{RST} Back")

    choice = get_input("Setting")
    if choice == "1":
        print(f"\n  {BR}Modes:{RST}")
        for name, info in ATTACK_MODES.items():
            print(f"    {Y}{name:12s}{RST} {DIM}{info['desc']}{RST}")
        mode = get_input("Mode", "balanced") or "balanced"
        if mode in ATTACK_MODES:
            config.apply_mode(mode)
            p_ok(f"Mode set: {mode}")
        else:
            p_fail(f"Unknown mode: {mode}")
    elif choice == "2":
        try:
            threads = int(get_input("Threads", "5") or "5")
        except ValueError:
            p_fail("Invalid number"); return
        config.set("attack", "threads", threads)
    elif choice == "3":
        try:
            mp = int(get_input("Max payloads (0=all)", "0") or "0")
        except ValueError:
            p_fail("Invalid number"); return
        config.set("attack", "max_payloads", mp)
    elif choice == "4":
        config.set("output", "verbose", not config.get("output", "verbose"))
        p_ok(f"Verbose: {config.get('output', 'verbose')}")
    elif choice == "5":
        d = get_input("Output directory", "results")
        config.set("output", "output_dir", d)
    elif choice == "6":
        try:
            g = int(get_input("Generations", "10") or "10")
        except ValueError:
            p_fail("Invalid number"); return
        config.set("attack", "evolve_generations", g)
    elif choice == "7":
        proxy_url = get_input("Proxy URL (empty=disable)")
        if proxy_url:
            config.set("proxy", "enabled", True)
            config.set("proxy", "proxy_url", proxy_url)
            p_ok(f"Proxy enabled: {proxy_url}")
        else:
            config.set("proxy", "enabled", False)
            p_info("Proxy disabled")


def save_reports(engine: AttackEngine, config: Config) -> None:
    output_dir = config.get("output", "output_dir")
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    data = engine.get_results()

    json_path = os.path.join(output_dir, f"scan_{ts}.json")
    generate_json_report(data, json_path)
    p_ok(f"JSON report: {json_path}")

    md_path = os.path.join(output_dir, f"scan_{ts}.md")
    generate_markdown_report(data, md_path)
    p_ok(f"Markdown report: {md_path}")

    if config.get("output", "report_html"):
        html_path = os.path.join(output_dir, f"scan_{ts}.html")
        generate_html_report(data, html_path)
        p_ok(f"HTML report: {html_path}")


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PromptStrike - AI Prompt Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --provider openai --key sk-... --model gpt-5.4 --scan full
  %(prog)s --provider ollama --model llama3 --scan jailbreak
  %(prog)s --provider gemini --key AIza... --model gemini-2.5-flash --scan chain
  %(prog)s --provider openai --key sk-... --model gpt-5.4 --scan evolve --evolve-cat jailbreak
  %(prog)s --provider custom --url https://api.example.com/chat --scan full
        """
    )

    target = parser.add_argument_group("Target")
    target.add_argument("--provider", choices=list(PROVIDERS.keys()), default="openai")
    target.add_argument("--key", help="API key")
    target.add_argument("--url", help="API endpoint URL")
    target.add_argument("--model", help="Model name", default="gpt-5.4")

    attack = parser.add_argument_group("Attack")
    attack.add_argument("--scan", choices=["full", "jailbreak", "system-leak", "guardrail", "encoding",
                         "language", "data", "overflow", "indirect", "token", "role", "chain", "evolve", "fuzz"],
                         default="full", help="Scan type")
    attack.add_argument("--mode", choices=list(ATTACK_MODES.keys()), default="balanced")
    attack.add_argument("--threads", type=int, default=5)
    attack.add_argument("--max-payloads", type=int, default=0)
    attack.add_argument("--payloads", help="Custom payload file (JSON)")

    evolve = parser.add_argument_group("Evolution")
    evolve.add_argument("--evolve-cat", default="jailbreak", help="Category to evolve")
    evolve.add_argument("--evolve-gen", type=int, default=10, help="Evolution generations")
    evolve.add_argument("--evolve-pop", type=int, default=20, help="Evolution population size")

    fuzz = parser.add_argument_group("Fuzzer")
    fuzz.add_argument("--fuzz-iters", type=int, default=100, help="Fuzzer iterations")
    fuzz.add_argument("--fuzz-cat", default="jailbreak", help="Category to fuzz")

    output = parser.add_argument_group("Output")
    output.add_argument("--output-dir", default="results")
    output.add_argument("--no-html", action="store_true")
    output.add_argument("--verbose", action="store_true")

    network = parser.add_argument_group("Network")
    network.add_argument("--proxy", help="Proxy URL")
    network.add_argument("--timeout", type=int, default=30)

    return parser


def cli_mode(args: argparse.Namespace) -> None:
    config = Config()
    config.set("target", "provider", args.provider)
    config.set("target", "api_key", args.key or "")
    config.set("target", "api_url", args.url or "")
    config.set("target", "model", args.model)
    config.set("attack", "threads", args.threads)
    config.set("attack", "max_payloads", args.max_payloads)
    config.set("attack", "evolve_generations", args.evolve_gen)
    config.set("attack", "evolve_population", args.evolve_pop)
    config.set("attack", "fuzz_iterations", args.fuzz_iters)
    config.set("output", "output_dir", args.output_dir)
    config.set("output", "verbose", args.verbose)
    config.set("output", "report_html", not args.no_html)
    config.apply_mode(args.mode)

    if args.proxy:
        config.set("proxy", "enabled", True)
        config.set("proxy", "proxy_url", args.proxy)

    scan_map = {
        "full": None,
        "jailbreak": "jailbreak",
        "system-leak": "system_leak",
        "guardrail": "guardrail_bypass",
        "encoding": "encoding_bypass",
        "language": "language_switch",
        "data": "data_extraction",
        "overflow": "context_overflow",
        "indirect": "indirect_injection",
        "token": "token_smuggling",
        "role": "role_escalation",
    }

    engine = AttackEngine(config)

    try:
        if args.scan == "chain":
            engine.run_chain_attack()
        elif args.scan == "evolve":
            engine.run_evolve(args.evolve_cat)
        elif args.scan == "fuzz":
            engine.run_fuzz(args.fuzz_cat, args.fuzz_iters)
        elif args.scan == "full" and args.payloads:
            with open(args.payloads) as f:
                custom = json.load(f)
            engine.run_scan(payloads=custom)
        elif args.scan in scan_map:
            cat = scan_map[args.scan]
            if cat:
                engine.run_single_category(cat)
            else:
                engine.run_scan()

        save_reports(engine, config)

    except KeyboardInterrupt:
        p_warn("\nInterrupted. Saving partial results...")
        save_reports(engine, config)


def main() -> None:
    print_banner()

    if len(sys.argv) > 1:
        parser = build_cli_parser()
        args = parser.parse_args()
        cli_mode(args)
    else:
        config = setup_target_interactive()
        interactive_menu(config)


if __name__ == "__main__":
    main()
