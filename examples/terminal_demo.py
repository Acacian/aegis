#!/usr/bin/env python3
"""
Terminal demo script for recording GIFs / asciicasts.

Usage:
    python examples/terminal_demo.py

For recording:
    # Option 1: asciinema
    asciinema rec -c "python examples/terminal_demo.py" demo.cast

    # Option 2: vhs (charmbracelet)
    vhs examples/demo.tape

This demo shows the core Aegis flow in a terminal-friendly format
with colored output, simulated typing, and clear visual separation.
"""

from __future__ import annotations

import asyncio
import sys
import time


# ANSI colors
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_RED = "\033[41m"


def typed(text: str, delay: float = 0.03) -> None:
    """Simulate typing effect."""
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def banner() -> None:
    print(f"\n{C.CYAN}{C.BOLD}")
    print("  ╔═══════════════════════════════════════╗")
    print("  ║          Aegis Demo                   ║")
    print("  ║   AI Agent Governance in 3 Lines      ║")
    print("  ╚═══════════════════════════════════════╝")
    print(f"{C.RESET}")
    time.sleep(0.5)


def section(title: str) -> None:
    print(f"\n{C.BOLD}{C.MAGENTA}{'─' * 50}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}{'─' * 50}{C.RESET}\n")
    time.sleep(0.3)


def show_policy() -> None:
    section("Step 1: Write a YAML Policy")
    typed("$ cat policy.yaml", delay=0.05)
    time.sleep(0.3)
    policy = f"""{C.DIM}# policy.yaml{C.RESET}
{C.CYAN}version{C.RESET}: "1"
{C.CYAN}defaults{C.RESET}:
  {C.CYAN}risk_level{C.RESET}: medium
  {C.CYAN}approval{C.RESET}: approve

{C.CYAN}rules{C.RESET}:
  - {C.CYAN}name{C.RESET}: read_safe
    {C.CYAN}match{C.RESET}: {{ type: "read" }}
    {C.CYAN}risk_level{C.RESET}: {C.GREEN}low{C.RESET}
    {C.CYAN}approval{C.RESET}: {C.GREEN}auto{C.RESET}

  - {C.CYAN}name{C.RESET}: write_review
    {C.CYAN}match{C.RESET}: {{ type: "write" }}
    {C.CYAN}risk_level{C.RESET}: {C.YELLOW}medium{C.RESET}
    {C.CYAN}approval{C.RESET}: {C.YELLOW}approve{C.RESET}

  - {C.CYAN}name{C.RESET}: no_deletes
    {C.CYAN}match{C.RESET}: {{ type: "delete" }}
    {C.CYAN}risk_level{C.RESET}: {C.RED}critical{C.RESET}
    {C.CYAN}approval{C.RESET}: {C.RED}block{C.RESET}"""
    print(policy)
    time.sleep(1)


def show_code() -> None:
    section("Step 2: Add Aegis to Your Agent (3 lines)")
    typed("$ python -c '", delay=0.05)
    code_lines = [
        f'{C.CYAN}from{C.RESET} aegis {C.CYAN}import{C.RESET} Action, Policy, Runtime',
        "",
        f'policy = Policy.from_yaml({C.GREEN}"policy.yaml"{C.RESET})',
        "runtime = Runtime(executor=my_executor, policy=policy)",
        "",
        f'{C.DIM}# Every action is now governed{C.RESET}',
        f"result = {C.CYAN}await{C.RESET} runtime.run_one("
        f'Action({C.GREEN}"read"{C.RESET}, {C.GREEN}"crm"{C.RESET}))',
    ]
    for line in code_lines:
        time.sleep(0.15)
        print(f"  {line}")
    print("'")
    time.sleep(1)


async def show_actions() -> None:
    section("Step 3: See Governance in Action")

    actions = [
        ("read", "crm", "LOW", "auto", "GREEN", "Fetch contacts"),
        ("write", "crm", "MEDIUM", "approve", "YELLOW", "Update record"),
        ("delete", "crm", "CRITICAL", "block", "RED", "Drop table"),
    ]

    for action_type, target, risk, approval, color, desc in actions:
        bg_code = getattr(C, f"BG_{color}")

        typed(f">>> runtime.run_one(Action(\"{action_type}\", \"{target}\"))", delay=0.04)
        time.sleep(0.3)

        # Show evaluation
        print(f"  {C.DIM}Evaluating...{C.RESET}", end="")
        time.sleep(0.2)
        print(f" {C.BOLD}matched rule:{C.RESET} {desc}")

        # Risk level
        print(f"  {C.BOLD}Risk:{C.RESET}     {bg_code}{C.BOLD} {risk} {C.RESET}")

        # Decision
        if approval == "auto":
            print(f"  {C.BOLD}Decision:{C.RESET} {C.GREEN}AUTO-APPROVED{C.RESET}")
            print(f"  {C.BOLD}Result:{C.RESET}   {C.GREEN}Executed successfully{C.RESET}")
        elif approval == "approve":
            print(f"  {C.BOLD}Decision:{C.RESET} {C.YELLOW}NEEDS APPROVAL{C.RESET}")
            time.sleep(0.3)
            print(f"  {C.DIM}  → Sending approval request to Slack...{C.RESET}")
            time.sleep(0.5)
            print(f"  {C.DIM}  → @admin approved via Slack{C.RESET}")
            print(f"  {C.BOLD}Result:{C.RESET}   {C.GREEN}Executed after approval{C.RESET}")
        else:
            print(f"  {C.BOLD}Decision:{C.RESET} {C.RED}BLOCKED{C.RESET}")
            print(f"  {C.BOLD}Result:{C.RESET}   {C.RED}Action rejected by policy{C.RESET}")

        # Audit note
        print(f"  {C.DIM}  → Audit logged to SQLite{C.RESET}")
        print()
        time.sleep(0.5)


def show_audit() -> None:
    section("Audit Trail")
    typed("$ aegis audit", delay=0.05)
    time.sleep(0.3)
    cols = f"{'ID':<4} {'Action':<12} {'Target':<8} "
    cols += f"{'Risk':<10} {'Decision':<12} {'Result':<10}"
    print(f"  {C.BOLD}{cols}{C.RESET}")
    print(f"  {'─' * 56}")
    G, Y, R, X = C.GREEN, C.YELLOW, C.RED, C.RESET
    rows = [
        ("1", "read", "crm", f"{G}LOW{X}", f"{G}auto{X}", f"{G}success{X}"),
        ("2", "write", "crm", f"{Y}MEDIUM{X}", f"{Y}approved{X}", f"{G}success{X}"),
        ("3", "delete", "crm", f"{R}CRITICAL{X}", f"{R}block{X}", f"{R}blocked{X}"),
    ]
    for row in rows:
        time.sleep(0.2)
        print(f"  {row[0]:<4} {row[1]:<12} {row[2]:<8} {row[3]:<20} {row[4]:<22} {row[5]}")
    time.sleep(1)


def outro() -> None:
    print(f"\n{C.CYAN}{C.BOLD}")
    print("  ╔═══════════════════════════════════════╗")
    print("  ║   pip install agent-aegis              ║")
    print("  ║   github.com/Acacian/aegis             ║")
    print("  ╚═══════════════════════════════════════╝")
    print(f"{C.RESET}")


async def main() -> None:
    banner()
    show_policy()
    show_code()
    await show_actions()
    show_audit()
    outro()


if __name__ == "__main__":
    asyncio.run(main())
