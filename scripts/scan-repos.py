#!/usr/bin/env python3
"""Batch-scan GitHub repos and produce JSON for the scan report page.

Usage:
    python scripts/scan-repos.py            # scan all, output JSON
    python scripts/scan-repos.py --limit 5  # scan first 5 only (testing)
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Ensure aegis is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.cli.scan import _grade, scan_directory  # noqa: E402

# ---------------------------------------------------------------------------
# Target repos — name, GitHub URL, approximate stars (for display)
# ---------------------------------------------------------------------------

REPOS: list[dict[str, str]] = [
    # === Tier 1: Major frameworks (already in v1 report) ===
    {"name": "LangChain", "url": "https://github.com/langchain-ai/langchain", "stars": "108K"},
    {"name": "CrewAI", "url": "https://github.com/crewAIInc/crewAI", "stars": "28K"},
    {"name": "AutoGen", "url": "https://github.com/microsoft/autogen", "stars": "42K"},
    {"name": "LlamaIndex", "url": "https://github.com/run-llama/llama_index", "stars": "40K"},
    {"name": "LiteLLM", "url": "https://github.com/BerriAI/litellm", "stars": "20K"},
    {"name": "Pydantic AI", "url": "https://github.com/pydantic/pydantic-ai", "stars": "12K"},
    {
        "name": "OpenAI Agents",
        "url": "https://github.com/openai/openai-agents-python",
        "stars": "6K",
    },
    {"name": "Google ADK", "url": "https://github.com/google/adk-python", "stars": "12K"},
    {
        "name": "awesome-llm-apps",
        "url": "https://github.com/Shubhamsaboo/awesome-llm-apps",
        "stars": "20K",
    },
    # === Tier 2: Popular AI agent frameworks ===
    {"name": "DSPy", "url": "https://github.com/stanfordnlp/dspy", "stars": "22K"},
    {"name": "Haystack", "url": "https://github.com/deepset-ai/haystack", "stars": "18K"},
    # Semantic Kernel excluded: C# primary, Python is thin wrapper (3 findings all test fixtures)
    {"name": "MetaGPT", "url": "https://github.com/geekan/MetaGPT", "stars": "48K"},
    {"name": "ChatDev", "url": "https://github.com/OpenBMB/ChatDev", "stars": "26K"},
    {"name": "CAMEL", "url": "https://github.com/camel-ai/camel", "stars": "10K"},
    # Swarm excluded: deprecated educational demo (512 lines)
    {"name": "Agno", "url": "https://github.com/agno-agi/agno", "stars": "20K"},
    {"name": "mem0", "url": "https://github.com/mem0ai/mem0", "stars": "25K"},
    {"name": "Composio", "url": "https://github.com/ComposioHQ/composio", "stars": "15K"},
    {"name": "browser-use", "url": "https://github.com/browser-use/browser-use", "stars": "55K"},
    # === Tier 3: Coding agents ===
    {"name": "OpenHands", "url": "https://github.com/All-Hands-AI/OpenHands", "stars": "50K"},
    {"name": "SWE-agent", "url": "https://github.com/SWE-agent/SWE-agent", "stars": "15K"},
    {"name": "aider", "url": "https://github.com/Aider-AI/aider", "stars": "30K"},
    {
        "name": "Open Interpreter",
        "url": "https://github.com/OpenInterpreter/open-interpreter",
        "stars": "58K",
    },
    # Cline excluded: VS Code extension, only 8 Python files
    {"name": "GPT Engineer", "url": "https://github.com/AntonOsika/gpt-engineer", "stars": "52K"},
    {"name": "Devika", "url": "https://github.com/stitionai/devika", "stars": "18K"},
    # === Tier 4: LLM tooling & orchestration ===
    # Excluded (AI libraries, not agent frameworks):
    #   Instructor, Guidance, Outlines, Magentic, ell, txtai, Chainlit
    {"name": "Mirascope", "url": "https://github.com/Mirascope/mirascope", "stars": "2K"},
    {"name": "ControlFlow", "url": "https://github.com/PrefectHQ/ControlFlow", "stars": "2K"},
    {"name": "Letta", "url": "https://github.com/letta-ai/letta", "stars": "15K"},
    # === Tier 5: RAG & data pipelines ===
    {"name": "Embedchain", "url": "https://github.com/embedchain/embedchain", "stars": "10K"},
    {"name": "Crawl4AI", "url": "https://github.com/unclecode/crawl4ai", "stars": "35K"},
    {"name": "Firecrawl", "url": "https://github.com/mendableai/firecrawl", "stars": "25K"},
    {"name": "Docling", "url": "https://github.com/DS4SD/docling", "stars": "18K"},
    # === Tier 6: Multi-agent & workflow ===
    {"name": "Agency Swarm", "url": "https://github.com/VRSEN/agency-swarm", "stars": "4K"},
    {"name": "Langflow", "url": "https://github.com/langflow-ai/langflow", "stars": "48K"},
    # Flowise excluded: TypeScript project, 0 Python files
    {"name": "Dify", "url": "https://github.com/langgenius/dify", "stars": "75K"},
    {"name": "SuperAGI", "url": "https://github.com/TransformerOptimus/SuperAGI", "stars": "15K"},
    {"name": "Promptflow", "url": "https://github.com/microsoft/promptflow", "stars": "10K"},
    {"name": "TaskWeaver", "url": "https://github.com/microsoft/TaskWeaver", "stars": "5K"},
    # === Tier 7: Misc AI tools with agent capabilities ===
    {"name": "Griptape", "url": "https://github.com/griptape-ai/griptape", "stars": "2K"},
    {"name": "Smolagents", "url": "https://github.com/huggingface/smolagents", "stars": "15K"},
]


def clone_repo(url: str, dest: Path, *, depth: int = 1) -> bool:
    """Shallow-clone a repo. Returns True on success."""
    try:
        subprocess.run(
            ["git", "clone", "--depth", str(depth), "--single-branch", url, str(dest)],
            capture_output=True,
            timeout=120,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"  WARN: clone failed for {url}: {e}", file=sys.stderr)
        return False


def scan_repo(repo: dict[str, str], clone_dir: Path) -> dict | None:
    """Clone and scan a single repo. Returns result dict or None on failure."""
    name = repo["name"]
    url = repo["url"]
    print(f"Scanning {name}...", flush=True)

    dest = clone_dir / name.lower().replace(" ", "-")
    if not clone_repo(url, dest):
        return None

    file_count, findings = scan_directory(dest)

    # Categorize
    categories: dict[str, int] = {}
    for f in findings:
        categories[f.category] = categories.get(f.category, 0) + 1

    # Pick top 3 examples
    examples = []
    for f in findings[:3]:
        try:
            rel = str(Path(f.file).relative_to(dest))
        except ValueError:
            rel = f.file
        examples.append(
            {
                "file": rel,
                "line": f.line,
                "category": f.category,
                "detail": f.detail,
                "owasp": f.owasp_risk,
            }
        )

    grade = _grade(len(findings))

    # Compute dir name (for backward compat)
    dir_name = name.lower().replace(" ", "-")

    return {
        "dir": dir_name,
        "name": name,
        "stars": repo["stars"],
        "url": url,
        "files": file_count,
        "findings": len(findings),
        "grade": grade,
        "categories": categories,
        "examples": examples,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch scan GitHub repos for AI security report")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of repos (0=all)")
    parser.add_argument("--output", type=str, default="", help="Output JSON file path")
    args = parser.parse_args()

    targets = REPOS[: args.limit] if args.limit > 0 else REPOS

    results = []
    with tempfile.TemporaryDirectory(prefix="aegis-scan-") as tmpdir:
        clone_dir = Path(tmpdir)
        for repo in targets:
            result = scan_repo(repo, clone_dir)
            if result:
                results.append(result)
                # Clean up to save disk space
                dest = clone_dir / repo["name"].lower().replace(" ", "-")
                shutil.rmtree(dest, ignore_errors=True)

    # Sort by findings descending
    results.sort(key=lambda r: r["findings"], reverse=True)

    output = json.dumps(results, ensure_ascii=False, indent=2)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"\nResults written to {args.output}")
    else:
        print(output)

    # Summary
    total_repos = len(results)
    total_findings = sum(r["findings"] for r in results)
    total_files = sum(r["files"] for r in results)
    grade_f = sum(1 for r in results if r["grade"] == "F")
    print("\n=== Summary ===", file=sys.stderr)
    print(f"Repos scanned: {total_repos}", file=sys.stderr)
    print(f"Total files: {total_files:,}", file=sys.stderr)
    print(f"Total findings: {total_findings:,}", file=sys.stderr)
    print(f"Grade F: {grade_f}/{total_repos}", file=sys.stderr)


if __name__ == "__main__":
    main()
