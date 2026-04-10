#!/usr/bin/env python3
"""SEO frontmatter audit for docs/**/*.md.

Enforces that every documentation page has a YAML frontmatter `description:`
field within the length window Google uses for SERP snippets. Run as a
pre-commit hook (see .pre-commit-config.yaml) or manually:

    python scripts/seo-audit.py            # audit all docs
    python scripts/seo-audit.py docs/foo.md  # audit a single file

Exit code 0 = pass, 1 = at least one violation.

Why this exists
---------------
Pages without `description:` fall back to the site-wide
`mkdocs.yml:site_description`, which means every such page ships an
identical meta description. Google then shows a generic snippet (or
auto-generated one) and the page loses click-through. Forcing every page
to declare its own description in a 50-160 character window keeps SERP
snippets unique and within Google's display limit.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REQUIRED_LEN = 50
MAX_LEN = 160
SKIP_NAMES = {"index.md", "404.md"}
DOCS_ROOT = Path("docs")

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
DESCRIPTION_RE = re.compile(
    r'^description:\s*["\']?(.+?)["\']?\s*$',
    re.MULTILINE,
)


def audit_file(path: Path) -> str | None:
    """Return None if the file passes, otherwise an error message."""
    text = path.read_text(encoding="utf-8")
    fm_match = FRONTMATTER_RE.match(text)
    if not fm_match:
        return "no frontmatter block"
    fm = fm_match.group(1)
    desc_match = DESCRIPTION_RE.search(fm)
    if not desc_match:
        return "missing 'description:' field"
    desc = desc_match.group(1).strip().rstrip('"').strip()
    if len(desc) < REQUIRED_LEN:
        return f"description too short ({len(desc)} chars, need {REQUIRED_LEN}+)"
    if len(desc) > MAX_LEN:
        return f"description too long ({len(desc)} chars, max {MAX_LEN})"
    return None


def collect_targets(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args if Path(a).suffix == ".md"]
    return sorted(DOCS_ROOT.rglob("*.md"))


def main(argv: list[str]) -> int:
    targets = collect_targets(argv[1:])
    failures: list[tuple[Path, str]] = []
    checked = 0

    for path in targets:
        if path.name in SKIP_NAMES:
            continue
        if not path.exists():
            continue
        checked += 1
        error = audit_file(path)
        if error:
            failures.append((path, error))

    if failures:
        print(f"SEO frontmatter audit: {len(failures)} of {checked} file(s) failed")
        for path, reason in failures:
            print(f"  {path}: {reason}")
        print()
        print(
            f'Fix: add `description: "..."` to the YAML frontmatter '
            f"({REQUIRED_LEN}-{MAX_LEN} chars)."
        )
        return 1

    print(f"SEO frontmatter audit: all {checked} doc(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
