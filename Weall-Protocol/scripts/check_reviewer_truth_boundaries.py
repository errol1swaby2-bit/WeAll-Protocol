#!/usr/bin/env python3
"""Check reviewert-facing docs for high-risk unbounded readiness claims.

This is a conservative documentation guard. It is not a semantic proof. It scans
Markdown files for risky phrases that should normally appear only with explicit
negation, lock, milestone, or future-work context.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC_ROOTS = [ROOT / "docs", ROOT / "README.md", ROOT.parent / "README.md"]

RISKY_PATTERNS = [
    re.compile(r"\bmainnet\s+ready\b", re.IGNORECASE),
    re.compile(r"\bready\s+for\s+mainnet\b", re.IGNORECASE),
    re.compile(r"\bpublic\s+multi[- ]validator\s+BFT\s+ready\b", re.IGNORECASE),
    re.compile(r"\bpublic\s+BFT\s+ready\b", re.IGNORECASE),
    re.compile(r"\blive\s+economics\b", re.IGNORECASE),
    re.compile(r"\beconomics\s+are\s+live\b", re.IGNORECASE),
    re.compile(r"\bpublic\s+testnet\s+ready\b", re.IGNORECASE),
    re.compile(r"\bproduction[- ]ready\s+governance\b", re.IGNORECASE),
    re.compile(r"\bproduction[- ]grade\s+private\s+messaging\b", re.IGNORECASE),
]

SAFE_CONTEXT_WORDS = {
    "not",
    "no",
    "without",
    "unless",
    "until",
    "requires",
    "require",
    "required",
    "future",
    "milestone",
    "work",
    "not-yet",
    "not yet",
    "does not",
    "do not",
    "must not",
    "cannot",
    "can't",
    "claim",
    "claimed",
    "unclaimed",
    "truth boundary",
    "boundary",
    "locked",
    "visible/locked",
}


def iter_markdown_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for root in DOC_ROOTS:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(sorted(root.rglob("*.md")))
    return files


def context_is_safe(line: str) -> bool:
    lowered = line.lower()
    return any(word in lowered for word in SAFE_CONTEXT_WORDS)


def main() -> int:
    findings: list[str] = []
    for path in iter_markdown_files():
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            rel = path
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for lineno, line in enumerate(lines, start=1):
            previous_context = " ".join(lines[max(0, lineno - 4):lineno - 1])
            combined_context = f"{previous_context} {line}"
            for pattern in RISKY_PATTERNS:
                if pattern.search(line) and not context_is_safe(combined_context):
                    findings.append(f"{rel}:{lineno}: risky unbounded claim: {line.strip()}")

    if findings:
        print("[truth-boundary] FAIL: high-risk unbounded readiness claims found")
        for finding in findings:
            print(finding)
        print("\nRewrite these lines with explicit truth boundaries before reviewert submission.")
        return 1

    print("[truth-boundary] OK: no high-risk unbounded reviewert readiness claims found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
