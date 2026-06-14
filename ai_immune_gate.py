#!/usr/bin/env python3
"""
AI Immune Gate - tiny wrapper for CI/CD and editor tasks.
Runs AI Immune Guard in fail-closed mode for combined auto-execution + mutation/propagation findings.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="CI gate wrapper for AI Immune Guard.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--report-dir", default="reports/ai-immune-guard")
    parser.add_argument("--github-annotations", action="store_true")
    args = parser.parse_args()

    script = Path(__file__).with_name("ai_immune_guard.py")
    cmd = [sys.executable, str(script), "--root", args.root, "--report-dir", args.report_dir]
    if args.github_annotations:
        cmd.append("--github-annotations")
    proc = subprocess.run(cmd, check=False)
    if proc.returncode == 2:
        print("AI Immune Gate: blocked combined auto-execution + self-mutation/propagation pattern.", file=sys.stderr)
        return 2
    if proc.returncode != 0:
        print("AI Immune Gate: scanner failed; refusing to continue in gate mode.", file=sys.stderr)
        return proc.returncode
    print("AI Immune Gate: no combined miasma-style auto-setup pattern detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
