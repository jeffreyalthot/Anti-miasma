#!/usr/bin/env python3
"""
AI Immune Gate

Small fail-closed wrapper for CI/editor tasks. It delegates all scanning to
AI Immune Guard and blocks only by returning the scanner's non-zero exit code.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="CI/editor gate wrapper for AI Immune Guard.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--report-dir", default="reports/ai-immune-guard")
    parser.add_argument("--github-annotations", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=30.0)
    args = parser.parse_args()

    script = Path(__file__).with_name("ai_immune_guard.py")
    cmd = [sys.executable, str(script), "--root", args.root, "--report-dir", args.report_dir]
    if args.github_annotations:
        cmd.append("--github-annotations")
    if args.watch:
        cmd.extend(["--watch", "--interval", str(args.interval)])

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
