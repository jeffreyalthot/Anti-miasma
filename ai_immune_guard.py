#!/usr/bin/env python3
"""
AI Immune Guard - defensive static scanner for repository auto-setup files.

Safety model:
- Does not execute scanned files or commands.
- Does not mutate source files, containers, GitHub infrastructure, or external systems.
- Does not scan other containers directly.
- Reads only repository text files matching allowlisted auto-setup paths/patterns.
- Emits JSON/Markdown/SARIF reports and returns non-zero in gate mode when both
  auto-execution and self-mutation/propagation indicators are present.

Primary targets:
- .vscode/tasks.json
- .cursor/rules/setup.mdc
- .github/workflows/*.yml / *.yaml
- package.json scripts, Makefile, setup.py, pyproject.toml, tox.ini, noxfile.py,
  Dockerfile, docker-compose.yml/yaml, devcontainer.json
"""
from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "1.0.0-safe"
DEFAULT_REPORT_DIR = "reports/ai-immune-guard"

AUTO_SETUP_PATTERNS = [
    ".vscode/tasks.json",
    ".cursor/rules/setup.mdc",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "package.json",
    "Makefile",
    "makefile",
    "setup.py",
    "pyproject.toml",
    "tox.ini",
    "noxfile.py",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".devcontainer/devcontainer.json",
    ".devcontainer/*.json",
    ".devcontainer/*.jsonc",
]

TEXT_EXTENSIONS = {
    ".json", ".jsonc", ".mdc", ".md", ".yml", ".yaml", ".toml", ".ini",
    ".py", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".txt", "",
}

AUTO_EXECUTION_INDICATORS: Dict[str, str] = {
    r"\bpostinstall\b|\bpreinstall\b|\bprepare\b|\bprestart\b|\bpoststart\b": "package-manager lifecycle auto-execution hook",
    r"\brunOn\b|\brunOptions\b|\bisBackground\b|\bproblemMatcher\b": "VS Code task auto/background execution metadata",
    r"\bcommand\s*[:=]\s*[\"']?[^\n]+": "command field inside an auto-setup surface",
    r"\bshell\s*[:=]\s*[\"']?[^\n]+": "shell execution directive",
    r"\bon:\s*(push|pull_request|workflow_run|schedule|repository_dispatch|workflow_dispatch)\b": "GitHub Actions event trigger",
    r"\bcron:\s*[\"'][^\"']+[\"']": "scheduled execution trigger",
    r"\bENTRYPOINT\b|\bCMD\b|\bRUN\b": "container build/runtime execution directive",
    r"\bmake\s+install\b|\binstall:\b|\bsetup\b|\bbootstrap\b": "install/bootstrap automation directive",
    r"\bcurl\b[^\n|;]*(\||>)|\bwget\b[^\n|;]*(\||>)": "remote script acquisition/execution pattern",
    r"\bInvoke-WebRequest\b|\biwr\b|\bStart-Process\b": "PowerShell remote/start execution pattern",
    r"\bpython\s+-c\b|\bnode\s+-e\b|\bbash\s+-c\b|\bsh\s+-c\b": "inline interpreter execution",
}

SELF_MUTATION_PROPAGATION_INDICATORS: Dict[str, str] = {
    r"\b(self[-_ ]?modify|self[-_ ]?mutation|polymorphic|metamorphic|mutate)\b": "explicit self-mutation terminology",
    r"\bcopy\b[^\n]{0,80}\b(\.vscode|\.cursor|tasks\.json|setup\.mdc|workflow|container|devcontainer)\b": "copy into auto-setup/container control path",
    r"\bcp\b[^\n]{0,80}\b(\.vscode|\.cursor|tasks\.json|setup\.mdc|workflow|container|devcontainer)\b": "POSIX copy into auto-setup/container control path",
    r"\bCopy-Item\b[^\n]{0,120}\b(\.vscode|\.cursor|tasks\.json|setup\.mdc|workflow|container|devcontainer)\b": "PowerShell copy into auto-setup/container control path",
    r"\bshutil\.copy(?:file|tree)?\b|\bfs\.copyFileSync\b|\bFile\.write\b": "programmatic file replication/write primitive",
    r"\bwrite_text\b|\bwrite_bytes\b|\bopen\s*\([^\n]{0,80}[\"']w[\"']|\bfs\.writeFileSync\b": "source/write mutation primitive",
    r"\bsed\s+-i\b|\bperl\s+-pi\b|\bReplace\b|\bSet-Content\b|\bAdd-Content\b": "in-place text mutation primitive",
    r"\bgit\s+(clone|pull|push|commit|am|apply)\b": "git replication or mutation primitive",
    r"\bgh\s+(repo|workflow|api|gist|pr|release)\b": "GitHub CLI automation primitive",
    r"\bdocker\s+(cp|exec|run|compose|context|container)\b|\bkubectl\s+(exec|cp|apply|create)\b": "cross-container orchestration primitive",
    r"\bfor\b[^\n]{0,100}\bin\b[^\n]{0,100}\b(containers?|repos?|workspaces?|projects?)\b": "loop targeting containers/repositories/workspaces",
    r"\bbase64\s+-d\b|\bfromCharCode\b|\beval\s*\(|\bexec\s*\(|\bFunction\s*\(": "obfuscated dynamic code generation primitive",
}

PRIVACY_SENSITIVE_PATTERNS: Dict[str, str] = {
    r"gh[pousr]_[A-Za-z0-9_]{20,}": "possible GitHub token",
    r"AKIA[0-9A-Z]{16}": "possible AWS access key id",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----": "possible private key",
    r"(?i)password\s*[:=]\s*[^\s]+": "possible password assignment",
    r"(?i)token\s*[:=]\s*[^\s]+": "possible token assignment",
}

MAX_FILE_BYTES = 1_000_000
MAX_SNIPPET = 220


@dataclasses.dataclass
class Evidence:
    category: str
    reason: str
    pattern: str
    line: int
    snippet: str


@dataclasses.dataclass
class Finding:
    path: str
    sha256: str
    size_bytes: int
    auto_execution: List[Evidence]
    self_mutation: List[Evidence]
    privacy_redactions: int
    severity: str
    verdict: str
    neutralization: str

    @property
    def is_blocking(self) -> bool:
        return self.severity in {"critical", "high"} and self.auto_execution and self.self_mutation


def redact_sensitive(text: str) -> Tuple[str, int]:
    redactions = 0
    out = text
    for pattern, label in PRIVACY_SENSITIVE_PATTERNS.items():
        matches = list(re.finditer(pattern, out))
        if matches:
            redactions += len(matches)
            out = re.sub(pattern, f"<REDACTED:{label}>", out)
    return out, redactions


def normalize_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def is_target_path(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    return any(fnmatch.fnmatch(rel, pattern) for pattern in AUTO_SETUP_PATTERNS)


def safe_read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {"Makefile", "makefile", "Dockerfile"}:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def iter_target_files(root: Path) -> Iterable[Path]:
    root = root.resolve()
    skipped_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skipped_dirs and not d.startswith(".cache")]
        cur = Path(current)
        for name in files:
            p = cur / name
            rel = normalize_path(p, root)
            if is_target_path(rel):
                yield p


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def snippet_for(text: str, start: int, end: int) -> str:
    left = max(0, start - 90)
    right = min(len(text), end + 90)
    snippet = text[left:right].replace("\r", " ").replace("\n", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if len(snippet) > MAX_SNIPPET:
        snippet = snippet[: MAX_SNIPPET - 3] + "..."
    return snippet


def collect_evidence(text: str, indicators: Dict[str, str], category: str) -> List[Evidence]:
    evidence: List[Evidence] = []
    seen = set()
    for pattern, reason in indicators.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.MULTILINE):
            key = (category, reason, line_number(text, match.start()))
            if key in seen:
                continue
            seen.add(key)
            evidence.append(
                Evidence(
                    category=category,
                    reason=reason,
                    pattern=pattern,
                    line=line_number(text, match.start()),
                    snippet=snippet_for(text, match.start(), match.end()),
                )
            )
            if len(evidence) >= 40:
                return evidence
    return evidence


def classify(auto: Sequence[Evidence], mutation: Sequence[Evidence]) -> Tuple[str, str, str]:
    if auto and mutation:
        return (
            "critical",
            "AUTO_EXECUTION_AND_SELF_MUTATION_OR_PROPAGATION_DETECTED",
            "Non-destructive neutralization: block the setup/gate in CI, do not execute the file, review manually, rotate any exposed secrets, and replace the auto-setup surface with a reviewed minimal task.",
        )
    if auto:
        return (
            "medium",
            "AUTO_EXECUTION_SURFACE_DETECTED_WITHOUT_MUTATION_EVIDENCE",
            "Allow only after human review; keep commands explicit and pinned.",
        )
    if mutation:
        return (
            "medium",
            "MUTATION_OR_PROPAGATION_PRIMITIVE_DETECTED_WITHOUT_AUTO_EXECUTION_EVIDENCE",
            "Review intent; avoid write/copy operations in setup surfaces.",
        )
    return ("info", "NO_COMBINED_MIASMA_PATTERN_DETECTED", "No action required.")


def scan_file(path: Path, root: Path) -> Optional[Finding]:
    raw = safe_read_text(path)
    if raw is None:
        return None
    redacted, redactions = redact_sensitive(raw)
    auto = collect_evidence(redacted, AUTO_EXECUTION_INDICATORS, "auto_execution")
    mutation = collect_evidence(redacted, SELF_MUTATION_PROPAGATION_INDICATORS, "self_mutation_or_propagation")
    severity, verdict, neutralization = classify(auto, mutation)
    data = path.read_bytes()
    return Finding(
        path=normalize_path(path, root),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        auto_execution=auto,
        self_mutation=mutation,
        privacy_redactions=redactions,
        severity=severity,
        verdict=verdict,
        neutralization=neutralization,
    )


def finding_to_dict(f: Finding) -> Dict[str, object]:
    return {
        "path": f.path,
        "sha256": f.sha256,
        "size_bytes": f.size_bytes,
        "severity": f.severity,
        "verdict": f.verdict,
        "blocking": f.is_blocking,
        "privacy_redactions": f.privacy_redactions,
        "neutralization": f.neutralization,
        "auto_execution_evidence": [dataclasses.asdict(e) for e in f.auto_execution],
        "self_mutation_or_propagation_evidence": [dataclasses.asdict(e) for e in f.self_mutation],
    }


def build_report(root: Path, findings: List[Finding]) -> Dict[str, object]:
    blocking = [f for f in findings if f.is_blocking]
    return {
        "tool": "AI Immune Guard",
        "version": VERSION,
        "mode": "static_non_destructive_repository_scope",
        "generated_at_epoch": int(time.time()),
        "root": str(root.resolve()),
        "safety_invariants": [
            "no scanned command execution",
            "no source mutation",
            "no cross-container access",
            "no secrets printed; sensitive-looking values are redacted",
            "CI blocking is done by process exit code only",
        ],
        "summary": {
            "files_scanned": len(findings),
            "blocking_findings": len(blocking),
            "critical_findings": sum(1 for f in findings if f.severity == "critical"),
            "medium_findings": sum(1 for f in findings if f.severity == "medium"),
            "info_findings": sum(1 for f in findings if f.severity == "info"),
        },
        "findings": [finding_to_dict(f) for f in findings],
    }


def write_json(report: Dict[str, object], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "ai_immune_report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_markdown(report: Dict[str, object], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "ai_immune_report.md"
    lines: List[str] = []
    summary = report["summary"]  # type: ignore[index]
    lines.append("# AI Immune Guard Report")
    lines.append("")
    lines.append(f"Tool version: `{report['version']}`")
    lines.append(f"Mode: `{report['mode']}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    for key, value in summary.items():  # type: ignore[union-attr]
        lines.append(f"- **{key}**: {value}")
    lines.append("")
    lines.append("## Safety invariants")
    lines.append("")
    for item in report["safety_invariants"]:  # type: ignore[index]
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    findings = report["findings"]  # type: ignore[index]
    if not findings:
        lines.append("No auto-setup files were found in the selected repository scope.")
    for item in findings:  # type: ignore[assignment]
        lines.append(f"### `{item['path']}`")
        lines.append("")
        lines.append(f"- Severity: **{item['severity']}**")
        lines.append(f"- Verdict: `{item['verdict']}`")
        lines.append(f"- Blocking: `{item['blocking']}`")
        lines.append(f"- SHA-256: `{item['sha256']}`")
        lines.append(f"- Size: `{item['size_bytes']}` bytes")
        lines.append(f"- Privacy redactions: `{item['privacy_redactions']}`")
        lines.append(f"- Neutralization: {item['neutralization']}")
        lines.append("")
        for section_name, evidence_key in [
            ("Auto-execution evidence", "auto_execution_evidence"),
            ("Self-mutation / propagation evidence", "self_mutation_or_propagation_evidence"),
        ]:
            lines.append(f"#### {section_name}")
            evidence = item[evidence_key]
            if not evidence:
                lines.append("No evidence in this category.")
            else:
                for ev in evidence:
                    lines.append(f"- Line `{ev['line']}`: {ev['reason']} — `{ev['snippet']}`")
            lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_sarif(report: Dict[str, object], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for f in report["findings"]:  # type: ignore[index]
        if not f["blocking"] and f["severity"] == "info":
            continue
        level = "error" if f["severity"] == "critical" else "warning"
        evidence = f["auto_execution_evidence"] + f["self_mutation_or_propagation_evidence"]
        line = evidence[0]["line"] if evidence else 1
        results.append(
            {
                "ruleId": f["verdict"],
                "level": level,
                "message": {"text": f"{f['verdict']}: {f['neutralization']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["path"]},
                            "region": {"startLine": int(line)},
                        }
                    }
                ],
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Immune Guard",
                        "informationUri": "https://github.com/security",
                        "version": VERSION,
                        "rules": [],
                    }
                },
                "results": results,
            }
        ],
    }
    path = out_dir / "ai_immune_report.sarif"
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path


def emit_github_annotations(findings: Sequence[Finding]) -> None:
    for f in findings:
        if f.severity == "info":
            continue
        evidence = (f.auto_execution or f.self_mutation)
        line = evidence[0].line if evidence else 1
        level = "error" if f.is_blocking else "warning"
        msg = f"{f.verdict}: {f.neutralization}"
        msg = msg.replace("\n", " ").replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{level} file={f.path},line={line},title=AI Immune Guard::{msg}")


def scan_once(root: Path, out_dir: Path, github_annotations: bool) -> int:
    findings = []
    for p in iter_target_files(root):
        finding = scan_file(p, root)
        if finding:
            findings.append(finding)
    report = build_report(root, findings)
    json_path = write_json(report, out_dir)
    md_path = write_markdown(report, out_dir)
    sarif_path = write_sarif(report, out_dir)
    if github_annotations:
        emit_github_annotations(findings)
    print(f"AI Immune Guard report: {json_path}")
    print(f"AI Immune Guard markdown: {md_path}")
    print(f"AI Immune Guard SARIF: {sarif_path}")
    return 2 if any(f.is_blocking for f in findings) else 0


def watch(root: Path, out_dir: Path, interval: float, github_annotations: bool) -> int:
    last_hash = ""
    print("AI Immune Guard watch mode active. Repository-scope static scanning only.")
    while True:
        snapshot = []
        for p in iter_target_files(root):
            try:
                stat = p.stat()
                snapshot.append((normalize_path(p, root), stat.st_mtime_ns, stat.st_size))
            except OSError:
                continue
        digest = hashlib.sha256(repr(sorted(snapshot)).encode()).hexdigest()
        if digest != last_hash:
            last_hash = digest
            code = scan_once(root, out_dir, github_annotations)
            if code == 2:
                print("AI Immune Guard watch detected a blocking condition. No files were changed.")
        time.sleep(max(5.0, interval))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Static non-destructive scanner for dangerous auto-setup surfaces.")
    parser.add_argument("--root", default=".", help="Repository root to scan. Default: current directory.")
    parser.add_argument("--report-dir", default=DEFAULT_REPORT_DIR, help="Report output directory.")
    parser.add_argument("--github-annotations", action="store_true", help="Emit GitHub Actions annotations.")
    parser.add_argument("--watch", action="store_true", help="Opt-in local watch mode. Does not install persistence.")
    parser.add_argument("--interval", type=float, default=30.0, help="Watch interval seconds, minimum 5.")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    out_dir = (root / args.report_dir).resolve() if not Path(args.report_dir).is_absolute() else Path(args.report_dir)
    if not root.exists() or not root.is_dir():
        print(f"Invalid repository root: {root}", file=sys.stderr)
        return 1
    if args.watch:
        return watch(root, out_dir, args.interval, args.github_annotations)
    return scan_once(root, out_dir, args.github_annotations)


if __name__ == "__main__":
    raise SystemExit(main())
