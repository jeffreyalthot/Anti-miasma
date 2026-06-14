#!/usr/bin/env python3
"""
AI Immune Guard - safe polyglot static scanner for repository auto-setup surfaces.

It is intentionally defensive:
- static analysis only;
- no execution of scanned commands;
- no source mutation;
- no cross-container access;
- no external reporting or network calls;
- CI blocking is only a non-zero exit code;
- reports redact common secret patterns;
- only allowlisted auto-setup surfaces are scanned.
"""
from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ai_immune_polyglot_rules import (
    AUTO_EXECUTION_RULES,
    AUTO_SETUP_PATTERNS,
    DEFENSIVE_CONTEXT_RULES,
    MAX_EVIDENCE_PER_CATEGORY,
    MAX_FILE_BYTES,
    MAX_SNIPPET_CHARS,
    MUTATION_PROPAGATION_RULES,
    PRIVACY_SENSITIVE_PATTERNS,
    SAFETY_MODEL_TEXT,
    SKIPPED_DIRECTORIES,
    SPECIAL_TEXT_NAMES,
    TEXT_EXTENSIONS,
    VERSION,
    Rule,
)

DEFAULT_REPORT_DIR = "reports/ai-immune-guard"


@dataclasses.dataclass
class Evidence:
    category: str
    rule_id: str
    reason: str
    kind: str
    score: int
    line: int
    snippet: str


@dataclasses.dataclass
class LanguageAgnosticFeatures:
    path: str
    bytes_size: int
    line_count: int
    token_count: int
    max_line_length: int
    high_entropy_string_count: int
    long_encoded_blob_count: int
    auto_setup_path_reference_count: int
    executable_extension_reference_count: int


@dataclasses.dataclass
class Finding:
    path: str
    sha256: str
    size_bytes: int
    language_surface: str
    features: LanguageAgnosticFeatures
    auto_execution: List[Evidence]
    self_mutation: List[Evidence]
    defensive_context: List[Evidence]
    privacy_redactions: int
    auto_score: int
    mutation_score: int
    defensive_score: int
    confidence: float
    severity: str
    verdict: str
    neutralization: str

    @property
    def is_blocking(self) -> bool:
        return self.severity == "critical" and bool(self.auto_execution) and bool(self.self_mutation)


@dataclasses.dataclass
class ScanOptions:
    root: Path
    report_dir: Path
    github_annotations: bool = False
    explain_nonblocking: bool = True


def normalize_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def is_target_path(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    return any(fnmatch.fnmatch(rel, pattern) for pattern in AUTO_SETUP_PATTERNS)


def is_text_candidate(path: Path) -> bool:
    return path.name in SPECIAL_TEXT_NAMES or path.suffix.lower() in TEXT_EXTENSIONS


def safe_read_text(path: Path) -> Optional[str]:
    try:
        stat = path.stat()
        if stat.st_size > MAX_FILE_BYTES:
            return None
        if not is_text_candidate(path):
            return None
        data = path.read_bytes()
        if b"\x00" in data[:4096]:
            return None
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def iter_target_files(root: Path) -> Iterable[Path]:
    root = root.resolve()
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIPPED_DIRECTORIES and not d.startswith(".cache")]
        cur = Path(current)
        for name in files:
            p = cur / name
            rel = normalize_path(p, root)
            if is_target_path(rel):
                yield p


def redact_sensitive(text: str) -> Tuple[str, int]:
    redactions = 0
    out = text
    for pattern, label in PRIVACY_SENSITIVE_PATTERNS.items():
        matches = list(re.finditer(pattern, out))
        if matches:
            redactions += len(matches)
            out = re.sub(pattern, f"<REDACTED:{label}>", out)
    return out, redactions


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def snippet_for(text: str, start: int, end: int) -> str:
    left = max(0, start - 100)
    right = min(len(text), end + 100)
    snippet = text[left:right].replace("\r", " ").replace("\n", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if len(snippet) > MAX_SNIPPET_CHARS:
        snippet = snippet[: MAX_SNIPPET_CHARS - 3] + "..."
    return snippet


def collect_evidence(text: str, rules: Sequence[Rule], category: str) -> List[Evidence]:
    evidence: List[Evidence] = []
    seen = set()
    for rule in rules:
        try:
            iterator = re.finditer(rule.pattern, text, flags=re.MULTILINE | re.IGNORECASE)
        except re.error:
            continue
        for match in iterator:
            line = line_number(text, match.start())
            key = (category, rule.rule_id, line)
            if key in seen:
                continue
            seen.add(key)
            evidence.append(
                Evidence(
                    category=category,
                    rule_id=rule.rule_id,
                    reason=rule.reason,
                    kind=rule.kind,
                    score=rule.score,
                    line=line,
                    snippet=snippet_for(text, match.start(), match.end()),
                )
            )
            if len(evidence) >= MAX_EVIDENCE_PER_CATEGORY:
                return evidence
    return evidence


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def extract_quoted_strings(text: str) -> Iterable[str]:
    pattern = r'(?s)(["\'])(.{16,4096}?)(?<!\\)\1'
    for match in re.finditer(pattern, text):
        yield match.group(2)


def language_surface_for(path: str) -> str:
    p = path.lower()
    if p.endswith("tasks.json") or "/.vscode/" in p:
        return "vscode-task-json"
    if p.endswith("setup.mdc") or "/.cursor/rules/" in p:
        return "cursor-rule-mdc"
    if "/.github/workflows/" in p:
        return "github-actions-yaml"
    if "/.devcontainer/" in p:
        return "devcontainer-json"
    if p.endswith("package.json"):
        return "node-package-json"
    if p.endswith("dockerfile") or p.endswith("/dockerfile") or p == "dockerfile":
        return "dockerfile"
    if p.endswith(("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml")):
        return "compose-yaml"
    if p.endswith(("makefile", "justfile", "taskfile.yml", "taskfile.yaml")):
        return "task-runner-file"
    if p.endswith(("setup.py", "pyproject.toml", "tox.ini", "noxfile.py", "setup.cfg")):
        return "python-build-setup"
    return "auto-setup-text-surface"


def compute_features(path: str, text: str, size: int) -> LanguageAgnosticFeatures:
    lines = text.splitlines()
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_\-:.]{1,}|[{}()[\];|&><=$]", text)
    quoted = list(extract_quoted_strings(text))
    high_entropy = 0
    encoded = 0
    encoded_re = re.compile(r"^[A-Za-z0-9+/=]{80,}$|^[A-Fa-f0-9]{120,}$")
    for value in quoted[:256]:
        compact = re.sub(r"\s+", "", value)
        if len(compact) >= 80 and shannon_entropy(compact) >= 4.4:
            high_entropy += 1
        if encoded_re.match(compact):
            encoded += 1
    control_refs = len(re.findall(r"(?i)\.vscode/tasks\.json|\.cursor/rules/setup\.mdc|\.github/workflows|devcontainer\.json|Dockerfile|package\.json", text))
    exec_refs = len(re.findall(r"(?i)\.(?:sh|bash|zsh|fish|ps1|bat|cmd|py|js|mjs|cjs|ts|rb|pl|php|lua|go|rs|java|cs|cpp|c|exe|dll)\b", text))
    return LanguageAgnosticFeatures(
        path=path,
        bytes_size=size,
        line_count=len(lines),
        token_count=len(tokens),
        max_line_length=max((len(line) for line in lines), default=0),
        high_entropy_string_count=high_entropy,
        long_encoded_blob_count=encoded,
        auto_setup_path_reference_count=control_refs,
        executable_extension_reference_count=exec_refs,
    )


def score_evidence(evidence: Sequence[Evidence]) -> int:
    by_rule: Dict[str, int] = {}
    for ev in evidence:
        by_rule[ev.rule_id] = max(by_rule.get(ev.rule_id, 0), ev.score)
    return sum(by_rule.values())


def has_kind(evidence: Sequence[Evidence], kinds: Sequence[str]) -> bool:
    wanted = set(kinds)
    return any(ev.kind in wanted for ev in evidence)


def add_feature_evidence(text: str, features: LanguageAgnosticFeatures) -> List[Evidence]:
    evidence: List[Evidence] = []
    if features.high_entropy_string_count and re.search(r"(?i)\b(eval|exec|Function|base64|decode|fromCharCode|Assembly\.Load|loadstring)\b", text):
        evidence.append(
            Evidence(
                category="self_mutation_or_propagation",
                rule_id="MUT_ENTROPY_WITH_DYNAMIC_CODE",
                reason="high-entropy encoded-looking string combined with dynamic decode/execution vocabulary",
                kind="operation",
                score=3,
                line=1,
                snippet="high-entropy encoded-looking string detected; value omitted from report",
            )
        )
    if features.long_encoded_blob_count and re.search(r"(?i)\b(base64|decode|eval|exec|powershell|python|node|bash|sh)\b", text):
        evidence.append(
            Evidence(
                category="self_mutation_or_propagation",
                rule_id="MUT_ENCODED_BLOB_CONTINUATION",
                reason="long encoded-looking payload combined with decode/interpreter vocabulary",
                kind="operation",
                score=3,
                line=1,
                snippet="encoded-looking payload detected; value omitted from report",
            )
        )
    if features.auto_setup_path_reference_count >= 2 and features.executable_extension_reference_count >= 1:
        evidence.append(
            Evidence(
                category="self_mutation_or_propagation",
                rule_id="MUT_CONTROL_PATH_AND_EXEC_REFERENCES",
                reason="multiple auto-setup control path references combined with executable/script file references",
                kind="target",
                score=2,
                line=1,
                snippet="auto-setup control paths and executable/script references detected",
            )
        )
    return evidence


def defensive_discount(auto: Sequence[Evidence], mutation: Sequence[Evidence], defensive: Sequence[Evidence]) -> int:
    if not defensive:
        return 0
    mutation_only_terms = mutation and all(ev.kind in {"intent", "target"} for ev in mutation)
    auto_is_rule_doc = auto and all(ev.rule_id in {"AUTO_CURSOR_ALWAYS_APPLY", "AUTO_CURSOR_SETUP_COMMAND", "AUTO_VSCODE_TASK_COMMAND"} for ev in auto)
    if mutation_only_terms and auto_is_rule_doc:
        return min(4, score_evidence(defensive))
    return min(2, score_evidence(defensive) // 2)


def classify(auto: Sequence[Evidence], mutation: Sequence[Evidence], defensive: Sequence[Evidence]) -> Tuple[str, str, str, float, int, int, int]:
    auto_score = score_evidence(auto)
    mutation_score_raw = score_evidence(mutation)
    defensive_score = score_evidence(defensive)
    mutation_score = max(0, mutation_score_raw - defensive_discount(auto, mutation, defensive))

    auto_operational = has_kind(auto, ["operation", "trigger"])
    mutation_operational = has_kind(mutation, ["operation", "propagation_target"])
    has_control_target = has_kind(mutation, ["target", "propagation_target"])

    # Strong defensive documentation often lists dangerous behavior as text.
    # If mutation evidence is only descriptive/target references, do not allow
    # that prose to become a blocking category. Actual write/copy/orchestration
    # primitives still remain countable.
    if defensive_score >= 5 and mutation and not mutation_operational:
        mutation_score = 0

    if auto and mutation and auto_score >= 3 and mutation_score >= 3 and auto_operational and (mutation_operational or has_control_target):
        confidence = min(0.99, 0.55 + min(auto_score, 10) * 0.025 + min(mutation_score, 12) * 0.03)
        return (
            "critical",
            "AUTO_EXECUTION_AND_SELF_MUTATION_OR_PROPAGATION_DETECTED",
            "Non-destructive neutralization: block this setup path by returning a non-zero exit code, do not execute scanned commands, preserve files unchanged, review the auto-setup surface manually, and replace it with a minimal reviewed setup.",
            round(confidence, 3),
            auto_score,
            mutation_score,
            defensive_score,
        )
    if auto:
        return (
            "medium",
            "AUTO_EXECUTION_SURFACE_DETECTED_WITHOUT_BLOCKING_MUTATION_EVIDENCE",
            "Non-blocking review recommended. Auto-setup commands should stay explicit, pinned, readable, and free of write/copy propagation behavior.",
            min(0.85, 0.35 + min(auto_score, 10) * 0.04),
            auto_score,
            mutation_score,
            defensive_score,
        )
    if mutation:
        return (
            "medium",
            "MUTATION_OR_PROPAGATION_PRIMITIVE_DETECTED_WITHOUT_AUTO_EXECUTION_EVIDENCE",
            "Non-blocking review recommended. Avoid write/copy/orchestration primitives in setup surfaces unless reviewed and minimal.",
            min(0.85, 0.35 + min(mutation_score, 10) * 0.04),
            auto_score,
            mutation_score,
            defensive_score,
        )
    return (
        "info",
        "NO_COMBINED_MIASMA_STYLE_PATTERN_DETECTED",
        "No action required.",
        0.0,
        auto_score,
        mutation_score,
        defensive_score,
    )


def scan_file(path: Path, root: Path) -> Optional[Finding]:
    raw = safe_read_text(path)
    if raw is None:
        return None
    redacted, redactions = redact_sensitive(raw)
    data = path.read_bytes()
    rel = normalize_path(path, root)
    features = compute_features(rel, redacted, len(data))
    auto = collect_evidence(redacted, AUTO_EXECUTION_RULES, "auto_execution")
    mutation = collect_evidence(redacted, MUTATION_PROPAGATION_RULES, "self_mutation_or_propagation")
    mutation.extend(add_feature_evidence(redacted, features))
    defensive = collect_evidence(redacted, DEFENSIVE_CONTEXT_RULES, "defensive_context")
    severity, verdict, neutralization, confidence, auto_score, mutation_score, defensive_score = classify(auto, mutation, defensive)
    return Finding(
        path=rel,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        language_surface=language_surface_for(rel),
        features=features,
        auto_execution=auto,
        self_mutation=mutation,
        defensive_context=defensive,
        privacy_redactions=redactions,
        auto_score=auto_score,
        mutation_score=mutation_score,
        defensive_score=defensive_score,
        confidence=confidence,
        severity=severity,
        verdict=verdict,
        neutralization=neutralization,
    )


def evidence_to_dict(ev: Evidence) -> Dict[str, object]:
    return dataclasses.asdict(ev)


def finding_to_dict(f: Finding) -> Dict[str, object]:
    return {
        "path": f.path,
        "language_surface": f.language_surface,
        "sha256": f.sha256,
        "size_bytes": f.size_bytes,
        "severity": f.severity,
        "verdict": f.verdict,
        "blocking": f.is_blocking,
        "confidence": f.confidence,
        "scores": {
            "auto_execution": f.auto_score,
            "self_mutation_or_propagation": f.mutation_score,
            "defensive_context": f.defensive_score,
        },
        "privacy_redactions": f.privacy_redactions,
        "neutralization": f.neutralization,
        "language_agnostic_features": dataclasses.asdict(f.features),
        "auto_execution_evidence": [evidence_to_dict(e) for e in f.auto_execution],
        "self_mutation_or_propagation_evidence": [evidence_to_dict(e) for e in f.self_mutation],
        "defensive_context_evidence": [evidence_to_dict(e) for e in f.defensive_context],
    }


def build_report(root: Path, findings: List[Finding]) -> Dict[str, object]:
    blocking = [f for f in findings if f.is_blocking]
    by_surface: Dict[str, int] = {}
    for f in findings:
        by_surface[f.language_surface] = by_surface.get(f.language_surface, 0) + 1
    return {
        "tool": "AI Immune Guard",
        "version": VERSION,
        "mode": "polyglot_static_non_destructive_auto_setup_surface_scan",
        "generated_at_epoch": int(time.time()),
        "root": str(root.resolve()),
        "safety_model": SAFETY_MODEL_TEXT,
        "safety_invariants": [
            "Static analysis only.",
            "No execution of scanned commands.",
            "No source mutation.",
            "No cross-container access.",
            "No external reporting or network calls.",
            "GitHub blocking is performed only by returning a non-zero exit code in CI.",
            "Reports redact common secret patterns.",
            "Only allowlisted auto-setup file surfaces are scanned.",
        ],
        "detection_rule": "blocking requires auto-execution evidence and self-mutation/self-rewriting/propagation/cross-container-orchestration/equivalent mutated continuation evidence in the same target file",
        "summary": {
            "files_scanned": len(findings),
            "blocking_findings": len(blocking),
            "critical_findings": sum(1 for f in findings if f.severity == "critical"),
            "medium_findings": sum(1 for f in findings if f.severity == "medium"),
            "info_findings": sum(1 for f in findings if f.severity == "info"),
            "surfaces": by_surface,
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
    lines.append("## Safety model")
    lines.append("")
    lines.append("```text")
    lines.append(str(report["safety_model"]))
    lines.append("```")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    for key, value in summary.items():  # type: ignore[union-attr]
        lines.append(f"- **{key}**: `{json.dumps(value, ensure_ascii=False) if isinstance(value, dict) else value}`")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    findings = report["findings"]  # type: ignore[index]
    if not findings:
        lines.append("No allowlisted auto-setup files were found in the selected repository scope.")
    for item in findings:  # type: ignore[assignment]
        lines.append(f"### `{item['path']}`")
        lines.append("")
        lines.append(f"- Surface: `{item['language_surface']}`")
        lines.append(f"- Severity: **{item['severity']}**")
        lines.append(f"- Verdict: `{item['verdict']}`")
        lines.append(f"- Blocking: `{item['blocking']}`")
        lines.append(f"- Confidence: `{item['confidence']}`")
        lines.append(f"- Scores: `{json.dumps(item['scores'], ensure_ascii=False)}`")
        lines.append(f"- SHA-256: `{item['sha256']}`")
        lines.append(f"- Size: `{item['size_bytes']}` bytes")
        lines.append(f"- Privacy redactions: `{item['privacy_redactions']}`")
        lines.append(f"- Neutralization: {item['neutralization']}")
        lines.append("")
        for title, key in [
            ("Auto-execution evidence", "auto_execution_evidence"),
            ("Self-mutation / propagation / mutated continuation evidence", "self_mutation_or_propagation_evidence"),
            ("Defensive-context evidence", "defensive_context_evidence"),
        ]:
            lines.append(f"#### {title}")
            evidence = item[key]
            if not evidence:
                lines.append("No evidence in this category.")
            else:
                for ev in evidence:
                    lines.append(
                        f"- Line `{ev['line']}` · `{ev['rule_id']}` · score `{ev['score']}` · {ev['reason']} — `{ev['snippet']}`"
                    )
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
                "properties": {
                    "confidence": f["confidence"],
                    "scores": f["scores"],
                    "languageSurface": f["language_surface"],
                },
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
                        "version": VERSION,
                        "rules": [
                            {
                                "id": "AUTO_EXECUTION_AND_SELF_MUTATION_OR_PROPAGATION_DETECTED",
                                "shortDescription": {"text": "Combined auto-execution and mutation/propagation behavior"},
                                "fullDescription": {"text": "Blocks only when both required categories are found in the same allowlisted auto-setup file."},
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    path = out_dir / "ai_immune_report.sarif"
    path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def emit_github_annotations(findings: Sequence[Finding]) -> None:
    for f in findings:
        if f.severity == "info":
            continue
        evidence = (f.auto_execution or f.self_mutation)
        line = evidence[0].line if evidence else 1
        level = "error" if f.is_blocking else "warning"
        msg = f"{f.verdict}: {f.neutralization}"
        msg = msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{level} file={f.path},line={line},title=AI Immune Guard::{msg}")


def scan_once(options: ScanOptions) -> int:
    findings: List[Finding] = []
    for path in iter_target_files(options.root):
        finding = scan_file(path, options.root)
        if finding:
            findings.append(finding)
    report = build_report(options.root, findings)
    json_path = write_json(report, options.report_dir)
    md_path = write_markdown(report, options.report_dir)
    sarif_path = write_sarif(report, options.report_dir)
    if options.github_annotations:
        emit_github_annotations(findings)
    print(f"AI Immune Guard report: {json_path}")
    print(f"AI Immune Guard markdown: {md_path}")
    print(f"AI Immune Guard SARIF: {sarif_path}")
    return 2 if any(f.is_blocking for f in findings) else 0


def watch(options: ScanOptions, interval: float) -> int:
    last_digest = ""
    print("AI Immune Guard watch mode active. Static repository-scope scan only; no persistence is installed.")
    while True:
        snapshot = []
        for p in iter_target_files(options.root):
            try:
                stat = p.stat()
                snapshot.append((normalize_path(p, options.root), stat.st_mtime_ns, stat.st_size))
            except OSError:
                continue
        digest = hashlib.sha256(repr(sorted(snapshot)).encode("utf-8")).hexdigest()
        if digest != last_digest:
            last_digest = digest
            code = scan_once(options)
            if code == 2:
                print("AI Immune Guard watch detected a blocking condition. No files were changed.")
        time.sleep(max(5.0, interval))


def resolve_report_dir(root: Path, report_dir: str) -> Path:
    out = Path(report_dir)
    return out if out.is_absolute() else (root / out).resolve()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Safe polyglot static scanner for dangerous repository auto-setup surfaces.")
    parser.add_argument("--root", default=".", help="Repository root to scan. Default: current directory.")
    parser.add_argument("--report-dir", default=DEFAULT_REPORT_DIR, help="Report output directory.")
    parser.add_argument("--github-annotations", action="store_true", help="Emit GitHub Actions annotations to stdout only.")
    parser.add_argument("--watch", action="store_true", help="Opt-in local watch mode. Does not install persistence.")
    parser.add_argument("--interval", type=float, default=30.0, help="Watch interval seconds; minimum 5 seconds.")
    parser.add_argument("--list-surfaces", action="store_true", help="List allowlisted target patterns and exit.")
    args = parser.parse_args(argv)

    if args.list_surfaces:
        for pattern in AUTO_SETUP_PATTERNS:
            print(pattern)
        return 0

    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"Invalid repository root: {root}", file=sys.stderr)
        return 1
    options = ScanOptions(
        root=root,
        report_dir=resolve_report_dir(root, args.report_dir),
        github_annotations=args.github_annotations,
    )
    if args.watch:
        return watch(options, args.interval)
    return scan_once(options)


if __name__ == "__main__":
    raise SystemExit(main())
