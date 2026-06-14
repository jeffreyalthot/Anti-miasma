#!/usr/bin/env python3
"""
AI Immune Polyglot Rules

Language-agnostic static detection rules for auto-setup surfaces.
This module contains data only. It performs no execution, no mutation,
no network access, and no container access.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

VERSION = "2.0.0-polyglot-safe"

SAFETY_MODEL_TEXT = """Safety model 
The implementation follows strict defensive constraints:

Static analysis only.
No execution of scanned commands.
No source mutation.
No cross-container access.
No external reporting or network calls.
GitHub blocking is performed only by returning a non-zero exit code in CI.
Reports redact common secret patterns.
Only allowlisted auto-setup file surfaces are scanned.
The tool detects a blocking pattern only when both of these categories are found in the same target file:

auto-execution behavior;
self-mutation, self-rewriting, propagation, cross-container orchestration, or equivalent mutated continuation behavior."""

# Only explicit auto-setup / developer-environment surfaces are scanned.
# This is intentionally not a general source-code crawler.
AUTO_SETUP_PATTERNS: List[str] = [
    ".vscode/tasks.json",
    ".vscode/*.json",
    ".cursor/rules/setup.mdc",
    ".cursor/rules/*.mdc",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".devcontainer/devcontainer.json",
    ".devcontainer/*.json",
    ".devcontainer/*.jsonc",
    "package.json",
    "pnpm-workspace.yaml",
    "npm-shrinkwrap.json",
    "Makefile",
    "makefile",
    "GNUmakefile",
    "Justfile",
    "justfile",
    "Taskfile.yml",
    "Taskfile.yaml",
    "Earthfile",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "tox.ini",
    "noxfile.py",
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    ".husky/*",
    ".gitpod.yml",
    ".gitpod.yaml",
    "codespaces/*.json",
]

TEXT_EXTENSIONS = {
    "", ".json", ".jsonc", ".mdc", ".md", ".yml", ".yaml", ".toml", ".ini",
    ".py", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd",
    ".mk", ".txt", ".cfg", ".conf", ".dockerfile",
}

SPECIAL_TEXT_NAMES = {
    "Makefile", "makefile", "GNUmakefile", "Justfile", "justfile", "Taskfile.yml",
    "Taskfile.yaml", "Earthfile", "Dockerfile", "noxfile.py", "package.json",
}

SKIPPED_DIRECTORIES = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".tox", ".nox", "dist", "build", "target", "out", ".gradle", ".idea", ".cache",
    "reports", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

MAX_FILE_BYTES = 1_000_000
MAX_SNIPPET_CHARS = 240
MAX_EVIDENCE_PER_CATEGORY = 64

@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: str
    reason: str
    score: int
    kind: str

# Auto-execution behavior across common setup formats, CI systems, and interpreter forms.
AUTO_EXECUTION_RULES: Tuple[Rule, ...] = (
    Rule("AUTO_VSCODE_TASK_COMMAND", r'"(?:command|args|type|runOptions|isBackground)"\s*:', "VS Code task execution metadata", 2, "operation"),
    Rule("AUTO_CURSOR_ALWAYS_APPLY", r'(?im)^\s*alwaysApply\s*:\s*true\s*$', "Cursor rule that can apply automatically", 2, "trigger"),
    Rule("AUTO_CURSOR_SETUP_COMMAND", r'(?i)`[^`]{0,160}\b(?:python|node|npm|pnpm|yarn|bash|sh|pwsh|powershell|make|just|task|docker)\b[^`]{0,160}`', "setup command embedded in Cursor/rule text", 2, "operation"),
    Rule("AUTO_GHA_EVENT", r'(?im)^\s*on\s*:\s*(?:\[?\s*)?(?:push|pull_request|workflow_run|schedule|repository_dispatch|workflow_dispatch|pull_request_target)\b', "GitHub Actions event trigger", 3, "trigger"),
    Rule("AUTO_GHA_RUN", r'(?im)^\s*run\s*:\s*\|?|\buses\s*:\s*actions/', "GitHub Actions run/use step", 2, "operation"),
    Rule("AUTO_CRON", r'(?i)\bcron\s*:\s*["\'][^"\']+["\']|\bschedule\s*:', "scheduled execution trigger", 3, "trigger"),
    Rule("AUTO_PACKAGE_LIFECYCLE", r'(?i)"(?:preinstall|install|postinstall|prepare|prepublish|prepack|postpack|prestart|start|poststart|pretest|posttest)"\s*:', "package-manager lifecycle or script hook", 3, "trigger"),
    Rule("AUTO_DEVCONTAINER_LIFECYCLE", r'(?i)"(?:initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"\s*:', "devcontainer lifecycle command", 3, "trigger"),
    Rule("AUTO_DOCKER_EXEC", r'(?im)^\s*(?:RUN|CMD|ENTRYPOINT|HEALTHCHECK|SHELL)\b', "Dockerfile build/runtime execution directive", 3, "operation"),
    Rule("AUTO_COMPOSE_EXEC", r'(?i)\b(?:command|entrypoint|healthcheck)\s*:', "compose runtime execution field", 2, "operation"),
    Rule("AUTO_MAKE_INSTALL", r'(?im)^\s*(?:install|setup|bootstrap|init|post-install|pre-install)\s*:', "make/task setup target", 3, "trigger"),
    Rule("AUTO_SHELL_INTERPRETER", r'(?i)\b(?:bash|sh|zsh|fish|pwsh|powershell|cmd|python|python3|node|ruby|perl|php|lua|Rscript|go\s+run|cargo\s+run|dotnet\s+run|java|javac)\b\s+(?:-c|-e|/c)\b', "inline interpreter execution", 3, "operation"),
    Rule("AUTO_REMOTE_SCRIPT_PIPE", r'(?i)\b(?:curl|wget|Invoke-WebRequest|iwr|fetch)\b[^\n]{0,180}(?:\||bash|sh|python|node|powershell|pwsh)', "remote acquisition followed by interpreter-style execution", 3, "operation"),
    Rule("AUTO_PROCESS_START", r'(?i)\b(?:Start-Process|Process\.Start|child_process\.(?:exec|spawn|execFile)|subprocess\.(?:run|Popen|call)|os\.system|Runtime\.getRuntime\(\)\.exec|system\s*\()\b', "process execution primitive", 3, "operation"),
    Rule("AUTO_HOOK_FRAMEWORK", r'(?i)\b(?:pre-commit|post-checkout|post-merge|pre-push|husky|lefthook|lint-staged)\b', "developer hook framework", 2, "trigger"),
)

# Mutation / propagation / mutated continuation behavior across many languages.
MUTATION_PROPAGATION_RULES: Tuple[Rule, ...] = (
    Rule("MUT_SELF_TERMS", r'(?i)\b(?:self[-_ ]?(?:modify|mutat|rewrit|replicat|install)|polymorphic|metamorphic|quine|mutated continuation)\b', "explicit self-mutation or mutated-continuation terminology", 1, "intent"),
    Rule("MUT_WRITE_PY", r'(?i)\b(?:open\s*\([^\n]{0,100}["\'](?:w|a|x|wb|ab)["\']|Path\([^\n]{0,80}\)\.(?:write_text|write_bytes)|write_text\s*\(|write_bytes\s*\(|shutil\.(?:copy|copy2|copyfile|copytree))\b', "Python file write/copy primitive", 3, "operation"),
    Rule("MUT_WRITE_JS", r'(?i)\b(?:fs\.(?:writeFileSync|writeFile|appendFileSync|appendFile|copyFileSync|cpSync|createWriteStream)|Deno\.(?:writeTextFile|writeFile|copyFile)|Bun\.write)\b', "JavaScript/TypeScript file write/copy primitive", 3, "operation"),
    Rule("MUT_WRITE_JVM", r'(?i)\b(?:Files\.(?:write|writeString|copy|move)|new\s+FileWriter|new\s+FileOutputStream|PrintWriter\s*\(|Paths\.get\()\b', "JVM language file write/copy primitive", 3, "operation"),
    Rule("MUT_WRITE_DOTNET", r'(?i)\b(?:File\.(?:WriteAllText|WriteAllBytes|AppendAllText|Copy|Move)|Directory\.(?:Copy|CreateDirectory)|new\s+StreamWriter)\b', ".NET file write/copy primitive", 3, "operation"),
    Rule("MUT_WRITE_GO", r'(?i)\b(?:os\.(?:WriteFile|Create|OpenFile|Rename|MkdirAll)|ioutil\.WriteFile|io\.Copy|filepath\.Walk(?:Dir)?)\b', "Go file write/copy/walk primitive", 3, "operation"),
    Rule("MUT_WRITE_RUST", r'(?i)\b(?:std::fs::(?:write|copy|rename|create_dir_all|OpenOptions)|File::create|OpenOptions::new)\b', "Rust file write/copy primitive", 3, "operation"),
    Rule("MUT_WRITE_CPP_C", r'(?i)\b(?:std::ofstream|std::filesystem::(?:copy|copy_file|rename|create_directories)|fopen\s*\([^\n]{0,80}["\'](?:w|a|wb|ab)["\']|CreateFileA|CreateFileW)\b', "C/C++ file write/copy primitive", 3, "operation"),
    Rule("MUT_WRITE_RUBY_PHP", r'(?i)\b(?:File\.write|File\.open\s*\([^\n]{0,80}["\'](?:w|a)["\']|IO\.write|file_put_contents|copy\s*\(|rename\s*\()\b', "Ruby/PHP file write/copy primitive", 3, "operation"),
    Rule("MUT_WRITE_SHELL", r'(?i)\b(?:cp|mv|install|rsync)\b[^\n]{0,140}\b(?:\.vscode|\.cursor|\.github|workflow|tasks\.json|setup\.mdc|devcontainer|Dockerfile|package\.json)\b|(?:>|>>)[^\n]{0,120}\b(?:\.vscode|\.cursor|\.github|workflow|tasks\.json|setup\.mdc|devcontainer)\b', "shell copy/write into auto-setup control path", 4, "propagation_target"),
    Rule("MUT_WRITE_POWERSHELL", r'(?i)\b(?:Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|New-Item)\b[^\n]{0,160}\b(?:\.vscode|\.cursor|\.github|workflow|tasks\.json|setup\.mdc|devcontainer|Dockerfile|package\.json)\b', "PowerShell write/copy into auto-setup control path", 4, "propagation_target"),
    Rule("MUT_INPLACE_REWRITE", r'(?i)\b(?:sed\s+-i|perl\s+-pi|python\s+-c[^\n]{0,120}write|node\s+-e[^\n]{0,120}write|replace\s*\()\b', "in-place rewrite primitive", 3, "operation"),
    Rule("MUT_CONTROL_PATH", r'(?i)\b(?:\.vscode/tasks\.json|\.cursor/rules/setup\.mdc|\.github/workflows/[^\s"\']+|devcontainer\.json|Dockerfile|package\.json|Makefile|Taskfile\.(?:yml|yaml)|Justfile)\b', "reference to auto-setup control path", 2, "target"),
    Rule("MUT_CONTAINER_ORCHESTRATION", r'(?i)\b(?:docker\s+(?:cp|exec|run|compose|context|container|volume|network)|kubectl\s+(?:exec|cp|apply|create|patch)|podman\s+(?:cp|exec|run)|nerdctl\s+(?:cp|exec|run))\b', "container orchestration primitive", 4, "propagation_target"),
    Rule("MUT_REPO_PROPAGATION", r'(?i)\b(?:git\s+(?:clone|pull|push|commit|am|apply|submodule)|gh\s+(?:repo|workflow|api|gist|pr|release)|hub\s+(?:pull-request|api))\b', "repository or GitHub automation primitive", 3, "operation"),
    Rule("MUT_WORKSPACE_LOOP", r'(?i)\b(?:for|foreach|while|walk|glob|find|Get-ChildItem|os\.walk|filepath\.Walk|Files\.walk|Directory\.Enumerate)\b[^\n]{0,180}\b(?:repo|repos|workspace|workspaces|container|containers|project|projects|runner|runners)\b', "loop over repositories/workspaces/containers/runners", 3, "operation"),
    Rule("MUT_DYNAMIC_CODE", r'(?i)\b(?:eval\s*\(|exec\s*\(|Function\s*\(|fromCharCode|compile\s*\(|loadstring\s*\(|assert\s*\(|vm\.runIn|ScriptEngineManager|Assembly\.Load|Expression\.Compile|Reflect\.construct)\b', "dynamic code generation or execution primitive", 3, "operation"),
    Rule("MUT_OBF_DECODE", r'(?i)\b(?:base64\s+-d|base64_decode|atob\s*\(|Buffer\.from\s*\([^\n]{0,80}["\']base64["\']|FromBase64String|b64decode|decodeURIComponent|xxd\s+-r|certutil\s+-decode)\b', "decode primitive often used for mutated/obfuscated continuation", 2, "operation"),
    Rule("MUT_PERMISSION_EXEC", r'(?i)\b(?:chmod\s+\+x|Set-ExecutionPolicy|icacls\b|attrib\s+\+h|launchctl|systemctl\s+enable|schtasks\s+/create|crontab\s+-)\b', "execution permission or persistence-style primitive", 3, "operation"),
)

# Context phrases that usually indicate defensive documentation/rules, not a malicious implementation.
DEFENSIVE_CONTEXT_RULES: Tuple[Rule, ...] = (
    Rule("DEF_STATIC_ONLY", r'(?i)\bstatic analysis only\b|\bno execution of scanned commands\b|\bno source mutation\b', "explicit static-only defensive constraint", 2, "defensive"),
    Rule("DEF_NO_CROSS_CONTAINER", r'(?i)\bno cross-container access\b|\bdo not access other containers\b|\bno external reporting or network calls\b', "explicit non-invasive defensive constraint", 2, "defensive"),
    Rule("DEF_REPORT_REDACT", r'(?i)\breports redact\b|\bredact common secret patterns\b|\bnon-zero exit code\b', "safe reporting/gating constraint", 1, "defensive"),
    Rule("DEF_DETECTION_WORDS", r'(?i)\bdetects?\b|\bscanner\b|\bguard\b|\bgate\b|\bneutralization\b|\bmanual security review\b', "defensive scanner/rule language", 1, "defensive"),
)

# Secret patterns are redacted before snippets are emitted.
PRIVACY_SENSITIVE_PATTERNS: Dict[str, str] = {
    r"gh[pousr]_[A-Za-z0-9_]{20,}": "possible GitHub token",
    r"github_pat_[A-Za-z0-9_]{22,}": "possible GitHub fine-grained token",
    r"AKIA[0-9A-Z]{16}": "possible AWS access key id",
    r"ASIA[0-9A-Z]{16}": "possible AWS temporary access key id",
    r"AIza[0-9A-Za-z_\-]{20,}": "possible Google API key",
    r"xox[baprs]-[0-9A-Za-z\-]{20,}": "possible Slack token",
    r"sk-[A-Za-z0-9]{20,}": "possible API token",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----": "possible private key",
    r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\",}]+": "possible password assignment",
    r"(?i)(token|secret|apikey|api_key|access_key)\s*[:=]\s*['\"]?[^\s'\",}]+": "possible secret assignment",
}

