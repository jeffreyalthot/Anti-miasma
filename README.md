# AI Immune Guard

Safe, non-destructive static protection for repository auto-setup files.

This package is intentionally defensive only. It does not self-propagate, self-mutate, install hidden persistence, access other containers, execute scanned commands, call the network, or modify GitHub infrastructure. It scans allowlisted repository auto-setup surfaces as text, reports evidence, and blocks CI only through a non-zero exit code when a file combines auto-execution with self-mutation, self-rewriting, propagation, cross-container orchestration, or equivalent mutated continuation behavior.

## Main files

- `ai_immune_guard.py` — polyglot static scanner and report generator.
- `ai_immune_polyglot_rules.py` — language-agnostic detection rules and safety constants.
- `ai_immune_gate.py` — CI/editor gate wrapper.
- `.vscode/tasks.json` — VS Code tasks to run the scanner/gate manually.
- `.cursor/rules/setup.mdc` — Cursor rule describing the safe setup gate.
- `.github/workflows/ai-immune-guard.yml` — GitHub Actions workflow that blocks unsafe PRs only with a non-zero exit code.
- `docs/SAFETY_MODEL.md` — exact safety model.
- `docs/POLYGLOT_METHOD.md` — summary of the language-agnostic method.

## Reports

Generated under `reports/ai-immune-guard/`:

- `ai_immune_report.json`
- `ai_immune_report.md`
- `ai_immune_report.sarif`

## Usage

Run locally:

```bash
python ai_immune_gate.py --root . --report-dir reports/ai-immune-guard
```

List scanned surfaces:

```bash
python ai_immune_guard.py --list-surfaces
```

Optional local watch mode:

```bash
python ai_immune_guard.py --root . --watch --interval 30
```

Watch mode is opt-in and does not install persistence.
