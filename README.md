# AI Immune Guard

Safe, non-destructive static protection for repository auto-setup files.

This package is intentionally defensive only. It does not self-propagate, self-mutate, install hidden persistence, access other containers, or modify GitHub infrastructure. It scans repository auto-setup surfaces as text, reports evidence, and blocks CI only through a non-zero exit code when a file combines auto-execution with self-mutation or propagation behavior.

## Files

- `ai_immune_guard.py` — static scanner and report generator.
- `ai_immune_gate.py` — CI/editor gate wrapper.
- `.vscode/tasks.json` — VS Code tasks to run the scanner/gate manually.
- `.cursor/rules/setup.mdc` — Cursor rule describing the safe setup gate.
- `.github/workflows/ai-immune-guard.yml` — GitHub Actions workflow to block unsafe pull requests.

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

Optional local watch mode:

```bash
python ai_immune_guard.py --root . --watch --interval 30
```

Watch mode is opt-in and does not install persistence.
