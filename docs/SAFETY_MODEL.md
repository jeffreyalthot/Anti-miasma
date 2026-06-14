# Safety model

The implementation follows strict defensive constraints:

1. Static analysis only.
2. No execution of scanned commands.
3. No source mutation.
4. No cross-container access.
5. No external reporting or network calls.
6. GitHub blocking is performed only by returning a non-zero exit code in CI.
7. Reports redact common secret patterns.
8. Only allowlisted auto-setup file surfaces are scanned.

The tool detects a blocking pattern only when both of these categories are found in the same target file:

- auto-execution behavior;
- self-mutation, self-rewriting, propagation, cross-container orchestration, or equivalent mutated continuation behavior.
