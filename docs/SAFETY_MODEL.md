# Safety model

Safety model 
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
self-mutation, self-rewriting, propagation, cross-container orchestration, or equivalent mutated continuation behavior.
