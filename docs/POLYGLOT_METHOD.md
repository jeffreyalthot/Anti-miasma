# Polyglot detection method

AI Immune Guard v2 uses a language-agnostic static model. It does not try to fully parse every programming language. Instead, it checks only allowlisted auto-setup surfaces and extracts cross-language behavioral evidence:

- setup triggers and execution directives;
- process-start primitives;
- interpreter inline execution;
- file write/copy/rewrite primitives across Python, JavaScript, TypeScript, JVM languages, .NET languages, Go, Rust, C/C++, PHP, Ruby, POSIX shell, and PowerShell;
- auto-setup control path targeting;
- container orchestration primitives;
- repository/GitHub automation primitives;
- dynamic code generation or encoded continuation patterns;
- loops over workspaces, repositories, containers, or runners;
- defensive context to reduce false positives in documentation and security rules.

The blocking decision remains strict: a target file must contain both auto-execution behavior and mutation/propagation/equivalent mutated-continuation behavior in the same allowlisted file.
