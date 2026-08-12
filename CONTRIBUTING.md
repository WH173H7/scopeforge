# Contributing

ScopeForge values small, reviewable changes and explicit security reasoning.
Before writing code, open an issue or discussion for changes that alter scope
semantics, the run model, command behavior, or stored data formats.

## Development workflow

1. Work from a focused branch.
2. Add or update behavior-focused tests.
3. Run `make check`.
4. Explain security implications and design tradeoffs in the pull request.

Commits should be coherent and avoid unrelated formatting churn. New
dependencies require a concrete justification, maintenance assessment, and
review of their security and licensing implications. Prefer the Go standard
library when it provides a clear implementation.

Scope changes require particular care: deny by default, make authorization
explicit, and test boundaries and exclusions. Test fixtures must use reserved
example domains and documentation address ranges rather than live third-party
systems.

Contributions are accepted under the repository's MIT license. Follow the
engineering rules in [AGENTS.md](AGENTS.md), which apply equally to human- and
tool-assisted changes.
