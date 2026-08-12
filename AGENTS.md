# ScopeForge engineering rules

These rules apply throughout the repository.

- Prefer simple code over speculative abstractions.
- Do not create packages named utils, helpers, common or manager as dumping grounds.
- Every exported API must have a concrete reason to be exported.
- Keep security-sensitive validation explicit.
- Network operations must support context cancellation and sensible timeouts.
- Never silently expand the user's authorised scope.
- Never log secrets or authentication tokens.
- Separate collection from rendering.
- Preserve raw evidence where useful, but distinguish evidence from derived observations.
- Tests should focus on behavior and edge cases rather than implementation details.
- Avoid comments that merely repeat what the code already says.
- Document unusual decisions and tradeoffs instead of narrating ordinary code.
- Do not add generated-looking placeholder features.
- Do not implement future milestones during an earlier milestone.
- Run formatting, tests and static checks before declaring a task complete.

## Working agreements

- Treat scope exclusions as higher priority than inclusions.
- Use reserved domains and documentation IP ranges in tests and examples.
- Keep result data on stdout and operational diagnostics on stderr.
- Do not add a dependency without documenting why the standard library is insufficient.
- Update `docs/architecture.md` when a change invalidates a recorded decision.
