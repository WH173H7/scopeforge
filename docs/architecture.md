# Architecture

## Status and intent

This document records the M0 foundation and M1 scope-validation command for
ScopeForge. It describes intended
boundaries where later implementation depends on them, but it does not claim
those components exist. ScopeForge is designed for authorised, primarily
passive reconnaissance. Active assessment is not part of the first milestone.

## Goals

- Make declared authorisation and evaluated scope visible in every run.
- Collect passive reconnaissance observations with attributable evidence.
- Produce deterministic structured data usable by humans and automation.
- Support cancellation, timeouts, partial results, and auditable failures.
- Remain maintainable across common desktop and server operating systems.

## Non-goals

- Vulnerability exploitation, brute force, credential attacks, payload
  delivery, or other active assessment behavior.
- Treating discovered, redirected, resolved, or related assets as implicitly
  authorised.
- Hiding collector failures to produce an apparently successful report.
- A plugin framework, distributed execution, service API, or web interface.
- Compatibility promises for data formats before a versioned schema exists.

## Minimal package structure

```text
cmd/scopeforge       executable entry point
internal/model       run, target, observation, evidence, and error types
internal/scope       target parsing and explicit policy evaluation
```

Packages for collection, persistence, configuration, logging, and rendering
will be introduced only when their behavior is implemented. Keeping all domain
packages under `internal` avoids committing to a public Go API prematurely.

## Run data model

A `Run` records an ID, timestamps, status, the exact `ScopePolicy` snapshot used
for authorization decisions, observations, and structured run errors. The ID
generation and persistence representation are deferred until persistent runs
exist.

An `Observation` contains a stable kind, the collector that produced it, its
subject, observation time, structured fields, and optional evidence references.
Fields describe derived or normalized facts. `Evidence` separately records the
source, capture time, media type, content, and optional digest of the material
supporting those facts. Keeping these concepts distinct permits retention or
redaction policies for raw material without corrupting derived results.

`RunError` captures a stable code, human-readable message, collector and target
when relevant, occurrence time, and whether retrying may succeed. Errors are
data only when a run can meaningfully continue; invalid authorization or
configuration prevents a run from starting.

## Target and scope policy

Targets have an explicit kind and normalized value. M0 supports exact DNS names
and IP addresses. DNS names are ASCII, lower-cased, stripped of one terminal
dot, and checked label by label. IP addresses use Go's canonical
`net/netip` representation. URL parsing is deliberately separate from target
parsing: a URL is not an authorization grant for its redirects or resolved
addresses.

`ScopePolicy` contains explicit allowed targets and explicit exclusions.
Evaluation is deny-by-default, uses exact normalized equality, and applies an
exclusion before an allowance. Normalized duplicate entries are removed while
preserving their first occurrence. ScopeForge does not support CIDRs, wildcards, suffix matching,
or automatic scope expansion.

Future relationship discovery must record a candidate asset before collection.
Every network interaction must independently evaluate the actual destination
against policy. DNS resolution and HTTP redirects must not widen scope.

## Collection boundary

Collectors will accept a `context.Context`, a validated target, and narrowly
scoped dependencies needed for their protocol. They will return observations,
evidence, and operational errors in domain terms. They will not print, format
reports, write persistent state, or choose additional targets. A coordinator
can later aggregate results and pass complete run data to text or JSON
renderers. No collector interface is added in M0 because no collector exists
yet; its exact shape should be driven by the first two real collectors.

## Errors

- Wrap causal errors with `%w` when callers need inspection.
- Use sentinel or typed errors only when callers take a distinct action.
- Include operation and target context once, at the boundary that has it.
- Do not encode errors as ambiguous empty results.
- Invalid input, invalid scope, or unsafe configuration fails before a run.
- A collector failure after a run starts is recorded as a `RunError`; the run
  may finish as partial if other results remain useful.
- Context cancellation and deadlines propagate unchanged enough for
  `errors.Is` checks.
- Messages exposed in JSON use stable codes for automation; prose is not an API.

The `validate-scope` external error codes are `invalid_target`,
`invalid_exclusion`, `missing_target`, `empty_effective_scope`,
`invalid_format`, and `invalid_usage`. These codes describe expected user
failures without exposing Go types or wrapped internal errors. When JSON is
selected, an expected error has this shape:

```json
{"error":{"code":"invalid_target","message":"target is invalid"}}
```

## Logging

Successful result output belongs on stdout; operational logs and text-mode
diagnostics belong on stderr. A JSON-mode expected error is emitted as the only
value on stdout so automation receives valid structured output; stderr remains
empty unless writing that result itself fails. Logging
will use structured key/value records through the standard library's `log/slog`.
Default level is `INFO`, with an explicit verbose option enabling `DEBUG`.
Fields should use stable names such as `run_id`, `collector`, `target`, and
`duration`. Secrets, authentication tokens, full authorization headers, and raw
response bodies must never be logged. Expected target-level findings are
observations, not log events.

## Configuration

Precedence, from lowest to highest, is built-in defaults, configuration file,
environment variables, then CLI flags. Each layer overrides only values it
explicitly sets. Lists that grant scope are replaced rather than merged across
layers so a higher-precedence source cannot accidentally retain unseen grants.
Exclusions may only narrow effective scope. The effective, normalized policy is
validated and displayed before collection and snapshotted into the run.

Configuration file format and environment variable names are deferred until a
setting exists that cannot be represented clearly by flags. Future defaults
must include finite network timeouts and bounded concurrency.

## CLI

```text
scopeforge help
scopeforge version
scopeforge validate-scope --target TARGET [--target TARGET...] \
  [--exclude TARGET...] [--format text|json]
```

M1 implements `validate-scope` using the standard library `flag` package.
Repeated flags avoid ambiguous comma splitting. Text is the interactive
default; JSON must be selected explicitly and contains no decorative output.
Unknown commands, flags, positional arguments, and formats are errors.

Process termination remains in `main`; command execution returns a code and
writes to injected streams so behavior is directly testable. Exit codes are:

```text
0  success
1  unexpected internal failure
2  CLI or usage failure
3  scope validation failure
```

Rendering is implemented separately from policy validation. The text renderer
sorts normalized targets by kind and value. JSON uses the same deterministic
ordering and this version 1 contract:

```json
{
  "schema_version": "1",
  "targets": [{"kind": "dns", "value": "example.com"}],
  "exclusions": [],
  "effective_target_count": 1
}
```

Incompatible structured-output changes require a schema-version change.
Partial future collector failures still need documented exit behavior before
the `run` command is implemented.

## Testing strategy

- Unit-test normalization, rejection, exact matching, exclusions, duplicate
  detection, and deny-by-default behavior with table-driven tests.
- Use reserved names and documentation address ranges; unit tests make no
  network calls.
- Add contract tests when JSON schemas and collector boundaries exist.
- Add integration tests around real protocol clients using local test servers,
  deterministic clocks, and controlled resolvers.
- Run race detection on code that introduces concurrency.
- Prefer observable behavior and boundary conditions over internal call counts.

CI runs formatting verification, `go vet`, and `go test` on Linux. Cross-platform
behavior should be tested when OS-specific code first appears.

## Security and abuse prevention

- Require explicit allow entries and make exclusions authoritative.
- Validate every actual network destination immediately before interaction.
- Do not infer authorization from DNS, redirects, certificates, registration
  records, or asset relationships.
- Bound concurrency, response sizes, redirects, retries, and request rates when
  network behavior is introduced.
- Require context cancellation and finite connect, request, and overall
  collector timeouts.
- Identify the client honestly where protocols support it and respect source
  terms and rate limits.
- Minimize collected personal data and define retention/redaction behavior for
  evidence before persistence is implemented.
- Keep credentials out of CLI arguments where practical, logs, result files,
  and error strings. Treat response content as untrusted input.
- Passive sources can still cause operational or legal impact; "passive" is
  not a substitute for authorization.

## Recorded tradeoffs

Exact matching is less convenient than wildcard or CIDR policies, but it makes
M0 authorization semantics reviewable. A richer policy syntax should be added
only with explicit boundary rules and tests. Flexible observation fields avoid
prematurely modeling every future protocol; stable observation kinds and a
future versioned JSON schema will constrain interoperability before persistence.
No collector abstraction exists yet because designing one without real
collectors would be speculative.
