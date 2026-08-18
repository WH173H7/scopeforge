# Architecture

## Status and intent

This document records the M0 foundation, M1 scope-validation command, M2
DNS evidence collection, M3A opt-in filesystem persistence of completed
run artifacts, and M3B read-only inspection of those artifacts. ScopeForge is
designed for authorised, primarily passive reconnaissance. Active assessment
is not part of the current milestones.

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
internal/artifact    opt-in filesystem persistence of completed runs
internal/dns         scoped DNS evidence collection
internal/model       run, target, observation, evidence, and error types
internal/render      deterministic text and JSON output
internal/scope       target parsing and explicit policy evaluation
```

Packages for other collectors, configuration, and logging will be introduced
only when their behavior is implemented. Keeping all domain packages under
`internal` avoids committing to a public Go API prematurely.

## Run data model

A `Run` records status, the exact `ScopePolicy` snapshot used for authorization
decisions, evidence, observations, and structured run errors. M3A populates run
ID, `StartedAt`, and `FinishedAt` for every reconnaissance execution so a
completed run can be persisted without a second data model. ID and timestamps
are omitted from JSON when empty, which keeps earlier fixtures valid.

An `Observation` contains a stable kind, the collector that produced it, its
subject, observation time, structured fields, and optional evidence references.
Fields describe derived or normalized facts. M2A does not derive observations.
`Evidence` records the original target, category, DNS record type, normalized
returned value, and an optional typed priority used by MX evidence. Adding an
optional `priority` field is backward-compatible within run schema version 1:
existing record objects are unchanged, while MX objects can carry information
that would otherwise be lost. Evidence remains separate so later derived
observations cannot be confused with data returned directly by a source.

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

## DNS collection and network boundary

The DNS collector accepts a `context.Context`, the effective `ScopePolicy`, one
normalized target, a resolver, and an explicit timeout. It supports DNS-name
targets only. It re-evaluates exact authorization immediately before each A,
AAAA, MX, NS, canonical-name, and TXT lookup, performs the lookups sequentially, and
has no retries, recursion, discovery, or concurrency.

The small `dns.Resolver` interface contains only the context-aware methods used
from `net.Resolver`: `LookupIP`, `LookupMX`, `LookupNS`,
`LookupCNAME`, and `LookupTXT`. It exists so tests can prove
authorization-before-network behavior, cancellation, timeouts, evidence
normalization, and failures without using public DNS. It is DNS-specific and is
not a generic collector or dependency-injection framework. The CLI uses an
explicit resolver with `PreferGo` and a context-aware `net.Dialer` timeout so
deadlines govern both lookup and DNS-server connection behavior rather than
depending on platform resolver cancellation behavior.

Collection returns model evidence and run errors; it never prints or renders.
The command aggregates those results, while text and JSON renderers handle
presentation. Addresses and hostnames returned by DNS remain evidence. They are
never added to `ScopePolicy`, queried, or treated as authorization for related
assets. Returned DNS names are lowercased, stripped of one trailing root dot,
deduplicated, and sorted; normalization does not imply authorization.

Go's `LookupCNAME` exposes a canonical name, not the underlying raw CNAME chain.
M2 records evidence only when that normalized name differs from the requested
target. It does not manufacture a self-referential CNAME, parse DNS packets, or
follow the returned name. MX evidence is sorted by preference then hostname;
NS and other evidence use normalized values for deterministic ordering.

TXT values are opaque, untrusted data: collection preserves case, internal
whitespace, and empty strings, deduplicating only exact byte-identical values.
Sorted values are bounded to 64 retained records, 4,096 source bytes per value,
and 65,536 source bytes per target. Per-value truncation is represented only by
the additive schema-v1 fields `truncated` and `original_length`; invalid UTF-8
is base64 encoded with `encoding: "base64"`. Fully omitted records from the
count or total-byte budgets produce a typed `evidence_limited` outcome with
`omitted_records` and `omitted_bytes`. These limits describe ScopeForge
retention, not DNS protocol constraints.

Human TXT output uses Go-style quoting: newlines, carriage returns, tabs, ESC,
and other control bytes are escaped, while printable Unicode remains readable.
JSON preserves valid UTF-8 directly and uses the explicit base64 representation
for invalid UTF-8. `evidence_limited` is informational and, like `no_result`,
does not degrade run status.

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

The `run` command additionally uses `unsupported_collector` and
`unsupported_target` before collection begins. Expected per-record collection
outcomes are structured run data with the small code set `no_result`,
`lookup_failed`, `timeout`, and `canceled`. They do not expose resolver error
strings. `no_result` represents informational evidence absence, including a
resolver not-found response, and does not degrade run status. This matters
because MX, NS, and distinct CNAME data are legitimately absent for many names.
A run with both evidence and actual failures is `partial`; one with actual
failures and no evidence is `failed`; cancellation is `canceled`. Because
expected DNS outcomes are represented in a successfully rendered run result,
they return exit code 0. Exit code 1 remains reserved for unexpected internal
failures.

Human output separates `no_result` entries under `DNS absence` from actual
`Collection failures`. Run schema version 1 continues to carry both through its
existing `errors` array to avoid a breaking review-time schema change; consumers
must use the stable `code` field to distinguish informational absence. A future
schema version may name these outcomes separately.

## Logging

Successful result output belongs on stdout; operational logs and text-mode
diagnostics belong on stderr. A JSON-mode expected error is emitted as the only
value on stdout so automation receives valid structured output; stderr remains
empty unless writing that result itself fails. Persistence failures after a
rendered run keep that run JSON on stdout and report `artifact_write_failed` on
stderr. Logging
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
scopeforge run --target TARGET [--target TARGET...] --collect dns \
  [--format text|json] [--save-dir DIR]
scopeforge inspect-run --run-dir DIR --id RUN_ID [--format text|json]
```

M1 implements `validate-scope` using the standard library `flag` package.
Repeated flags avoid ambiguous comma splitting. Text is the interactive
default; JSON must be selected explicitly and contains no decorative output.
Unknown commands, flags, positional arguments, and formats are errors.

Process termination remains in `main`; command execution returns a code and
writes to injected streams so behavior is directly testable. Exit codes are:

```text
0  success
1  unexpected internal failure, a requested run artifact could not be saved,
   or an inspect-run filesystem read failed unexpectedly
2  CLI or usage failure
3  scope validation failure, or inspect-run rejected an artifact/input
```

`--save-dir` is optional. When it is omitted, no run artifact is written.
When it is present, stdout still receives the normal text or JSON run result
first. A persistence failure is reported as `artifact_write_failed` on stderr
and exits 1 without rewriting or appending to stdout, so `--format json`
remains a single valid JSON document. Exit 1 is used because saving was part of
the requested command and the existing 2/3 codes already mean usage and scope
validation failures.

## Persistent run artifacts

M3A persists exactly the in-memory `Run` after collection. It does not repeat
DNS lookups, follow evidence, or expand scope. The `internal/artifact` package
is the filesystem boundary; it is not a storage framework or database
abstraction.

Run IDs are generated with the standard library: a UTC `YYYYMMDDThhmmssZ`
prefix plus eight cryptographically random bytes as lowercase hex, for example
`20260818T150405Z-abababababababab`. The format is filesystem-safe, compact,
and independent of target names. Tests inject a clock function and an
`io.Reader` at that ID boundary. Empty or path-like IDs are rejected.

`StartedAt` is captured immediately before collection. `FinishedAt` is captured
after collection and status assignment, including cancellation and collector
failure. Both are stored and serialized as UTC RFC3339/RFC3339Nano values.
Tests inject `now` rather than sleeping on the wall clock.

When ScopeForge creates `--save-dir`, it uses permission `0700` and does not
chmod a directory that already existed. Artifact files are created with `0600`.
These modes are the Unix intent; Windows file-mode semantics are not claimed.
The destination name is `<run-id>.json` inside the requested directory. An
existing destination is an error, not an overwrite.

Writes open that final path with `O_WRONLY|O_CREATE|O_EXCL` and mode `0600`,
then write the complete canonical JSON, `Sync`, and close. `O_EXCL` is the
no-overwrite guarantee: if the name already exists, creation fails and
ScopeForge returns `ErrExists` without replacing the file. There is no
separate existence check and no rename onto the destination.

A detected write, sync, or close failure removes the incomplete destination
where practical. This is not transactional persistence. It does not guarantee
crash-atomic replacement of a partial file, durability beyond the performed
`Sync`, or cleanup after process or machine termination.

M3A encoding and M3B decoding share one canonical JSON document type in
`internal/artifact`. `--format json` and persisted files are that document.
`inspect-run --format json` re-encodes it; unknown additive fields tolerated
on read are not preserved in the re-encoded output.

## Inspecting saved artifacts

`inspect-run` is a read-only command. It does not take a resolver, does not
call collectors, and does not create, chmod, rename, rewrite, or delete
files. Loading a saved run is not authorization to contact the recorded
assets.

The artifact path is only `<run-dir>/<validated-run-id>.json`. IDs reuse the
M3A `ValidID` grammar, so path separators, `..`, absolute paths, and a `.json`
suffix are rejected. The command does not search recursively or accept an
arbitrary `--file` path.

`artifact.Read` Lstats the path, rejects symlinks and non-regular files, and
refuses files larger than 16 MiB before decoding. The size bound is a
ScopeForge safety limit, not a schema limit. After a bounded read, JSON is
decoded without rejecting unknown fields in schema version 1, then validated.

Required schema version 1 checks include: `schema_version` exactly `"1"`;
present valid `id` matching `--id`; parseable UTC `started_at`/`finished_at`
with finish not before start; known status; valid targets and exclusions;
recognized collectors (`dns`); evidence category/record types and TXT
encoding/truncation consistency; MX priority present; and outcomes with
required fields. Missing, empty, or unknown `schema_version` is
`unsupported_artifact_schema`. An internal `id` that does not match `--id` is
`artifact_id_mismatch`. Other malformed content maps to `invalid_artifact`.

Inspect-run exit codes: malformed flags and invalid format remain 2; missing
or invalid `--id`/`--run-dir`, not found, unsupported schema, invalid
artifact, ID mismatch, and oversize are 3; unexpected OS read failures are 1.
Successful text output is an inspection view that reuses DNS evidence
rendering, including TXT quoting. Successful JSON output is the canonical
artifact document.

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

The `run` command has its own version 1 JSON result containing `status`,
`targets`, `exclusions`, `collectors`, `evidence`, and `errors`. Additive
identity fields `id`, `started_at`, and `finished_at` appear when populated.
Its targets, exclusions, and evidence are sorted deterministically, and empty
evidence/error/exclusion collections are encoded as arrays rather than `null`.
Incompatible structured-output changes require a schema-version change. stdout
JSON and persisted artifacts are produced by the same encoder.

## Testing strategy

- Unit-test normalization, rejection, exact matching, exclusions, duplicate
  detection, and deny-by-default behavior with table-driven tests.
- Use reserved names and documentation address ranges; unit tests make no
  network calls.
- Add contract tests when JSON schemas and collector boundaries exist.
- Add integration tests around real protocol clients using local test servers,
  deterministic clocks, and controlled resolvers.
- Test DNS through a controllable resolver; automated tests never require the
  system resolver or Internet connectivity.
- Test filesystem persistence and inspection in temporary directories with
  injected clocks and run IDs; do not depend on a developer home directory or
  wall-clock sleeps. inspect-run tests must not invoke a DNS resolver.
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
- Minimize collected personal data. Persisted run artifacts contain
  reconnaissance evidence and should be treated as sensitive; M3A does not
  implement automatic retention, redaction, or encryption-at-rest. M3B treats
  those files as untrusted local input and does not collect against them.
- Keep credentials out of CLI arguments where practical, logs, result files,
  and error strings. Treat response content as untrusted input.
- Passive sources can still cause operational or legal impact; "passive" is
  not a substitute for authorization.

## Recorded tradeoffs

Exact matching is less convenient than wildcard or CIDR policies, but it makes
M0 authorization semantics reviewable. A richer policy syntax should be added
only with explicit boundary rules and tests. Flexible observation fields avoid
prematurely modeling every future protocol; stable observation kinds and a
future versioned JSON schema will constrain interoperability. Persistence is an
explicit filesystem write of the canonical run JSON, not a database or generic
repository. No generic collector abstraction exists because one DNS
implementation is not enough evidence for a common collector lifecycle. The
narrow resolver boundary is sufficient for deterministic network tests without
dictating future collectors.
