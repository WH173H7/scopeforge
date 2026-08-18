# ScopeForge

ScopeForge is an early-stage, scope-aware reconnaissance and attack-surface
mapping CLI for authorised security assessments. It currently validates and
displays explicit exact-match scope policies and collects DNS A, AAAA, CNAME,
MX, NS, and TXT evidence for explicitly authorised DNS names.

ScopeForge is intended to grow toward passive DNS, certificate, RDAP, and HTTP
metadata collection; run inspection; run comparison; JSON output; and
human-readable reports. Active assessment is outside the first milestone.

## Current commands

```text
scopeforge help
scopeforge version
scopeforge validate-scope --target VALUE [options]
scopeforge run --target VALUE --collect dns [--save-dir DIR] [options]
```

`--target` and `--exclude` are repeatable and accept exact DNS names or IP
addresses. `--format` accepts `text` (the default) or `json`.

```sh
scopeforge validate-scope --target example.com --target 192.0.2.10
scopeforge validate-scope --target example.com --exclude example.com
scopeforge validate-scope --target example.com --format json
```

Authorization does not extend to related names. Authorizing `example.com` does
not authorize `api.example.com` or any other subdomain. Exclusions take
precedence over targets, and validation fails if no effective target remains.
Text output is intended for people; JSON output uses a versioned deterministic
contract for automation.

## DNS collection

The `run` command currently supports only the `dns` collector and DNS-name
targets. Targets are repeatable, and `--format` accepts `text` or `json`.

```sh
scopeforge run --target example.com --collect dns
scopeforge run --target example.com --target example.org --collect dns
scopeforge run --target example.com --collect dns --format json
```

Each lookup is authorized against the declared exact-match policy immediately
before the network operation. Returned addresses and MX, NS, or canonical
hostnames are evidence, not new targets: they do not expand authorization and
are not queried recursively. MX evidence retains its preference value.

Canonical-name evidence uses Go's standard resolver. ScopeForge records a
distinct normalized canonical name when one is returned, but does not parse raw
DNS packets or expose a complete CNAME chain. Expected DNS failures and absent
record families are included in the result instead of being hidden or printed
as successful evidence.

TXT is retained as untrusted evidence and is not interpreted as SPF, DMARC,
DKIM, a vulnerability, or an instruction. Per target, ScopeForge retains at
most 64 unique TXT values, 4,096 source bytes per value, and 65,536 source
bytes in total. Retained truncation is reported on each evidence item; fully omitted records
are reported with an explicit evidence_limited outcome. Invalid UTF-8 is
represented as base64; human output quotes TXT values so control characters
cannot be emitted directly to a terminal, while printable Unicode remains
readable.

## Persistent run artifacts

Persistence is opt-in. Without `--save-dir`, ScopeForge writes only to stdout
and creates no run files.

```sh
scopeforge run --target example.com --collect dns --save-dir ./runs
scopeforge run --target example.com --collect dns --format json --save-dir ./runs
```

When `--save-dir` is set, the normal stdout result is still printed, and one
versioned JSON artifact is written as `<run-id>.json` inside that directory.
Filenames use a generated run ID, not target names. Artifacts reuse the same
schema version 1 JSON contract as `--format json`, including run identity,
timestamps, authorized scope, evidence, and structured outcomes. Treat stored
artifacts as potentially sensitive reconnaissance data.

If the artifact cannot be written, stdout still contains the run result and
the process exits non-zero with `artifact_write_failed`.

## Development

ScopeForge requires Go 1.24 or later.

```sh
make fmt
make lint
make test
make check
```

`make lint` runs the standard-library-aware `go vet`. If `golangci-lint` is
installed, `.golangci.yml` provides a small additional profile.

Use ScopeForge only on systems and targets you are explicitly authorised to
assess. See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[CONTRIBUTING.md](CONTRIBUTING.md) before contributing.

## License

[MIT](LICENSE)
