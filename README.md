# ScopeForge

ScopeForge is an early-stage, scope-aware reconnaissance and attack-surface
mapping CLI for authorised security assessments. It currently validates and
displays explicit exact-match scope policies and collects DNS A and AAAA
evidence for explicitly authorised DNS names.

ScopeForge is intended to grow toward passive DNS, certificate, RDAP, and HTTP
metadata collection; persistent runs; run comparison; JSON output; and
human-readable reports. Active assessment is outside the first milestone.

## Current commands

```text
scopeforge help
scopeforge version
scopeforge validate-scope --target VALUE [options]
scopeforge run --target VALUE --collect dns [options]
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

Each A and AAAA lookup is authorized against the declared exact-match policy
immediately before the network operation. Returned IPv4 and IPv6 addresses are
evidence, not new targets: they do not expand authorization and are not queried
recursively. Expected DNS failures are included in the result instead of being
hidden or printed as successful evidence.

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
