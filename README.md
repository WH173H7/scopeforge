# ScopeForge

ScopeForge is an early-stage, scope-aware reconnaissance and attack-surface
mapping CLI for authorised security assessments. The repository currently
contains the M0 engineering foundation: design documentation, an initial data
model, and exact target/scope validation. It does not yet perform
reconnaissance or make network requests.

ScopeForge is intended to grow toward passive DNS, certificate, RDAP, and HTTP
metadata collection; persistent runs; run comparison; JSON output; and
human-readable reports. Active assessment is outside the first milestone.

## Current commands

```text
scopeforge help
scopeforge version
```

The proposed next interface is documented in
[docs/architecture.md](docs/architecture.md). Commands that collect or validate
user-supplied targets are not implemented in M0.

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
