# Security policy

## Supported versions

ScopeForge has not published a stable release. Security fixes are applied to
the default branch while the project is in early development.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security advisory feature for this repository. Include the affected revision,
reproduction steps, impact, and any suggested mitigation. If private advisory
reporting is unavailable, contact the repository owner through the private
contact method listed on their GitHub profile.

Please avoid accessing data beyond what is necessary to demonstrate the issue,
disrupting services, or testing against systems without authorisation. We will
acknowledge a report when received and coordinate disclosure after assessing
the issue. Response and remediation timelines depend on severity and maintainer
availability; no fixed service-level agreement is offered.

## Operational safety

ScopeForge is intended only for authorised security work. An allowed target is
not permission to assess related targets. Redirects, resolved addresses,
subdomains, and discovered assets must each pass the applicable scope policy
before any future collector interacts with them.

The DNS collector rechecks authorization before every A, AAAA, MX, NS,
canonical-name, and TXT lookup. Addresses, hostnames, and TXT strings returned
by those lookups are evidence only. ScopeForge does not add them to the
authorized policy, query them, follow CNAME chains, or recursively discover
related names.

TXT content is treated as attacker-controlled evidence, never as a command or
authorization signal. Retention limits bound its output, invalid UTF-8 is
represented explicitly, and control characters are escaped in human output.

Reports and saved run artifacts may contain sensitive infrastructure
information. Store them with appropriate access controls, retention limits, and
encryption. ScopeForge creates `--save-dir` and artifact files with owner-only
permissions when the platform permits and when it creates those paths itself.
It does not chmod a pre-existing save directory. Never include authentication
tokens or secrets in bug reports, logs, fixtures, or examples.
