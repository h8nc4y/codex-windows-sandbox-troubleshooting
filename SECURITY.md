# Security Policy

This repository documents a troubleshooting workflow for the Codex sandbox
on Windows. It should never contain secrets, but its guidance touches
sandbox backends, Windows ACLs, and security posture — so guidance that
weakens a security boundary more than documented is treated as a security
problem too.

## Supported Versions

The `main` branch is the supported version. Tagged releases receive fixes
through new tags on `main`.

## Reporting A Vulnerability

Use GitHub private vulnerability reporting for:

- A real secret, credential, or private identifier accidentally committed
  to this repository.
- Guidance that could cause readers to weaken or disable the sandbox
  beyond the documented scoped workarounds, grant broader ACLs than
  necessary, kill other users' processes or logon sessions, or otherwise
  degrade a security boundary presented as a "fix".
- A validation gap that allows unsafe public examples.

Do not open a public issue containing tokens, credentials, private keys,
OAuth material, customer data, raw secret-bearing logs, private repository
names, hostnames, usernames, or internal paths.

## Public Issue Safety

Public issues may include:

- Symptom class and layer, such as "CreateProcessAsUserW failed: 5 on the
  agent path" or "setup helper ACL failure".
- Sanitized command classes and their outcomes, such as the `codex
  sandbox` bisect result or whether the config parses, without private
  paths.
- The Codex version observed (claims here are version-scoped).
- Placeholder host, profile, workspace, and path names.

Public issues must not include:

- Secret values or secret-displaying command output.
- Private repository names, internal absolute paths, hostnames,
  usernames, or customer data.
- Raw agent transcripts or sandbox logs that contain any of the above —
  quote the single relevant error line instead.

## Scanner Coverage

The private-marker scanner (`scripts/scan-private-markers.ps1`) is a
best-effort safety net, not a guarantee. It scans git-tracked text files
for a curated set of secret prefixes (GitHub, OpenAI, AWS, GCP, Slack,
Stripe, PEM key blocks, and similar), private-looking absolute Windows
paths (allowlisting documented placeholders and the well-known system
locations this skill cites), non-allowlisted GitHub repository URLs, and
configured local markers, and it redacts any matched value. It does not
detect every possible secret format and is no substitute for keeping real
credentials out of the repository in the first place. Treat a passing scan
as "no known marker found," not "definitely safe."

## Response Expectations

Maintainers should acknowledge actionable security reports when
available, remove or redact unsafe public material, and prefer guidance
that reduces data-exposure and boundary-weakening risk. If real exposure
is possible, rotate the affected secret outside this public repository and
document only the remediation status.
