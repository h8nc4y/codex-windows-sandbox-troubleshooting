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
configured local markers. It redacts every matched value. It does not
detect every possible format and is no substitute for keeping private
material out of the repository. Treat a passing scan as "no known marker
found," not "definitely safe."

When Git is available, tracked-file discovery runs in finite-time child
processes with a fixed-allowlist environment and isolated configuration;
unknown ambient and caller-provided variables are cleared. Windows creates
the requested executable suspended with only the three standard-stream
handles inherited, assigns it to a kill-on-close Job, and resumes it after
assignment. Assignment, resume, or consecutive Job-close failures keep the
target suspended, continue all remaining cleanup, aggregate termination and
close errors, and verify process exit within a finite wait. Every created
standard stream is disposed explicitly.
The direct native streams use fixed 8 KiB buffers and preserve binary
stdin/stdout/stderr without PowerShell serialization or a Windows
PowerShell 5.1 UTF-8 preamble. POSIX starts the command in a
dedicated session/process group and cleans up that group when execution
does not finish cleanly. Process
deadlines and output sizes are bounded on both platforms. The total process
deadline includes stream drain, descendant cleanup, and handle disposal and
is rechecked immediately before returning the bounded result.

The scanner checks recognized staged text blobs and differing regular
working-tree files. It snapshots staged entries, flags, and tracked
working-tree and local-marker file bytes before analysis and requires the
same staged state, file presence, and byte content immediately before
reporting. Raw staged entry and flag snapshots are compared both before and
after the final working-tree/local-marker byte revalidation.
File count, bytes, line length/count, rule traversal, findings, diagnostic
width, process output, and total scan time have separate limits. The scan
deadline is lower-only (`1..120000` milliseconds), finding output is capped
at 64 KiB before a single write, and the shared clock is checked immediately
before clock-scoped failure, finding, and success output. The public entry
point intentionally has no PowerShell parameter block; common parameters are
therefore raw tokens subject to the same validator. Invalid public arguments
and uncaught helper, process, provider, isolation, or cleanup failures return
fixed redacted exit-2 diagnostics without absolute paths.
Diagnostics escape control, formatting, bidi, and Unicode separator
characters; matched values remain redacted.

Unsupported repository entries, inconsistent repository state,
symlink/reparse paths, invalid text input, malformed Git output, timeout,
or incomplete process streams stop the scan. Working-tree fallback is
used only for a confirmed non-repository, or when Git is unavailable and
no `.git` entry exists in the target ancestry. Other Git failures do not
silently broaden or change the scan scope. Invalid root-level or ancestor
`.git` files/directories fail with a fixed `git-probe` integrity code.
A linked-worktree `.git` file is allowed only when Git proves the exact
checkout root. Windows compares the metadata name case-insensitively;
POSIX treats `.GIT` as ordinary case-sensitive content. Nested `.git`
control entries are excluded from fallback content. A tracked
`.private-markers.local` file is rejected because that input is local-only.

## Response Expectations

Maintainers should acknowledge actionable security reports when
available, remove or redact unsafe public material, and prefer guidance
that reduces data-exposure and boundary-weakening risk. If real exposure
is possible, rotate the affected secret outside this public repository and
document only the remediation status.
