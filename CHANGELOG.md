# Changelog

All notable changes to this project are documented in this file.

The format loosely follows Keep a Changelog conventions.

## Unreleased

### Fixed

- Hardened private-marker maintenance as one bounded contract: staged and
  working-tree text views are checked consistently, repository state is
  revalidated before reporting, unsafe filesystem states fail closed, and
  diagnostics and scan resources have explicit limits.
- Added a shared cross-platform process boundary with finite deadlines,
  bounded streams, and descendant cleanup, plus regression coverage for
  repository state, filesystem handling, limits, diagnostics, and cleanup.
- Added a lower-only 120-second scan-wide deadline, a 64 KiB atomic finding
  output cap, and immediate deadline checks before fixed failure, finding,
  and success writes without taking ownership of standard output.
- Added Windows assignment/resume/Job-close failure injection that verifies
  suspended child termination, aggregate cleanup, explicit stream disposal,
  and PID disappearance. Added fixed `git-probe` failures for invalid root
  and ancestor `.git` files/directories, Git-proven linked-worktree support,
  and OS-aware `.git` / `.GIT` handling.
- Revalidated tracked working-tree and local-marker bytes and presence
  immediately after the final raw index snapshots, detected local-marker
  entries without following dangling links, rejected backslash-bearing Git
  paths, preserved filesystem-root identity during canonicalization, and
  started the process deadline clock before launch and POSIX session-gate
  setup. Success acceptance now rejects an elapsed total deadline even when
  the child has already exited or stream/cleanup work crosses the deadline,
  with deterministic post-exit and post-cleanup regression fixtures.
- Rechecked raw staged entry and debug metadata snapshots after final
  working-tree/local-marker byte revalidation, closing the last index-only
  mutation window with third-listing race fixtures.
- Replaced inherited Git child environments with a fixed executable-derived
  allowlist, and collapsed invalid invocation and uncaught boundary failures
  to fixed redacted exit-2 diagnostics without absolute path disclosure.
- Removed the public scanner parameter binder so invalid PowerShell common
  parameters reach the same raw-token diagnostic, and made launch cleanup
  continue through all streams, safe handles, and a final Job-close retry.
- Added first-call AST ownership regressions (including `.Invoke()` and
  `.InvokeReturnAsIs()`), rejected runtime or ambient scriptblocks in
  pre-raw pipelines, wrapper commands, and receiver-bound member dispatch,
  and required custom helpers to be unconditional top-level definitions
  executed before use. Module-qualified commands no longer inherit builtin
  or raw-target trust. Added byte-exact binary standard-stream coverage and
  a native `git cat-file --batch` fixture that detects a PowerShell 5.1 stdin
  preamble or caller console-encoding drift.
- Required receiver assignments to unconditionally dominate member calls,
  required `foreach` receiver values to come from source-bound enumerations,
  rejected ambient `global:` callable selection, and isolated each self-test
  run's scanner children in a suite-owned temporary namespace.
- Preserved and regression-tested this skill's repository URL allowlist,
  documented Windows system-path examples, and
  `CODEX_WINDOWS_SANDBOX_TROUBLESHOOTING_PRIVATE_MARKERS` input.
- Corrected the permission guidance so it no longer combines beta
  permission profiles with legacy `sandbox_mode` /
  `sandbox_workspace_write`. The English and Japanese skills and both
  permission examples now explain that the two configuration systems are
  mutually exclusive, that any loaded legacy selector takes precedence
  over `default_permissions`, and that `[windows] sandbox` is a separate
  native-backend choice.

### Changed

- Added a bounded `macos-15` validation job that requires a Darwin runtime,
  exercises the forced native `setsid(2)` process-containment fallback,
  requires target exit zero, verifies descendant cleanup, rejects a
  synthetic nonzero target, and emits an explicit gate-evidence line. The
  exact runner, timeout, command, and workflow shape are protected by the
  readiness validator and mutation fixtures.
- Selected `libSystem.B.dylib` for macOS native `setsid` / process-group
  signaling while retaining `libc` on Linux, and added a bounded fixed-code
  gate-status channel that diagnoses native library, entry-point, errno,
  and ready-file failures without reflecting target output or paths.
- Avoided the read-only PowerShell 7 `$IsMacOS` automatic variable when
  selecting the native session library.
- Expanded validation to a bounded Windows job covering PowerShell 7 and
  Windows PowerShell 5.1 plus a bounded Ubuntu 24.04 job, pinned checkout
  to an immutable revision, and made the readiness validator own the exact
  triggers, read-only permission, job set, step, property, runner, timeout,
  checkout, recursive committed-tree whitespace check, and four-file BOM
  contracts.
- Added a Markdown-fence validation guard that rejects copy-paste examples
  mixing `sandbox_mode` with `[permissions.*]`, and pinned the current
  composition contract to the official Permissions documentation checked
  on 2026-07-23.

## 0.1.0 - 2026-07-16

### Added

- Initial Codex Windows sandbox troubleshooting skill (`SKILL.md`):
  layer-based triage (config load → setup helper → process creation →
  in-sandbox runtime), symptom (a) `CreateProcessAsUserW failed: 5` on the
  agent execution path with the `codex sandbox` CLI bisect and a preserved
  worked example of a refuted contention hypothesis, symptom (b)
  Git Bash / MSYS2 `Win32 error 5` incompatibility with the PowerShell
  fallback and WSL-shim trap, symptom (c) elevated setup-helper ACL
  failures with the field-verified least-privilege recovery, symptom (d)
  the `config.toml` permission-token brick trap and safe editing
  procedure, symptom (e) the three-condition stack for writes outside the
  workspace, and least-privilege principles throughout.
- Japanese full version of the skill (`docs/SKILL.ja.md`).
- Synthetic examples: one-page layer triage checklist, CLI bisect
  commands with interpretation, and config.toml permissions with brick
  recovery.
- Private-marker scan for common secret prefixes, private-looking
  absolute paths (with allowlisted placeholders and the well-known system
  locations this skill documents), and non-allowlisted GitHub repository
  URLs (own repository and openai/codex citations allowed), with a
  self-test and local marker support through `.private-markers.local` or
  the `CODEX_WINDOWS_SANDBOX_TROUBLESHOOTING_PRIVATE_MARKERS` environment
  variable.
- OSS readiness validation script for required public project files,
  skill frontmatter, verbatim canonical error strings in both language
  versions, and the no-sandbox-bypass safety posture statement.
- GitHub Actions workflow for validation, private-marker scanning, and
  whitespace checks.
- Issue and pull request templates with sanitized-report guidance and a
  version field (all claims are version-scoped).
- Contributor, security, code of conduct, editor, and Git attribute
  documentation.
