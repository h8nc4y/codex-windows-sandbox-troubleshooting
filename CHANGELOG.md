# Changelog

All notable changes to this project are documented in this file.

The format loosely follows Keep a Changelog conventions.

## Unreleased

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
