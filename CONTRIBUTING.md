# Contributing

Thanks for improving this skill. This repository is intentionally small:
changes should make the triage sharper, the recovery safer, or a claim
better grounded.

## Before You Start

- Read [SKILL.md](SKILL.md) and the examples under [examples](examples).
- `SKILL.md` (English) is canonical. When you change it, update
  [docs/SKILL.ja.md](docs/SKILL.ja.md) in the same pull request so the two
  stay in sync.
- Do not paste tokens, credentials, private keys, OAuth codes, raw logs,
  customer data, private repository names, hostnames, usernames, or
  internal absolute paths into issues, pull requests, commits, or
  examples. No token or secret value ever belongs in this repository.
- Use synthetic placeholders such as `<profile>`, `<dir>`, `<workspace>`,
  and `<HOST>` for examples.
- Put personal or organization-specific scan markers in an untracked
  `.private-markers.local` file, not in repository source.

## Grounding Rules

This skill's value is that every rule traces to observed behavior on a
stated version. Keep it that way:

- Claims about sandbox behavior must carry the version they were observed
  on ("observed on codex-cli 0.142.5; may be fixed in later versions —
  retest before applying workarounds"). Behavior that changed in a newer
  version is a welcome contribution — update the claim, do not silently
  delete the history.
- Keep the canonical error strings verbatim (`CreateProcessAsUserW
  failed: 5`, `couldn't create signal pipe`, `CreateFileMapping ... Win32
  error 5`, `SetNamedSecurityInfoW failed: 5`,
  `FilesystemPermissionToml`). They are what readers search for; the
  validation script checks for them.
- Mark speculation and design-derived-but-unvalidated guidance explicitly
  as unverified. Do not remove existing honesty markers
  ("field-observed", "unverified") without evidence that changes their
  status.
- Do not add guidance that weakens the sandbox beyond the documented
  scoped workarounds. Recommendations must move toward least privilege;
  "disable the sandbox" is not an acceptable fix in this repository, and
  the validation script checks that the safety posture statement stays in
  `SKILL.md`.
- The misdiagnosis-and-correction worked example in symptom (a) is
  load-bearing (it teaches the bisect-first discipline); do not edit it
  away for brevity.

## Repository Hygiene

Tracked text uses UTF-8 without BOM, LF, and no trailing whitespace by
default. The scanner, its process helper, its self-test, and the readiness
validator are the documented exception: Windows PowerShell 5.1 executes
these `.ps1` files with Japanese comments, so they intentionally retain a
UTF-8 BOM. The readiness validator enforces this contract.

## Development Workflow

1. Create a focused branch.
2. Make the smallest coherent change.
3. Update examples or README text when user-facing guidance changes.
4. Add or adjust validation when a safety rule should be
   machine-checkable.
5. Run the validation commands before opening a pull request.

## Validation

From the repository root, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate-oss-readiness.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-scan-private-markers.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\scan-private-markers.ps1
git diff --check
git diff --cached --check
```

If `pwsh` is available, it is also acceptable for the PowerShell scripts:

```powershell
pwsh -NoProfile -File .\scripts\validate-oss-readiness.ps1
pwsh -NoProfile -File .\scripts\test-scan-private-markers.ps1
pwsh -NoProfile -File .\scripts\scan-private-markers.ps1
```

On macOS, Linux, or any POSIX shell with PowerShell 7 (`pwsh`) installed,
use forward slashes:

```bash
pwsh -NoProfile -File ./scripts/validate-oss-readiness.ps1
pwsh -NoProfile -File ./scripts/test-scan-private-markers.ps1
pwsh -NoProfile -File ./scripts/scan-private-markers.ps1
```

On macOS, also run the Darwin canary and forced native process-containment
evidence path:

```bash
pwsh -NoProfile -File ./scripts/test-scan-private-markers.ps1 -RequireMacOSNativePosixContainment
```

The command must print the structured Darwin/native-gate evidence line
before its normal pass line. The evidence requires target exit zero and
successful descendant cleanup; the self-test also checks that an otherwise
equivalent nonzero target is rejected. Ubuntu and Windows must continue to
use the commands above so their external-`setsid`, forced-native, Job
Object, and Windows PowerShell 5.1 coverage remain intact.

## Pull Request Expectations

- Explain the problem and the chosen fix.
- Include validation results.
- Call out any remaining unknowns.
- If the change alters a recovery step or a workaround's scope, state the
  Codex version it was verified on and the failure mode it prevents (or
  the false alarm it removes) concretely.

## Maintainer Notes

Prefer documentation and validation that keep readers on the
least-privilege path. Avoid adding broad dependencies or network-backed
checks unless they are clearly necessary for public safety.
