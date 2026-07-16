# CLI Bisect Commands

The decisive experiment for symptom (a) — `windows sandbox: runner error:
CreateProcessAsUserW failed: 5` on the agent execution path. One command
settles what a chain of ACL and privilege experiments cannot. Placeholders
only; field-observed on Codex CLI 0.142.5 (as of July 2026).

## The Bisect

Run the sandbox directly, without the agent execution path
(`codex mcp-server`):

```powershell
codex sandbox -P <profile> -C <dir> -- cmd /c echo x
```

- `-P <profile>` — the same permissions profile the failing agent session
  uses.
- `-C <dir>` — the same workspace directory.
- `-- cmd /c echo x` — the smallest possible payload; you are testing the
  spawn, not the command.

## Interpreting The Result

| Direct CLI | Agent path (`codex mcp-server`) | Conclusion |
| --- | --- | --- |
| succeeds | fails with `CreateProcessAsUserW failed: 5` | Sandbox backend, sandbox user, workspace ACLs, window-station/desktop ACLs, privileges, and modes are **all healthy**. The fault is isolated to the agent execution path. Stop auditing ACLs; treat as an upstream agent-path defect, apply the scoped workaround only if needed, retest on the next Codex version. |
| fails | fails | The problem is below the agent path. Walk the triage layers instead: config load (d), setup helper (c), write authorization (e). |
| succeeds | succeeds | No symptom (a). If something else is wrong, start from the triage table. |

Worth one paragraph of respect: in the originating field case, a
multi-session contention hypothesis looked confirmed (closing other
sessions once coincided with recovery) — and this bisect refuted it. The
CLI succeeded under every condition (non-elevated caller, elevated and
unelevated modes, private desktop on/off, headless) while the agent path
failed with the same binary and config. Run the bisect before believing
any richer story.

## Optional Variations

Each variation answers one extra question, still read-only in effect:

```powershell
# Same profile, different workspace: is it workspace-specific?
codex sandbox -P <profile> -C <other-dir> -- cmd /c echo x

# Different profile, same workspace: is it profile-specific?
codex sandbox -P <other-profile> -C <dir> -- cmd /c echo x
```

## Read-Only Diagnostics

```powershell
# Which codex mcp-server processes exist (agent execution path instances)?
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq 'codex.exe' -and $_.CommandLine -match 'mcp-server' } |
  Select-Object ProcessId, CreationDate

# Evidence of the sandbox-user model: the workspace ACL carries a
# dedicated sandbox group entry (name may vary by version).
(Get-Acl '<workspace>').Access |
  Where-Object IdentityReference -match 'CodexSandboxUsers'

# Runner helper processes (note a stuck runner in your report; do not kill it).
Get-Process -Name 'codex-command-runner*' -ErrorAction SilentlyContinue
```

## What Not To Do After A Positive Bisect

- Do not keep experimenting with DACLs, privileges, or sandbox modes — the
  bisect just proved them healthy.
- Do not kill other sessions' processes or the sandbox user's logon
  sessions; contention is probably not your cause (see the worked example
  in [SKILL.md](../SKILL.md)).
- If you must keep working before an upstream fix: the scoped
  `danger-full-access` workaround in SKILL.md applies **only** to trusted
  local work, recorded with the version it was applied on, and retired
  after retesting on the next release.
