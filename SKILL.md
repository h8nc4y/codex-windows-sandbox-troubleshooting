---
name: codex-windows-sandbox-troubleshooting
description: >-
  Triage Codex sandbox startup failures on Windows by failing layer — config
  load, sandbox setup helper, process creation, in-sandbox runtime — instead
  of guessing. Use on symptoms like "windows sandbox: runner error:
  CreateProcessAsUserW failed: 5" (often only on the agent execution path via
  codex mcp-server), Git Bash / MSYS2 failing only inside the sandbox with
  "CreateFileMapping ... Win32 error 5" or "couldn't create signal pipe", the
  elevated setup helper's "SetNamedSecurityInfoW failed: 5", every session
  bricked by "data did not match any variant of untagged enum
  FilesystemPermissionToml" after a config.toml permissions edit, or denied
  writes outside the workspace despite a config write grant, including a
  permission profile ignored because legacy sandbox settings are loaded.
  Covers the codex sandbox CLI bisect, PowerShell fallback for Git Bash,
  config editing, and least-privilege recovery without disabling the sandbox.
---

# Codex Windows Sandbox Troubleshooting

Codex on Windows runs sandboxed commands as a dedicated local sandbox user.
When that machinery fails, the errors look alike — three distinct failures
all surface Win32 error 5 (ERROR_ACCESS_DENIED) — but the fixes are
completely different. This skill's core move: identify the failing layer
first, from the failing API name and the boot order, then apply that layer's
specific diagnosis. Do not chase ACLs, privileges, or modes until the layer
is known.

## Scope, Versions, And Safety Posture

- Everything here is field-observed on Codex CLI 0.142.5-era builds on
  Windows (as of July 2026; symptom (c) was observed with the Codex app
  build 26.707.3351.0 alongside CLI 0.142.5). Sandbox internals change:
  observed on those versions; may be fixed in later versions — retest before
  applying workarounds.
- The permission-profile composition rules in symptoms (d) and (e) come
  from the current official Permissions documentation, checked on
  2026-07-23. Permission profiles are beta, so re-check that source before
  copying configuration into a later Codex release.
- This skill does not recommend bypassing or disabling the sandbox. Every
  recovery below moves toward least privilege first: PowerShell fallback,
  narrow profile grants, per-command escalation. Where a bypass exists
  (`danger-full-access`), it is documented as a temporary avoidance strictly
  limited to trusted local work — never as the fix.

## When To Use

- Any Codex command fails before your program runs, with one of the error
  strings in the triage table below.
- Every Codex session on the machine suddenly fails to start after a
  `config.toml` edit.
- A named permission profile parses but appears to be ignored after a
  `sandbox_mode` setting or CLI `--sandbox` flag is introduced.
- Git Bash or MSYS2 tools fail only when the Windows sandbox is enabled.
- Writes to a path outside the workspace are denied even though
  `config.toml` grants `write` on it.
- You are about to weaken or disable the sandbox to "fix" an error and want
  the least-privilege alternative first.

## Triage First: Which Layer Is Failing?

Startup crosses these layers in order. An earlier-layer failure masks
everything after it, so check in this order:

1. **Config load** — `config.toml` is parsed. A parse failure kills every
   session before any sandbox machinery starts.
2. **Sandbox setup helper** — the `elevated` backend prepares ACLs for the
   sandbox user.
3. **Process creation** — the runner spawns your command as the sandbox
   user (`CreateProcessAsUserW`).
4. **In-sandbox runtime** — the spawned program itself initializes (this is
   where the MSYS2/Git Bash runtime fails).

Write authorization (symptom (e)) is a cross-cutting stack on top: config
grant, OS ACL, and runner health must all hold.

| Error you see | Failing layer | Section |
| --- | --- | --- |
| `data did not match any variant of untagged enum FilesystemPermissionToml` | 1. Config load | (d) |
| A permission-profile grant is ignored while `sandbox_mode` or CLI `--sandbox` is active | Config selection | (d) |
| `SetNamedSecurityInfoW failed: 5` in the sandbox setup log | 2. Setup helper (ACL preparation) | (c) |
| `windows sandbox: runner error: CreateProcessAsUserW failed: 5` | 3. Process creation | (a) |
| `CreateFileMapping ... Win32 error 5` or `couldn't create signal pipe` (Git Bash / MSYS2 only) | 4. In-sandbox runtime | (b) |
| Writes outside the workspace denied; commands otherwise fine | Write authorization stack | (e) |

Error 5 is ERROR_ACCESS_DENIED in (a), (b), and (c) alike — the number does
not identify the layer. The failing **API name** does:
`SetNamedSecurityInfoW` = setup, `CreateProcessAsUserW` = spawn,
`CreateFileMapping` / signal pipe = runtime.

## Symptom (a): `CreateProcessAsUserW failed: 5` On The Agent Execution Path

What it looks like: when Codex runs via `codex mcp-server` (for example,
driven by an MCP client or another agent), **every** command fails with
`windows sandbox: runner error: CreateProcessAsUserW failed: 5` — even a
trivial `echo`, even shell-based file reads. Direct `codex sandbox` CLI
invocations of the same install can succeed at the same time — that
contrast is exactly the bisect below.

### The Decisive Bisect: `codex sandbox` CLI vs The Agent Path

Run the sandbox directly, bypassing the agent execution path:

```powershell
codex sandbox -P <profile> -C <dir> -- cmd /c echo x
```

Interpretation:

- **CLI succeeds, agent path fails** → the sandbox backend, sandbox user,
  workspace ACLs, window-station/desktop ACLs, privileges, and
  elevated/unelevated modes are all healthy — that one command clears them
  all at once. The fault is isolated to the agent execution path
  (`codex mcp-server` / exec). Stop auditing ACLs; treat it as an upstream
  agent-path defect (see the workaround below) and retest on later versions.
- **CLI also fails** → the problem is below the agent path. Work up the
  layer table instead: config load (d) or the setup helper (c) — and if
  neither matches, the spawn environment is genuinely broken on both
  paths, which puts workspace-ACL and sandbox-user diagnostics back on
  the table.

This bisect settles more in one command than a chain of ACL and privilege
experiments — run it before believing any richer story about the cause.

### Worked Example: Refuting The Wrong Hypothesis

This failure was initially misdiagnosed, and the correction is instructive
enough to preserve (field-observed, as of July 2026):

- **The plausible-but-wrong story.** The failure appeared while multiple
  agent sessions ran concurrently, sharing the sandbox user and runner.
  Contention over the shared logon looked like the cause, and closing other
  sessions *did* coincide with recovery once — which seemed to confirm it.
- **The bisect that broke the story.** `codex sandbox` CLI succeeded under
  every condition tried — non-elevated caller, elevated and unelevated
  sandbox modes, private desktop on and off, headless — while the mcp-server
  path kept failing with the same binary (0.142.5), same config, same
  non-elevated context. Contention over shared state cannot explain "one
  path always works, the other always fails."
- **Hypotheses refuted by measurement**, each tested directly:
  - Multi-session contention (the original story): disproved by the bisect;
    the one observed "recovery after closing sessions" was coincidence.
  - Window-station / desktop DACL missing a sandbox-group entry: adding an
    ACE to WinSta0 / Default changed nothing.
  - Caller elevation: with every involved process non-elevated, the CLI
    still succeeded.
  - Stale mcp-server process: a freshly started server failed identically.
  - Install-channel mismatch (npm vs app): both were the same version.
  - Sandbox mode and `sandbox_private_desktop`: no combination mattered.
- **Where it actually broke.** The sandbox user's LastLogon timestamp
  updated on every attempt, so `LogonUser` succeeded; the failure is after
  token acquisition, at process creation. Error 5 (ACCESS_DENIED), not 1326
  (bad password), not 1314 (missing privilege). Binary strings include
  `failed to lock ConPTY handle`; the agent path uses a ConPTY/tty plus
  restricted-token spawn that the direct CLI does not exercise — the defect
  lives in that path. The config comments observed alongside `[windows]
  sandbox = "elevated"` reference the same known issue family
  (openai/codex#26737, openai/codex#26803).

The lesson: correlation with concurrent sessions was coincidence. One
decisive bisect beats serial elimination of plausible causes — and it is
also the cheapest experiment of the lot.

### Read-Only Diagnostics

```powershell
# Which codex mcp-server processes exist (agent execution path instances)?
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq 'codex.exe' -and $_.CommandLine -match 'mcp-server' } |
  Select-Object ProcessId, CreationDate

# Evidence of the sandbox-user model: the workspace ACL carries a
# dedicated sandbox group entry (name may vary by version).
(Get-Acl '<workspace>').Access |
  Where-Object IdentityReference -match 'CodexSandboxUsers'

# Runner helper processes (a stuck runner is worth noting, not killing).
Get-Process -Name 'codex-command-runner*' -ErrorAction SilentlyContinue
```

### Workaround, Strictly Scoped

`sandbox = "danger-full-access"` on the agent path avoids the failure —
because it does not enter the sandbox at all; commands run directly as your
own user account. Field-confirmed to work on 0.142.5, and acceptable only
under all of these conditions:

- The work is trusted local development you would run unsandboxed anyway.
- The setting is temporary and tracked: record the version it was applied
  on, and retest `read-only` / `workspace-write` on the agent path when a
  newer Codex arrives (observed broken on 0.142.5; for example, retest on
  0.143 or whatever the next stable is), then remove the workaround.
- You treat it as an avoidance, not a repair — the sandbox is still broken
  on the agent path, and full access removes the security boundary rather
  than fixing it.

### Do Not

- Do not kill other sessions' processes, the shared runner, or the sandbox
  user's logon sessions to "free" the runner. You risk destroying other
  work in flight, and — per the worked example — contention is probably not
  your cause anyway.
- Do not start DACL/privilege surgery before running the bisect.

## Symptom (b): Git Bash / MSYS2 Fail Only Inside The Sandbox

What it looks like (minimal commands, field-observed):

- `C:\Program Files\Git\bin\bash.exe -lc ...` fails with
  `CreateFileMapping ... Win32 error 5`.
- `C:\Program Files\Git\usr\bin\bash.exe -lc ...` fails with
  `couldn't create signal pipe, Win32 error 5`.
- The same Git Bash works normally outside the sandbox.

This is a layer-4 failure: the sandbox created the process fine (unlike
symptom (a)); the MSYS2 runtime then failed to create the kernel objects
(file mappings, pipes) it needs under the sandbox's restrictions. Workspace
ACLs are typically healthy — this is an incompatibility between the sandbox
and the MSYS2 runtime, not a filesystem permission gap, so ACL work will
not fix it.

The WSL shim trap, distinct from the above: invoking plain `bash` resolves
through PATH to `C:\Windows\System32\bash.exe` — the WSL shim, not Git
Bash — which fails differently with
`Bash/Service/CreateInstance/E_ACCESSDENIED`. Always call Git Bash by
absolute path so you know which failure you are even looking at.

Practical rules:

1. Inside the sandbox, use PowerShell for routine commands. It does not
   depend on the MSYS2 runtime and works where Git Bash cannot.
2. If a step genuinely requires Git Bash, run **that step only** outside
   the sandbox through your tool's escalation/approval mechanism (in Codex,
   an escalated exec that prompts for approval). Do not disable the sandbox
   globally to make `bash` work.
3. Refer to Git Bash by absolute path (or an explicit variable you set);
   never rely on `bash` from PATH on Windows.

Upstream reports of the same class: openai/codex#7031, openai/codex#12000,
openai/codex#15016 — Windows-sandbox-only failures of Git Bash / `sh.exe`
with `couldn't create signal pipe` or `CreateFileMapping` error 5, where
PowerShell works. Other agent tools have likewise treated Windows sandbox +
Git Bash/MSYS2 as a known incompatibility (as of July 2026). Retest after
upgrading Codex before assuming it still holds.

## Symptom (c): `elevated` Setup Helper Fails ACL Preparation

What it looks like: with the `elevated` sandbox backend, even
`cmd.exe /d /c echo hello` stops **before launch**. The sandbox setup log
shows the helper failing while preparing ACLs — observed entries include
adding a write ACE to a non-system drive root and a read ACE to app package
resources, each ending in `SetNamedSecurityInfoW failed: 5`.

This is a layer-2 failure — earlier than (a)'s process creation and (b)'s
runtime. The command never gets as far as a spawn attempt.

Two hard-won facts (field-observed on app build 26.707.3351.0 / CLI
0.142.5):

- **Full access is not a repair.** Switching to full access made the helper
  refresh run the same ACL processing — and fail the same way. "It worked
  under full access" only means the broken layer was bypassed; do not
  record the environment as fixed on that basis.
- **A weaker backend + narrower permissions recovered it.** The
  field-verified recovery combination was `default_permissions =
  ":workspace"` together with `[windows] sandbox = "unelevated"`. On the
  observed host, `unelevated` alone was not enough to keep using the
  previously active profile (one with explicit read / deny carve-outs) —
  the profile also had to drop to the plain workspace preset.

Consequences to plan around while running the fallback:

- A plain workspace profile denies writes outside the workspace. Tasks that
  used to write elsewhere should write into the workspace and let a human
  (or a later non-sandboxed step) collect the artifacts.
- `unelevated` is the weaker backend: network isolation and read/write
  split enforcement are weaker than under `elevated`. Treat it as a
  fallback, not the new normal.
- When a later Codex version lets you return to `elevated`, re-verify the
  full boundary before trusting it: setup helper log clean, writes outside
  the workspace still denied, credential paths still denied, network
  isolation behaving as configured.

## Symptom (d): `config.toml` Filesystem Permission Tokens — The Brick Trap

Permission profiles are beta and **do not compose with the older
`sandbox_mode` / `[sandbox_workspace_write]` settings**. Choose one
configuration system for a session:

- Permission-profile path: set `default_permissions` and define
  `[permissions.<name>]`; remove `sandbox_mode` and
  `[sandbox_workspace_write]` from every loaded config layer.
- Legacy path: set `sandbox_mode` and, when needed,
  `[sandbox_workspace_write]`; do not expect `[permissions.*]` or
  `default_permissions` to apply.

If `sandbox_mode` appears in any loaded config, the selected config profile
sets it, or the CLI passes `--sandbox`, Codex uses the legacy settings
instead of `default_permissions`. The Windows-native backend selector
`[windows] sandbox = "elevated" | "unelevated"` is separate from the
top-level legacy `sandbox_mode` and may accompany either system. The
documented exception is managed `allowed_permission_profiles`, which
forces permission profiles; administrators deploying it should remove the
older settings as the official guide requires.

The filesystem permission values in `[permissions.<profile>.filesystem]`
accept exactly three tokens:

- `read` — read only.
- `write` — read **and** write (create, rename, delete included).
- `deny` — no access; used for carve-outs such as `"**/*.env" = "deny"`.

There is no `read-write` token. Write access is `write`, one word.

```toml
# Valid permission-profile example. Do not add sandbox_mode.
default_permissions = "dev"

[permissions.dev]
extends = ":workspace"

[permissions.dev.filesystem]
glob_scan_max_depth = 3
"C:/path/to/data"    = "write"
"C:/path/to/ref"     = "read"

[permissions.dev.filesystem.":workspace_roots"]
"**/*.env"           = "deny"
```

The trap: an invalid token does not just disable that one profile. It makes
the whole `config.toml` fail to parse at startup:

```text
data did not match any variant of untagged enum FilesystemPermissionToml
```

and **every Codex session on the machine fails to start** (bricked) until
the file is fixed. The blast radius is total, and the observed error output
named only the enum — it did not point at the offending line.

Safe editing procedure:

1. Back up `config.toml` before editing.
2. Use only `read` / `write` / `deny` as values.
3. After editing, immediately start one session (or run any trivial CLI
   command that loads the config) and confirm the config parses. Never
   batch-edit and walk away.
4. If you are bricked: restore the backup, or re-check the most recent edit
   for an invalid token — the observed parse error did not point at the
   line.

Reference (checked 2026-07-23): the official Permissions documentation at
https://learn.chatgpt.com/docs/permissions

## Symptom (e): Writing Outside The Workspace Needs Three Conditions

On Windows, a `config.toml` write grant alone does not make a path outside
the workspace (cwd) writable. All three of these must hold:

1. **Config**: choose one configuration system, not a mixture. On the
   permission-profile path, `default_permissions` must select a profile
   whose `[permissions.<profile>.filesystem]` grants
   `"<absolute path>" = "write"`, and no loaded config layer or CLI
   `--sandbox` may select the legacy system. On the legacy path, use
   `sandbox_mode = "workspace-write"` plus the path in
   `[sandbox_workspace_write].writable_roots`; do not combine that with a
   permission-profile grant.
2. **OS ACL**: the sandbox executes commands as a dedicated local sandbox
   user/group — visible as an entry like `<HOST>\CodexSandboxUsers` with
   Modify rights in the workspace's ACL, which Codex adds to the workspace
   automatically. A path outside the workspace has no such entry, so the
   OS denies the write even though config allows it. Granting it (only
   with the resource owner's approval — this changes ACLs on a possibly
   shared resource):

   ```powershell
   icacls "<dir>" /grant "<HOST>\CodexSandboxUsers:(OI)(CI)M" /T
   ```

3. **Runner health**: process creation as the sandbox user must actually
   work. If symptom (a) is active, the write fails at spawn regardless of
   conditions 1 and 2.

Because three independent conditions must all hold, direct writes outside
the workspace are fragile on Windows. Prefer writing artifacts inside the
workspace and collecting them afterwards; reserve outside-the-workspace
grants for cases that truly need them, and keep each grant as narrow as
possible.

## Principles

- **Identify the layer before touching anything.** Config load → setup
  helper → process creation → in-sandbox runtime. Win32 error 5 appears at
  three different layers; the failing API name locates it, the number does
  not.
- **Prefer the decisive bisect over serial elimination.** `codex sandbox`
  CLI vs the agent path settles backend, ACLs, privileges, and modes in one
  command. The worked example above exists because plausible stories
  survive until that experiment runs.
- **Move toward least privilege, not away from it.** PowerShell fallback,
  per-command escalation, narrow profile grants, `:workspace` presets —
  before any global weakening. Disabling the sandbox
  (`danger-full-access`) is a temporary avoidance for trusted local work
  only, and it carries an expiry: retest on the next version.
- **"Full access works" is not a diagnosis and not a repair.** It bypasses
  layers (a) and (c) rather than fixing them, and for (c) the helper was
  observed failing identically under full access anyway.
- **Do not kill what you do not own.** Other sessions' processes, shared
  runners, and the sandbox user's logon sessions stay up. Note a stuck
  runner in your report; let a human decide.
- **Workarounds are version-scoped.** Record the version each was observed
  on; when Codex updates, retest the sandboxed path first and retire the
  workaround. Leaving an expired bypass in place is how a temporary
  avoidance becomes a permanent hole.
- **Edit `config.toml` like production config.** Backup first, valid
  tokens only, load-check immediately after — one bad permission token
  bricks every session on the machine.

## Provenance

Every rule above traces to field observation on Windows hosts running
Codex CLI 0.142.5-era builds (as of July 2026) — including one documented
misdiagnosis and its correction, preserved as a worked example rather than
edited out. Wording like "field-observed" marks behavior actually hit and
worked through; anything not directly measured is marked unverified.

Reproducing these failures requires an environment that is already broken
in the right way, so this repository's CI does not attempt reproduction:
it validates document structure and scans for private markers, and the
commands here are syntax-checked (PowerShell parses them) and marked
field-observed rather than CI-reproduced. Version numbers are part of every
claim on purpose: sandbox internals change, and a workaround that outlives
its bug becomes a liability.
