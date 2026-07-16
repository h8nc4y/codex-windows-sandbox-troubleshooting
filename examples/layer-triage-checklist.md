# Layer Triage Checklist (One Page)

Print-friendly companion to [SKILL.md](../SKILL.md). Work top to bottom: an
earlier-layer failure masks everything after it. All examples use
placeholders; all claims are field-observed on Codex CLI 0.142.5-era builds
(as of July 2026) — retest on newer versions.

## The Table

| # | Layer | Error you see | Symptom | First move |
| --- | --- | --- | --- | --- |
| 1 | Config load | `data did not match any variant of untagged enum FilesystemPermissionToml` | (d) | Restore config backup / fix the token |
| 2 | Setup helper (ACL prep, `elevated`) | `SetNamedSecurityInfoW failed: 5` in the setup log | (c) | `:workspace` + `unelevated` fallback |
| 3 | Process creation | `windows sandbox: runner error: CreateProcessAsUserW failed: 5` | (a) | Run the CLI bisect |
| 4 | In-sandbox runtime | `CreateFileMapping ... Win32 error 5` / `couldn't create signal pipe` (Git Bash / MSYS2 only) | (b) | PowerShell fallback |
| — | Write authorization | Writes outside the workspace denied; commands otherwise fine | (e) | Check the three conditions |

Remember: error 5 = ERROR_ACCESS_DENIED at layers 2, 3, and 4 alike. The
failing **API name** locates the layer; the number does not.

## Ordered Checks

### Step 0 — Does any session start at all?

- No session starts, and the error mentions `FilesystemPermissionToml`
  → **layer 1, symptom (d)**. The config does not parse; nothing below
  this can run. Fix: restore the pre-edit backup of `config.toml`
  (typically at `~/.codex/config.toml`), or re-check your latest edit —
  the only valid filesystem permission tokens are `read` / `write` /
  `deny`.

### Step 1 — On the `elevated` backend, does setup complete?

- Even `cmd.exe /d /c echo hello` stops before launch, and the sandbox
  setup log shows ACL preparation failing with
  `SetNamedSecurityInfoW failed: 5` → **layer 2, symptom (c)**.
- Do **not** switch to full access as a "repair" — the helper refresh runs
  the same ACL processing and fails identically (field-observed).
- Field-verified fallback: `default_permissions = ":workspace"` together
  with `[windows] sandbox = "unelevated"`; write artifacts inside the
  workspace while it is in effect.

### Step 2 — Does process creation succeed?

- `windows sandbox: runner error: CreateProcessAsUserW failed: 5`
  → **layer 3, symptom (a)**. Run the decisive bisect before touching
  anything:

  ```powershell
  codex sandbox -P <profile> -C <dir> -- cmd /c echo x
  ```

- CLI succeeds, agent path (`codex mcp-server`) fails → the fault is the
  agent execution path; stop auditing ACLs. See
  [cli-bisect-commands.md](cli-bisect-commands.md).
- CLI also fails → go back up this list (config, setup helper, write
  stack).

### Step 3 — Does the spawned program initialize?

- The process starts, but Git Bash / MSYS2 dies with
  `CreateFileMapping ... Win32 error 5` or
  `couldn't create signal pipe, Win32 error 5`, while the same command
  works outside the sandbox → **layer 4, symptom (b)**.
- Use PowerShell for routine commands. Call Git Bash by absolute path
  (plain `bash` resolves to the System32 WSL shim, a different failure).
  Escalate only the specific step that truly needs Git Bash.

### Step 4 — Commands run, but writes outside the workspace fail?

- **Symptom (e)**: three independent conditions must all hold —
  1. config: `sandbox_mode = "workspace-write"` plus a profile `write`
     grant on the target path;
  2. OS ACL: the sandbox user/group (an entry like
     `<HOST>\CodexSandboxUsers`) has Modify on the target path;
  3. runner health: symptom (a) is not active.
- Prefer writing inside the workspace and collecting artifacts afterwards.

## Do-Not Reminders

- Do not kill other sessions' processes, shared runners, or the sandbox
  user's logon sessions.
- Do not run ACL/privilege surgery before the bisect (step 2) has said the
  sandbox side is actually at fault.
- Do not record "full access works" as a fix — it bypasses layers 2 and 3
  instead of repairing them.
- Do not leave a version-scoped workaround in place after upgrading Codex
  without retesting the sandboxed path.
