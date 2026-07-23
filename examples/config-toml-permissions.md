# config.toml Permissions: Correct Usage And Brick Recovery

Companion to symptom (d) and (e) in [SKILL.md](../SKILL.md). Placeholders
only. Official reference checked 2026-07-23:
<https://learn.chatgpt.com/docs/permissions>

## The Only Three Tokens

Filesystem permission values in `[permissions.<profile>.filesystem]`
accept exactly `read`, `write`, and `deny`:

```toml
# Valid permission-profile shape. Do not add sandbox_mode.
default_permissions = "dev"

[permissions.dev]
extends = ":workspace"

[permissions.dev.filesystem]
glob_scan_max_depth = 3
"C:/path/to/data"  = "write"   # read AND write (create/rename/delete included)
"C:/path/to/ref"   = "read"    # read only

[permissions.dev.filesystem.":workspace_roots"]
"**/*.env"         = "deny"    # carve-out: no access even under a write grant
```

There is no `read-write` token. Write access is `write`, one word.

## Choose One Configuration System

Permission profiles are beta and do not compose with the older
`sandbox_mode` / `[sandbox_workspace_write]` settings:

- Permission-profile path: use `default_permissions` plus
  `[permissions.<name>]`, with no `sandbox_mode` or
  `[sandbox_workspace_write]` in any loaded config layer.
- Legacy path: use `sandbox_mode` plus `[sandbox_workspace_write]` when
  needed; do not expect `default_permissions` or `[permissions.*]` to
  apply.

If `sandbox_mode` appears in any loaded config, the selected config
profile sets it, or the command passes `--sandbox`, Codex selects the
legacy system instead of `default_permissions`. The native Windows
`[windows] sandbox = "elevated" | "unelevated"` selector is separate and
can accompany either system. Managed `allowed_permission_profiles` is the
documented exception that forces permission profiles; administrators
deploying it should remove older settings as the official guide requires.

For comparison, this is a legacy-only shape; keep it in a different
configuration from the permission-profile example above:

```toml
sandbox_mode = "workspace-write"

[sandbox_workspace_write]
writable_roots = ["C:/path/to/data"]
```

## The Brick: What An Invalid Token Does

An invalid value — for example `= "read-write"` — does not merely disable
that profile. The whole `config.toml` fails to parse at startup:

```text
data did not match any variant of untagged enum FilesystemPermissionToml
```

Consequences (field-observed):

- **Every** Codex session on the machine fails to start, not just the
  edited profile. The blast radius is total.
- The observed error output named only the enum — it did not point at the
  offending entry.

## Safe Editing Procedure

1. **Back up first**:

   ```powershell
   Copy-Item -LiteralPath "$HOME\.codex\config.toml" -Destination "$HOME\.codex\config.toml.bak"
   ```

2. Choose either permission profiles or the legacy sandbox settings,
   never both. On the permission-profile path, use only `read` / `write` /
   `deny` as filesystem permission values.
3. **Load-check immediately** — start one session, or run any trivial CLI
   command that loads the config, and confirm no parse error appears.
   Never batch-edit and walk away.
4. Keep the backup until the load check passes.

## Recovery When Bricked

1. Restore the backup:

   ```powershell
   Copy-Item -LiteralPath "$HOME\.codex\config.toml.bak" -Destination "$HOME\.codex\config.toml"
   ```

2. No backup? Re-open the config and re-check the **most recent edit**
   for a non-token value (`read-write`, `rw`, `readonly`, quotes missing,
   etc.) — the observed parse error did not point at the line.
3. Load-check again before doing anything else.

## Reminder: A Write Grant Alone Is Not Enough Outside The Workspace

On Windows, writing to a path outside the workspace needs all three
(symptom (e) in SKILL.md):

1. Config: one complete configuration system. Either
   `default_permissions` selects a profile with an
   `"<absolute path>" = "write"` grant and no legacy selector is loaded,
   or the legacy `sandbox_mode = "workspace-write"` configuration lists
   the path in `[sandbox_workspace_write].writable_roots`.
2. OS ACL: the dedicated sandbox user/group (an entry like
   `<HOST>\CodexSandboxUsers`) holding Modify on the target — Codex adds
   this to the workspace automatically, but not to outside paths. Granting
   it requires the resource owner's approval:

   ```powershell
   icacls "<dir>" /grant "<HOST>\CodexSandboxUsers:(OI)(CI)M" /T
   ```

3. Runner health: process creation as the sandbox user actually works
   (symptom (a) not active).

If any one is missing, the write fails — config edits alone cannot fix an
OS-ACL or runner-layer denial. Prefer writing inside the workspace and
collecting artifacts afterwards.
