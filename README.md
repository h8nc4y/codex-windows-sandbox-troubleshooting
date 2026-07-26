# codex-windows-sandbox-troubleshooting

[![Validate](https://github.com/h8nc4y/codex-windows-sandbox-troubleshooting/actions/workflows/validate.yml/badge.svg)](https://github.com/h8nc4y/codex-windows-sandbox-troubleshooting/actions/workflows/validate.yml)

An agent skill for Codex on Windows (installable for Claude Code too):
triage sandbox startup failures by the layer that fails — config load,
sandbox setup helper, process creation, or the in-sandbox runtime — instead
of guessing at ACLs and privileges. Covers `CreateProcessAsUserW failed: 5`
on the agent execution path, Git Bash / MSYS2 `Win32 error 5`
incompatibility, elevated setup-helper ACL failures, and the `config.toml`
permission-token typo that bricks every session.

## What It Solves

Codex on Windows runs sandboxed commands as a dedicated local sandbox user.
When that machinery fails, three unrelated failures all print Win32 error 5
(ERROR_ACCESS_DENIED), and the obvious-looking fixes (ACL surgery, killing
processes, switching to full access) range from useless to harmful. The
skill documents, from field experience:

- **The triage table**: which error string means which failing layer, and
  why the failing API name — not the error number — locates the fault.
- **Symptom (a)** — `windows sandbox: runner error: CreateProcessAsUserW
  failed: 5` only when Codex runs via `codex mcp-server`: the one-command
  bisect (`codex sandbox` CLI vs the agent path) that clears the backend,
  ACLs, privileges, and modes all at once, plus a preserved worked example
  of a plausible-but-wrong contention hypothesis and the measurements that
  refuted it.
- **Symptom (b)** — Git Bash / MSYS2 failing only inside the sandbox
  (`CreateFileMapping ... Win32 error 5`, `couldn't create signal pipe`):
  a sandbox↔MSYS2-runtime incompatibility, the PowerShell fallback, the
  WSL-shim PATH trap, and the upstream issue references.
- **Symptom (c)** — the `elevated` backend's setup helper failing ACL
  preparation (`SetNamedSecurityInfoW failed: 5`): why full access is not a
  repair, and the field-verified least-privilege recovery combination.
- **Symptom (d)** — `config.toml` filesystem permission tokens are exactly
  `read` / `write` / `deny`; an invalid token (such as `read-write`) fails
  the whole config parse with `data did not match any variant of untagged
  enum FilesystemPermissionToml` and bricks every session. Backup and
  post-edit load checks are the discipline. Permission profiles do not
  compose with legacy `sandbox_mode` / `sandbox_workspace_write`; a mixed
  configuration uses the legacy system instead of `default_permissions`.
- **Symptom (e)** — writing outside the workspace needs three independent
  conditions (config grant, OS ACL, healthy runner); why that stack is
  fragile and what to do instead.

## Who It Is For

- Anyone running Codex on Windows whose sandbox suddenly refuses to start
  commands, or who is about to edit `config.toml` permissions.
- Agents (Codex, Claude Code, or others) that drive Codex through
  `codex mcp-server` and hit agent-path-only failures.
- Anyone deciding whether a sandbox error justifies weakening the sandbox —
  the skill's answer is a least-privilege path for each layer.

## Install

Clone the repository:

```bash
git clone https://github.com/h8nc4y/codex-windows-sandbox-troubleshooting.git
cd codex-windows-sandbox-troubleshooting
```

### Codex (agent skills)

Codex reads user-scope skills from `~/.agents/skills` (per the official
skills documentation). Manual install on shells with POSIX syntax:

```bash
dest="${HOME}/.agents/skills/codex-windows-sandbox-troubleshooting"
if [ -e "$dest" ]; then
  echo "Install target already exists: $dest"
else
  mkdir -p "$dest"
  cp SKILL.md "$dest/SKILL.md"
fi
```

Manual Codex-style skill install from PowerShell:

```powershell
$dest = Join-Path $HOME '.agents\skills\codex-windows-sandbox-troubleshooting'
if (Test-Path -LiteralPath $dest) {
  throw "Install target already exists: $dest"
}
New-Item -ItemType Directory -Path $dest | Out-Null
Copy-Item -LiteralPath .\SKILL.md -Destination (Join-Path $dest 'SKILL.md')
```

To scope the skill to a single project instead, copy `SKILL.md` to
`.agents/skills/codex-windows-sandbox-troubleshooting/SKILL.md` inside that
repository — Codex scans `.agents/skills` from the working directory up to
the repository root (per the official skills documentation).

### Claude Code

Claude Code auto-invokes the skill when a task matches the `description`
frontmatter. Install for your user account on shells with POSIX syntax:

```bash
dest="${HOME}/.claude/skills/codex-windows-sandbox-troubleshooting"
if [ -e "$dest" ]; then
  echo "Install target already exists: $dest"
else
  mkdir -p "$dest"
  cp SKILL.md "$dest/SKILL.md"
fi
```

Install for your user account from PowerShell:

```powershell
$dest = Join-Path $HOME '.claude\skills\codex-windows-sandbox-troubleshooting'
if (Test-Path -LiteralPath $dest) {
  throw "Install target already exists: $dest"
}
New-Item -ItemType Directory -Path $dest | Out-Null
Copy-Item -LiteralPath .\SKILL.md -Destination (Join-Path $dest 'SKILL.md')
```

Notes:

- If you set `CLAUDE_CONFIG_DIR`, replace `~/.claude` with that directory.
- To scope the skill to a single project instead, copy `SKILL.md` to
  `.claude/skills/codex-windows-sandbox-troubleshooting/SKILL.md` inside
  that project's repository.

The existence guard is intentional: do not overwrite an already-installed
skill without reviewing the local copy first.

If your agent reads skills from a different directory, check its
documentation and copy `SKILL.md` into the matching
`skills/codex-windows-sandbox-troubleshooting/` folder.

## Manual Use

Reach for the skill when you see one of these:

- `windows sandbox: runner error: CreateProcessAsUserW failed: 5` — often
  only when Codex runs via `codex mcp-server`, while direct CLI use works.
- Git Bash / MSYS2 commands fail only inside the sandbox with
  `CreateFileMapping ... Win32 error 5` or `couldn't create signal pipe`.
- The `elevated` backend stops even `cmd /c echo` before launch, with
  `SetNamedSecurityInfoW failed: 5` in the sandbox setup log.
- Every Codex session fails to start after a `config.toml` edit, with
  `data did not match any variant of untagged enum
  FilesystemPermissionToml`.
- A named permission profile parses but its grants are ignored while a
  legacy `sandbox_mode` setting or CLI `--sandbox` flag is active.
- A path outside the workspace stays read-only although `config.toml`
  grants `write` on it.

Then follow [SKILL.md](SKILL.md): find your error in the triage table,
jump to that symptom's section, and apply its layer-specific diagnosis —
starting with the `codex sandbox` CLI bisect where process creation is
involved.

## Synthetic Examples

- [Layer triage checklist](examples/layer-triage-checklist.md) — the
  one-page symptom-to-layer table with an ordered check sequence.
- [CLI bisect commands](examples/cli-bisect-commands.md) — the decisive
  `codex sandbox` bisect with interpretation, plus read-only diagnostics.
- [config.toml permissions](examples/config-toml-permissions.md) — valid
  permission tokens, the brick-and-recover walkthrough, and the safe
  editing procedure.

The examples use placeholders only. Do not replace them with secrets, real
repository paths you cannot publish, or customer data in public issues.

## Upstream Issues Referenced

- Agent-path spawn failures (config comments observed alongside
  `[windows] sandbox = "elevated"` reference this family):
  [openai/codex#26737](https://github.com/openai/codex/issues/26737),
  [openai/codex#26803](https://github.com/openai/codex/issues/26803)
- Git Bash / MSYS2 inside the Windows sandbox:
  [openai/codex#7031](https://github.com/openai/codex/issues/7031),
  [openai/codex#12000](https://github.com/openai/codex/issues/12000),
  [openai/codex#15016](https://github.com/openai/codex/issues/15016)
- Permissions documentation (checked 2026-07-23):
  <https://learn.chatgpt.com/docs/permissions>

Issue states change; check them before assuming a behavior still holds.

## 日本語概要 (Japanese Overview)

Windows 上の Codex サンドボックスが起動できない・書けないとき、「どの層が
失敗しているか」で切り分けるトラブルシュート集です。config ロード → setup
helper → プロセス生成 → サンドボックス内 runtime の順に見ます。

- 症状 (a): `codex mcp-server` 経由（エージェント実行経路）でのみ
  `CreateProcessAsUserW failed: 5` — 最短の切り分けは `codex sandbox` CLI
  直接実行との二分。CLI が通れば backend・ACL・特権はすべて健全で、原因は
  エージェント経路に限定できます。「多セッション競合説」を実測で棄却した
  経緯を worked example として収録。
- 症状 (b): Git Bash / MSYS2 がサンドボックス内でのみ `Win32 error 5` —
  sandbox と MSYS2 runtime の非互換。通常コマンドは PowerShell を使い、
  `bash` 名は WSL shim に解決されるため Git Bash は絶対パスで呼ぶ。
- 症状 (c): `elevated` の setup helper が ACL 準備段で
  `SetNamedSecurityInfoW failed: 5` — full access への切替は同じ ACL 処理で
  失敗するため修復手段とみなさない。実測済みの復旧は `:workspace` +
  `unelevated` の組合せ。
- 症状 (d): config.toml の filesystem 権限トークンは `read` / `write` /
  `deny` の3つだけ。`read-write` 等の無効値は config 全体をロード不能にし、
  全セッションが起動不能（ブリック）。編集前バックアップ・編集後ロード確認
  が必須。permission profile と旧 `sandbox_mode` /
  `sandbox_workspace_write` は併用できず、混在時は旧方式が
  `default_permissions` より優先される。
- 症状 (e): workspace 外への書込みは (1) config の write 許可 (2) OS ACL
  (3) runner の健全性（サンドボックスユーザーとしてのプロセス生成が通る
  こと）、の3条件がすべて要る。

この skill はサンドボックスの回避・無効化を推奨しません。原則は最小権限へ
倒すこと（PowerShell fallback、コマンド単位のエスカレーション、狭い権限、
版数を記録した一時回避と上流修正後の再検証）です。

日本語の完全版は [docs/SKILL.ja.md](docs/SKILL.ja.md) にあります。
インストールは上記の手順どおり、`SKILL.md` を Codex なら
`~/.agents/skills/codex-windows-sandbox-troubleshooting/` へ、Claude Code
なら `~/.claude/skills/codex-windows-sandbox-troubleshooting/` へコピー
してください。

## Safety Notes

- This skill never recommends bypassing or disabling the sandbox as a fix.
  `danger-full-access` appears only as a temporary avoidance strictly
  limited to trusted local work, version-recorded, and retired on the next
  release; full access is explicitly **not** a repair for the setup-helper
  failure (it fails the same way).
- Recoveries move toward least privilege: PowerShell fallback,
  per-command escalation, narrow profile grants, `:workspace` presets.
- Never kill other sessions' processes, shared runners, or the sandbox
  user's logon sessions to "free" a stuck runner.
- ACL changes on shared resources (the `icacls` grant in symptom (e))
  require the resource owner's approval.
- Never paste tokens, credentials, private logs, hostnames, usernames, or
  customer data into public issues.

## Limitations

- Runtime failures are field-observed on Codex CLI 0.142.5-era builds (as
  of July 2026). The permission-profile non-composition rule comes from
  the official beta Permissions documentation checked on 2026-07-23.
  Sandbox internals and beta configuration may change; re-check the
  official source and retest before applying a workaround on a newer
  Codex.
- The failures require an already-broken environment to reproduce, so this
  repository's CI cannot reproduce them. CI validates document structure
  and scans for private markers; the commands are syntax-checked and
  marked field-observed rather than CI-reproduced.
- The exact sandbox user/group naming, log locations, and config keys may
  vary by Codex version and install channel.

## Non-Goals

- No automation that "fixes" your sandbox for you. This repository is a
  written triage discipline with copy-adaptable commands, not a tool.
- No general Codex configuration tutorial; the focus is startup failures
  and the permission model around them.
- No sandbox-hardening or sandbox-escape research; this is operational
  troubleshooting for legitimate local development.

## Validation

Run the full local validation from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate-oss-readiness.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-scan-private-markers.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\scan-private-markers.ps1
```

If `pwsh` is available, the same checks can be run with:

```powershell
pwsh -NoProfile -File .\scripts\validate-oss-readiness.ps1
pwsh -NoProfile -File .\scripts\test-scan-private-markers.ps1
pwsh -NoProfile -File .\scripts\scan-private-markers.ps1
```

On macOS, Linux, or any POSIX shell with PowerShell 7 (`pwsh`) installed:

```bash
pwsh -NoProfile -File ./scripts/validate-oss-readiness.ps1
pwsh -NoProfile -File ./scripts/test-scan-private-markers.ps1
pwsh -NoProfile -File ./scripts/scan-private-markers.ps1
```

Also run Git whitespace checks on your working changes before publishing:

```bash
git diff --check
git diff --cached --check
```

The GitHub Actions workflow runs the same validation, scan self-test,
private-marker scan, and whitespace check on pull requests and pushes to
`main`. Windows runs the self-test separately under PowerShell 7 and
Windows PowerShell 5.1; Ubuntu 24.04 runs the PowerShell 7 self-test for
the external-`setsid` and forced-native POSIX process boundaries. macOS 15
requires a Darwin runtime canary, forces the native `setsid(2)` fallback,
and prints structured evidence only after the target exits zero and
descendant cleanup succeeds. All three jobs have a ten-minute timeout and
use an immutable checkout action revision.

The macOS-only evidence command is:

```powershell
pwsh -NoProfile -File ./scripts/test-scan-private-markers.ps1 -RequireMacOSNativePosixContainment
```

It fails outside Darwin and fails if the process boundary does not report
the forced native gate, the target exits nonzero, or cleanup is incomplete.
A final `POSIX containment evidence: platform=Darwin; ...;
nonzero-rejection=passed; descendant-cleanup=passed.` line therefore records
the exercised gate and the rejected nonzero fixture rather than treating a
generic successful exit as macOS containment evidence.

The native wrapper resolves `setsid` / `kill` through
`libSystem.B.dylib` on macOS and `libc` on other POSIX hosts. Startup
failures use a bounded, fixed-code status channel that distinguishes native
library, entry-point, type-definition, platform-detection, native-invocation,
`setsid` errno, and ready-file failures. Separately, the parent infers a fixed
gate `timeout` only when status is empty, the total deadline was reached, and
the child is still running. The child closes a staging file
before atomically publishing the final status path, so the parent never
accepts a partially written diagnostic. Unknown status content is reported
only as `unknown`; target output and paths are not reflected into the
diagnostic. The POSIX self-test injects a fixed failure at each native
startup phase, verifies the matching parent reason, and requires cleanup of
both final and staging files. Readiness validation locates the executable
wrapper assignment and its cleanup loop on the same expected try/else path,
then parses the embedded wrapper itself. It fixes all six base64 sources and
placeholder replacements; closes the status function blocks, catch-all
handlers, parameter, staging write, atomic move, and direct Exists/Delete
failure cleanup; closes the final cleanup
collection and Delete body; and allows only the eight expected wrapper
top-level statements. The wrapper-wide file-call allowlist, exact native
definition hash, phase assignments, fault seams, and direct native calls use
ordinal comparisons. Mutations hidden behind false control flow, nested
functions/scriptblocks, sliced cleanup collections, direct final writes,
altered phase names, or textual comments and here-strings therefore fail.
The Darwin evidence fixture keeps its cold child startup and `Add-Type`
compilation bounded by a 30-second test-only total deadline; production
timeouts are unchanged.

The scanner, its process helper, its self-test, and the readiness validator
contain Japanese comments and are also executed by Windows PowerShell 5.1.
These four files intentionally retain a UTF-8 BOM; the validator enforces
that exception.

Git-backed discovery is finite and isolated. Each Git command receives a
fixed-allowlist child environment, isolated configuration, bounded output,
and a deadline of at most 15 seconds. Unknown ambient and caller-provided
variables are discarded before the child starts. Windows starts the
requested executable suspended, gives only its three standard-stream
handles to the child, assigns it to a kill-on-close Job, and only then
resumes it. Assignment, resume, and consecutive Job-close failure regressions
terminate the still-suspended process, continue every remaining cleanup step,
aggregate the failures, and verify its exit within a finite wait. Every
standard stream that was created is disposed explicitly.
The direct native transport uses fixed 8 KiB buffers and raw byte streams,
so Windows PowerShell 5.1 cannot inject CLIXML or a UTF-8 stdin preamble;
regression
fixtures compare binary stdin/stdout/stderr and native
`git cat-file --batch` output byte for byte. POSIX starts the command
in a dedicated session/process group and cleans up that group when the
command times out or leaves an incomplete stream. The same total process
deadline is checked before initial success acceptance and again after stream
drain, descendant cleanup, and handle disposal.

Within a repository, the scanner checks recognized staged text blobs and
differing regular working-tree files. It requires both the final raw staged
entry and flag snapshots, each tracked working-tree file's presence and
bytes, and the local marker file's presence and bytes to match their initial
snapshots before reporting success. Raw staged entry and flag snapshots are
checked both before and after the final working-tree/local-marker
revalidation. File count, bytes, line length/count,
rule traversal, findings,
the 64 KiB serialized finding payload, process output, and the scan-wide
deadline of at most 120 seconds are independently bounded. The deadline is
checked again immediately before any clock-scoped failure diagnostic,
finding payload, or success line is written. The public scanner has no
PowerShell parameter block, so common-parameter binding cannot fail before
its raw-token validator. Invalid public arguments and uncaught helper,
process, provider, isolation, or cleanup failures collapse to fixed redacted
exit-2 diagnostics without printing an absolute path.
Diagnostics escape control and formatting characters and never print the
matched value.

Working-tree fallback is limited to confirmed non-repositories or hosts
where Git is unavailable and no `.git` entry exists in the target
ancestry. A root or ancestor `.git` file/directory that does not establish
a valid repository exits with the fixed `git-probe` integrity diagnostic.
A linked-worktree `.git` file is accepted only when Git proves the exact
checkout root. Metadata-name matching follows the operating system:
Windows treats `.git` and `.GIT` alike, while POSIX keeps `.GIT` as
ordinary case-sensitive content. Nested `.git` control entries remain
excluded from fallback content.
Other Git failures, unsupported repository entries,
symlink/reparse paths, inconsistent repository state, invalid text input,
and incomplete process output stop the scan instead of changing its
scope. The scanner remains a targeted marker check, not a universal
content classifier.

## Contributing

Contributions are welcome when they make the triage sharper, the recovery
safer, or a claim better grounded. Read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request.

Keep all examples synthetic. Do not include tokens, credentials, private
repository names, hostnames, usernames, internal absolute paths, or
customer data.

For local-only private markers, create an untracked
`.private-markers.local` file with one literal marker per line, or set
`CODEX_WINDOWS_SANDBOX_TROUBLESHOOTING_PRIVATE_MARKERS` with
newline-separated markers. The scanner reads these values but does not
print the matched marker.

## Security

If you find unsafe guidance (for example, advice that would weaken the
sandbox more than documented) or accidental private-data exposure, follow
[SECURITY.md](SECURITY.md) and use private reporting for sensitive details.

## License

MIT. See [LICENSE](LICENSE).
