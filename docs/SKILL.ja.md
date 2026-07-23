# Codex Windows サンドボックス・トラブルシューティング（日本語完全版）

これは [SKILL.md](../SKILL.md)（英語・正典）の日本語完全版です。内容が食い違う
場合は英語版を正とします。

Codex は Windows 上で、サンドボックス化したコマンドを専用のローカル・サンド
ボックスユーザーとして実行します。この機構が壊れたとき、エラーは互いに似て
見えます — 実際、3つの異なる失敗がどれも Win32 error 5
(ERROR_ACCESS_DENIED) を出します — が、直し方はまったく異なります。この
skill の核となる動き: **まず失敗している層を特定する**。失敗した API 名と
起動順から層を割り出し、その層に固有の診断を適用します。層が分かるまで
ACL・特権・モードをいじり回さないこと。

## 対象範囲・バージョン・安全姿勢

- 本書の内容はすべて Windows 上の Codex CLI 0.142.5 世代のビルドでの実測
  です（2026年7月時点。症状 (c) は Codex app build 26.707.3351.0 + CLI
  0.142.5 で観測）。サンドボックス内部は変わります: 「observed on
  <version>; may be fixed in later versions — retest before applying
  workarounds」（当該版での観測であり、以降の版では修正されている可能性が
  ある。回避策を適用する前に再検証すること）という限定つきで読んでください。
- 症状 (d)・(e) の permission profile 合成規則は、2026-07-23 に確認した
  現行の公式 Permissions ドキュメントに基づきます。permission profile は
  beta のため、後の Codex 版へ設定をコピーする前に一次情報を再確認して
  ください。
- この skill はサンドボックスの回避・無効化を修復手段として推奨しません。
  以下の復旧手順はすべて最小権限側へ倒します: PowerShell fallback、狭い
  profile 権限、コマンド単位のエスカレーション。バイパス
  （`danger-full-access`）に触れる箇所は、「信頼済みローカル作業に限定した
  一時回避」としてのみ記述しており、修復とは扱いません。

## いつ使うか

- どの Codex コマンドも、プログラムが動き出す前に、下の triage 表にある
  エラー文字列のどれかで失敗する。
- `config.toml` を編集した直後から、マシン上の全 Codex セッションが起動
  しなくなった。
- named permission profile はパースされるのに、`sandbox_mode` の設定や CLI
  `--sandbox` の追加後から適用されなくなった。
- Git Bash / MSYS2 系ツールが、Windows サンドボックス有効時だけ失敗する。
- `config.toml` で `write` を許可しているのに、workspace 外パスへの書込みが
  拒否される。
- エラーを「直す」ためにサンドボックスを弱めよう・切ろうとしていて、その前に
  最小権限の代替を確認したい。

## まず triage: どの層が失敗しているか

起動は次の層を順に通過します。前の層の失敗は後の層をすべて覆い隠すので、
この順で確認します:

1. **Config ロード** — `config.toml` のパース。パース失敗は、サンドボックス
   機構が動き出す前に全セッションを殺します。
2. **サンドボックス setup helper** — `elevated` backend がサンドボックス
   ユーザー用の ACL を準備する段。
3. **プロセス生成** — runner がコマンドをサンドボックスユーザーとして
   spawn する段（`CreateProcessAsUserW`）。
4. **サンドボックス内 runtime** — spawn されたプログラム自身の初期化
   （MSYS2 / Git Bash の runtime が失敗するのはここ）。

書込み認可（症状 (e)）はこの上に載る横断的なスタックです: config の許可、
OS ACL、runner の健全性の3つが揃う必要があります。

| 見えているエラー | 失敗している層 | 節 |
| --- | --- | --- |
| `data did not match any variant of untagged enum FilesystemPermissionToml` | 1. Config ロード | (d) |
| `sandbox_mode` または CLI `--sandbox` が有効な間だけ permission profile の grant が無視される | Config 選択 | (d) |
| sandbox setup log 内の `SetNamedSecurityInfoW failed: 5` | 2. Setup helper（ACL 準備） | (c) |
| `windows sandbox: runner error: CreateProcessAsUserW failed: 5` | 3. プロセス生成 | (a) |
| `CreateFileMapping ... Win32 error 5` / `couldn't create signal pipe`（Git Bash / MSYS2 のみ） | 4. サンドボックス内 runtime | (b) |
| workspace 外への書込みだけ拒否され、コマンド自体は動く | 書込み認可スタック | (e) |

Error 5 は (a)(b)(c) のどれでも ERROR_ACCESS_DENIED です — 番号は層を特定
しません。特定するのは失敗した **API 名** です: `SetNamedSecurityInfoW` =
setup、`CreateProcessAsUserW` = spawn、`CreateFileMapping` / signal pipe =
runtime。

## 症状 (a): エージェント実行経路での `CreateProcessAsUserW failed: 5`

何が起きるか: Codex を `codex mcp-server` 経由（例: MCP クライアントや別の
エージェントから駆動する場合）で動かすと、**すべての**コマンドが
`windows sandbox: runner error: CreateProcessAsUserW failed: 5` で失敗
します — 単純な `echo` も、シェル経由のファイル読取もです。同じ Codex の
`codex sandbox` CLI 直接実行は同時刻でも成功し得ます — その対比こそが
下の二分法です。

### 決定的な二分法: `codex sandbox` CLI vs エージェント経路

エージェント実行経路を通さず、サンドボックスを直接起動します:

```powershell
codex sandbox -P <profile> -C <dir> -- cmd /c echo x
```

解釈:

- **CLI が成功し、エージェント経路だけ失敗する** → sandbox backend、
  サンドボックスユーザー、workspace の ACL、ウィンドウステーション／
  デスクトップの ACL、特権、elevated/unelevated モードは**すべて健全**
  — この1コマンドで全部まとめて潔白が証明されます。原因はエージェント
  実行経路（`codex mcp-server` / exec）に限定されます。ACL 監査は打ち
  切り、上流のエージェント経路の不具合として扱い（下記の回避策参照）、
  新しい版で再検証します。
- **CLI も失敗する** → 問題はエージェント経路より下にあります。層の表に
  沿って config ロード (d)、setup helper (c) を見ます — どちらにも該当
  しなければ、spawn 環境そのものが両経路で壊れており、workspace ACL と
  サンドボックスユーザーの診断が改めて俎上に載ります。

この二分法は、ACL・特権の実験を連ねるより多くのことを1コマンドで確定
させます。原因についてどんなもっともらしい説を信じるより先に、まずこれを
実行してください。

### Worked example: 誤った仮説を実測で棄却した経緯

この失敗は最初、誤診断されました。その訂正の経緯は保存する価値があるので
そのまま収録します（実測、2026年7月時点）:

- **もっともらしいが誤りだった説。** 失敗は複数のエージェントセッションが
  並行し、サンドボックスユーザーと runner を共有している状況で発生しま
  した。共有 logon の取り合い（競合）が原因に見え、実際に他セッションを
  閉じたら一度は復旧した — これが説を「確認」したように見えました。
- **説を壊した二分法。** `codex sandbox` CLI は試したすべての条件で成功
  — 非昇格の呼び出し元でも、elevated / unelevated モードでも、private
  desktop の有無でも、headless でも — 一方 mcp-server 経路は同一バイナリ
  (0.142.5)・同一 config・同一非昇格文脈で失敗し続けました。共有状態の
  競合では「片方の経路は常に成功し、もう片方は常に失敗する」ことを説明
  できません。
- **実測で棄却できた仮説**（それぞれ直接検証済み）:
  - 多セッション競合（元々の説）: 二分法で棄却。観測された「他セッション
    を閉じたら復旧」は偶然の一致。
  - ウィンドウステーション / デスクトップ DACL にサンドボックスグループの
    エントリが無い説: WinSta0 / Default に ACE を追加しても変化なし。
  - 呼び出し元の昇格: 関与する全プロセスが非昇格でも CLI は成功。
  - mcp-server プロセスの経年劣化: 新規起動した server も同様に失敗。
  - インストール経路の差（npm vs app）: 両者同一バージョン。
  - sandbox モードと `sandbox_private_desktop`: どの組合せでも無関係。
- **実際に壊れていた場所。** サンドボックスユーザーの LastLogon が毎回
  更新されていたので `LogonUser` は成功しており、失敗はトークン取得の
  **後**、プロセス生成の段です。Error 5 (ACCESS_DENIED) であって 1326
  （パスワード不一致）でも 1314（特権欠如）でもない。バイナリ内の文字列に
  `failed to lock ConPTY handle` があり、エージェント経路は直接 CLI が
  通らない ConPTY/tty + restricted-token spawn を使います — 不具合はその
  経路にあります。`[windows] sandbox = "elevated"` とともに観測された
  config コメントも同じ既知 issue 系（openai/codex#26737、
  openai/codex#26803）を参照しています。

教訓: 並行セッションとの相関は偶然でした。決定的な二分法1つは、もっとも
らしい原因を順に潰していく作業に勝ります — しかも一番安い実験です。

### 読取専用の診断コマンド

```powershell
# codex mcp-server プロセス（エージェント実行経路のインスタンス）の一覧
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq 'codex.exe' -and $_.CommandLine -match 'mcp-server' } |
  Select-Object ProcessId, CreationDate

# サンドボックスユーザー方式の証拠: workspace の ACL に専用サンドボックス
# グループのエントリが入っている（名前は版により変わり得る）。
(Get-Acl '<workspace>').Access |
  Where-Object IdentityReference -match 'CodexSandboxUsers'

# runner helper プロセス（stuck していても kill せず、報告に留める）。
Get-Process -Name 'codex-command-runner*' -ErrorAction SilentlyContinue
```

### 回避策（厳密にスコープを切る）

エージェント経路での `sandbox = "danger-full-access"` はこの失敗を回避
できます — サンドボックスに入らず、コマンドがあなた自身のユーザーとして
直接実行されるからです。0.142.5 で動作することを実測済みですが、許容される
のは次のすべてを満たす場合だけです:

- その作業が、サンドボックス無しでも実行するであろう信頼済みのローカル
  開発であること。
- 設定が一時的であり、追跡されていること: 適用した版を記録し、新しい
  Codex が来たらエージェント経路の `read-only` / `workspace-write` を
  再検証して（0.142.5 で破損を観測。例えば 0.143 なり次の stable なりで
  要再検証）、回避策を撤去すること。
- これを修復ではなく回避として扱うこと — エージェント経路のサンドボックス
  は壊れたままであり、full access は境界を直すのではなく取り払っています。

### してはいけないこと

- runner を「解放」する目的で、他セッションのプロセス・共有 runner・
  サンドボックスユーザーの logon セッションを kill しないこと。進行中の
  他の作業を壊すリスクがあり、しかも worked example のとおり、競合は
  おそらくあなたの原因ではありません。
- 二分法を実行する前に DACL / 特権の手術を始めないこと。

## 症状 (b): Git Bash / MSYS2 がサンドボックス内でのみ失敗する

何が起きるか（最小コマンド、実測）:

- `C:\Program Files\Git\bin\bash.exe -lc ...` が
  `CreateFileMapping ... Win32 error 5` で失敗。
- `C:\Program Files\Git\usr\bin\bash.exe -lc ...` が
  `couldn't create signal pipe, Win32 error 5` で失敗。
- 同じ Git Bash がサンドボックス外では正常に動く。

これは層4の失敗です: サンドボックスはプロセス生成までは成功しており
（症状 (a) との違い）、その後 MSYS2 runtime が、サンドボックスの制約下で
必要な kernel object（file mapping、pipe）を作れずに落ちています。
workspace の ACL は通常健全です — これはサンドボックスと MSYS2 runtime の
非互換であって、ファイルシステム権限の不足ではないため、ACL をいじっても
直りません。

WSL shim の罠（上記とは別物）: 素の `bash` は PATH 解決で
`C:\Windows\System32\bash.exe` — Git Bash ではなく WSL shim — に到達し、
別のエラー（`Bash/Service/CreateInstance/E_ACCESSDENIED`）で失敗します。
どの失敗を見ているのかを分かった状態にするため、Git Bash は必ず絶対パスで
呼んでください。

実務ルール:

1. サンドボックス内の通常コマンドは PowerShell を使う。MSYS2 runtime に
   依存せず、Git Bash が動かない場所でも動きます。
2. 本当に Git Bash が必要な工程は、**その工程だけ**をツールのエスカレー
   ション／承認機構でサンドボックス外実行する（Codex なら承認を挟む
   escalated exec）。`bash` を動かすためにサンドボックス全体を無効化
   しないこと。
3. Git Bash は絶対パス（または自分で明示的に設定した変数）で参照する。
   Windows で PATH 上の `bash` に頼らないこと。

同種の上流報告: openai/codex#7031、openai/codex#12000、openai/codex#15016
— Windows サンドボックス有効時のみ Git Bash / `sh.exe` が
`couldn't create signal pipe` または `CreateFileMapping` の error 5 で失敗
し、PowerShell は動く、という内容です。他のエージェントツールでも Windows
サンドボックス + Git Bash/MSYS2 は既知の非互換として扱われています
（2026年7月時点）。Codex を更新したら、まだ該当するか再検証してください。

## 症状 (c): `elevated` setup helper が ACL 準備で失敗する

何が起きるか: `elevated` サンドボックス backend で、
`cmd.exe /d /c echo hello` のような最小コマンドすら**起動前に**止まり
ます。sandbox setup log には、helper が ACL 準備中に失敗した記録が残り
ます — 観測した項目は、非システムドライブの root への write ACE 追加と、
app package resources への read ACE 追加が、いずれも
`SetNamedSecurityInfoW failed: 5` で終わっているものでした。

これは層2の失敗です — (a) のプロセス生成、(b) の runtime より前であり、
コマンドは spawn の試行にすら到達しません。

実測で得た2つの事実（app build 26.707.3351.0 / CLI 0.142.5 で観測）:

- **Full access は修復手段ではない。** full access へ切り替えても、helper
  の refresh は同じ ACL 処理を実行し — 同じように失敗しました。「full
  access なら動いた」は壊れた層を迂回したという意味でしかなく、それを
  根拠に環境を修復済みと記録しないでください。
- **より弱い backend + より狭い権限の組合せで復旧した。** 実測で確認できた
  復旧組合せは `default_permissions = ":workspace"` と
  `[windows] sandbox = "unelevated"` の併用です。観測したホストでは
  `unelevated` 単独では、それまで使っていた profile（明示的な read / deny
  carve-out を持つもの）を使い続けることができず、profile 側も素の
  workspace プリセットまで落とす必要がありました。

fallback 運用中に織り込むべき帰結:

- 素の workspace profile は workspace 外への書込みを拒否します。これまで
  外部へ書いていたタスクは、workspace 内に成果物を書き、人間（または後段の
  非サンドボックス工程）が回収する形に変えます。
- `unelevated` は弱い方の backend です: network isolation と read/write
  分離の強制は `elevated` より弱くなります。fallback として扱い、新しい
  常態にしないこと。
- 後の版で `elevated` に戻せるようになったら、信頼する前に境界を一式再検証
  します: setup helper のログが clean であること、workspace 外への書込みが
  引き続き拒否されること、credential パスが引き続き拒否されること、network
  isolation が設定どおりに振る舞うこと。

## 症状 (d): `config.toml` の filesystem 権限トークン — ブリックの罠

Permission profile は beta で、旧式の `sandbox_mode` /
`[sandbox_workspace_write]` とは**併用できません**。1セッションでは次の
どちらか一方を選びます:

- permission profile 方式: `default_permissions` と
  `[permissions.<name>]` を使い、ロード対象の全 config layer から
  `sandbox_mode` と `[sandbox_workspace_write]` を除く。
- 旧方式: `sandbox_mode` と、必要なら `[sandbox_workspace_write]` を使い、
  `[permissions.*]` / `default_permissions` が適用されるとは考えない。

どのロード対象 config にでも `sandbox_mode` がある、選択した config
profile がそれを設定する、または CLI へ `--sandbox` を渡すと、Codex は
`default_permissions` より旧方式を優先します。Windows native backend を
選ぶ `[windows] sandbox = "elevated" | "unelevated"` は、top-level の旧
`sandbox_mode` とは別物で、どちらの方式とも組み合わせられます。文書化
された例外は managed `allowed_permission_profiles` で、permission profile
を強制します。これを配備する管理者は、公式手順どおり旧設定を除去して
ください。

`[permissions.<profile>.filesystem]` の権限値が受け付けるトークンは
ちょうど3つです:

- `read` — 読取のみ。
- `write` — 読取**と**書込み（作成・改名・削除を含む）。
- `deny` — アクセス禁止。`"**/*.env" = "deny"` のような carve-out に使う。

`read-write` というトークンは存在しません。書込み許可は `write` の一語
です。

```toml
# 正しい permission profile 例。sandbox_mode は追加しない。
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

罠: 無効なトークンは、その profile を無効にするだけでは済みません。
`config.toml` 全体が起動時にパース失敗します:

```text
data did not match any variant of untagged enum FilesystemPermissionToml
```

そして修正するまで**マシン上の全 Codex セッションが起動不能**（ブリック）
になります。爆風は全域に及び、観測したエラー出力は enum 名を言うだけで、
問題の行を指しませんでした。

安全な編集手順:

1. 編集前に `config.toml` をバックアップする。
2. 値には `read` / `write` / `deny` だけを使う。
3. 編集後は直ちにセッションを1つ起動する（または config をロードする適当な
   最小 CLI コマンドを実行する）ことで、config がパースされることを確認
   する。まとめて編集して放置しないこと。
4. ブリックしてしまったら: バックアップを復元するか、直近の編集から無効
   トークンを探す — 観測したパースエラーは行を教えてくれませんでした。

参照（2026-07-23確認）: 公式の Permissions ドキュメント
https://learn.chatgpt.com/docs/permissions

## 症状 (e): workspace 外への書込みには3条件が要る

Windows では、`config.toml` の write 許可だけでは workspace（cwd）外の
パスへ書けるようになりません。次の3つがすべて成立している必要があります:

1. **Config**: 2方式を混ぜず、どちらか一方を選ぶ。permission profile
   方式では、`default_permissions` が選ぶ profile の
   `[permissions.<profile>.filesystem]` に
   `"<絶対パス>" = "write"` があり、ロード対象の config layer にも CLI
   `--sandbox` にも旧方式の選択がないこと。旧方式では
   `sandbox_mode = "workspace-write"` と
   `[sandbox_workspace_write].writable_roots` を使い、permission profile
   の grant と併用しないこと。
2. **OS ACL**: サンドボックスは専用のローカル・サンドボックスユーザー／
   グループとしてコマンドを実行します — workspace の ACL に
   `<HOST>\CodexSandboxUsers` のようなエントリが Modify 権限つきで見え、
   これは Codex が workspace には自動付与します。workspace 外のパスには
   このエントリが無いため、config が許可していても OS が書込みを拒否
   します。付与するには（リソースのオーナー承認を得た場合のみ — 共有
   リソースの ACL 変更です）:

   ```powershell
   icacls "<dir>" /grant "<HOST>\CodexSandboxUsers:(OI)(CI)M" /T
   ```

3. **Runner の健全性**: サンドボックスユーザーとしてのプロセス生成が実際に
   動くこと。症状 (a) が起きている間は、条件1・2が揃っていても書込みは
   spawn の段で失敗します。

独立した3条件がすべて成立し続ける必要があるため、Windows での workspace 外
直接書込みは脆い構成です。成果物は workspace 内に書いて後から回収する形を
優先し、外部パスへの許可は本当に必要な場合に限り、1つ1つの許可を可能な
かぎり狭く保ってください。

## 原則

- **何かに触る前に層を特定する。** Config ロード → setup helper →
  プロセス生成 → サンドボックス内 runtime。Win32 error 5 は3つの異なる層に
  現れます。場所を特定するのは失敗した API 名であって、番号ではありません。
- **逐次消去より決定的な二分法を選ぶ。** `codex sandbox` CLI vs エージェント
  経路は、backend・ACL・特権・モードを1コマンドで確定させます。上の worked
  example が存在するのは、その実験が走るまでもっともらしい説が生き残るから
  です。
- **最小権限へ向かって倒す。逆へ倒さない。** PowerShell fallback、コマンド
  単位のエスカレーション、狭い profile 権限、`:workspace` プリセット — を
  全域的な弱体化より先に。サンドボックス無効化（`danger-full-access`）は
  信頼済みローカル作業限定の一時回避であり、期限つきです: 次の版で再検証
  すること。
- **「full access なら動く」は診断でも修復でもない。** それは層 (a)(c) を
  直すのではなく迂回しているだけで、(c) では full access 下でも helper が
  同一の失敗をすることが観測済みです。
- **自分の所有物でないものを kill しない。** 他セッションのプロセス、共有
  runner、サンドボックスユーザーの logon セッションはそのままにする。stuck
  した runner は報告に記録し、判断は人間に委ねる。
- **回避策はバージョンにスコープする。** それぞれ観測した版を記録し、Codex
  が更新されたらまずサンドボックス経路を再検証して回避策を撤去する。期限
  切れのバイパスを放置することが、一時回避を恒久的な穴に変えます。
- **`config.toml` は本番設定のつもりで編集する。** まずバックアップ、値は
  正規トークンのみ、編集直後にロード確認 — 権限トークン1つの誤りがマシン上
  の全セッションをブリックします。

## Provenance（出自）

上のルールはすべて、Windows ホスト上の Codex CLI 0.142.5 世代ビルドでの
実測（2026年7月時点）に遡ります — 1件の誤診断とその訂正を含み、それは編集で
消さずに worked example として保存しています。「field-observed（実測）」の
表記は実際に踏んで切り抜けた挙動を指し、直接測定していないものは unverified
（未検証）と明記します。

これらの失敗の再現には「都合よく壊れた環境」が必要なため、このリポジトリの
CI は再現を試みません: CI が検証するのはドキュメント構造と private marker
のスキャンであり、収録コマンドは構文確認（PowerShell としてパースできる
こと）に留め、CI 再現済みではなく field-observed と表記しています。すべての
主張にバージョン番号を付けているのは意図的です: サンドボックス内部は変わる
ものであり、バグより長生きした回避策は負債になります。
