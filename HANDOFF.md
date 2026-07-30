# HANDOFF: codex-windows-sandbox-troubleshooting

最終確認: 2026-07-31 JST（Codex）。
公開する技術内容の正典は [SKILL.md](SKILL.md)、利用手順は [README.md](README.md)、変更記録は [CHANGELOG.md](CHANGELOG.md) とする。

## 現在地

- 2026-07-31のHANDOFF作成着手時点で、`main`、`origin/main`、remote `main` は基準commit `58138ccba47a754023e67fba4855ba2dfb9590c0` で一致し、tracked tree は cleanだった。再開時はlive値を再取得する。
- 公開repositoryのdefault branchは`main`。
- 2026-07-31観測時のopen issueは0件。
- 2026-07-31観測時、[PR #4](https://github.com/h8nc4y/codex-windows-sandbox-troubleshooting/pull/4) はopen、mergeable、`UNSTABLE`。
- PR #4の2026-07-31観測headは`8fb21d73ed79b722e655fd02162c84b0bccfc254`。
- 2026-07-31観測時の最新runではWindowsとUbuntuが成功し、macOS native jobが失敗した。
- PR #4は2026-07-31までの6つのhead revisionでmacOS jobが連続して失敗した。

## PR #4の失敗境界

- Validate run `30219646904` のmacOS jobはreadinessを通過した後、self-testのGit-backed fixture群が固定`scanner-boundary`へ閉じた。
- 専用のDarwin evidence成功行は、suite全体が失敗したため出力されていない。
- このrunだけではnative containmentの受け入れを完了扱いにできない。
- 既存branch `test/add-macos-native-posix-ci` とそのcheckoutはcleanであり、所有権を維持する。

## 現在の検証証跡

- 基準main `58138ccba47a754023e67fba4855ba2dfb9590c0` のValidate run `30147138999` はWindowsとUbuntuで成功した。
- 2026-07-31観測時のPR #4最新Validate run `30219646904` はWindowsとUbuntuが成功し、macOSが失敗した。
- このhandoff更新はPowerShell 7 / Windows PowerShell 5.1のOSS readiness、private-marker self-test、実private-marker scanをすべて通過した。Gitleaks directory scanも0件。
- 実環境のsandbox修復、ACL変更、secret、production data、deploy、費用操作は実施していない。

## 次の一手

PR #4へ変更を重ねる前に、macOSでGit-backed fixtureが固定`scanner-boundary`へ閉じる最初の原因をfocused reproductionで一つに絞る。
既存branchと既存checkoutを削除、rewrite、または別作業へ流用しない。
macOS jobが成功するまでPR #4をmergeしない。
