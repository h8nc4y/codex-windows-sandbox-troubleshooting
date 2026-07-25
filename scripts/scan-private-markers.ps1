# advanced script の共通parameter binderもscript bodyより前に失敗して
# absolute pathを出し得る。param block自体を持たず、全tokenをautomatic
# `$args` から取り込んで固定診断の内側だけで解釈する。
[object[]]$ScannerArguments = @($args)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Console.Out は host 所有のまま使い、finding payload の actual bytes を
# cap計算と同じBOM-less UTF-8へ固定する。
[Console]::OutputEncoding =
    New-Object System.Text.UTF8Encoding($false)

$Path = ''
$GitCommandTimeoutMilliseconds = 15000
$ScanDeadlineMilliseconds = 120000
$seenScannerArguments =
    [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
$invocationContractValid = $true
for ($argumentIndex = 0;
    $argumentIndex -lt @($ScannerArguments).Count;
    $argumentIndex += 2) {
    if ($argumentIndex + 1 -ge @($ScannerArguments).Count -or
        $ScannerArguments[$argumentIndex] -isnot [string]) {
        $invocationContractValid = $false
        break
    }
    $argumentNameText = [string]$ScannerArguments[$argumentIndex]
    if ($argumentNameText -notmatch '^-{1,2}(?<name>[A-Za-z][A-Za-z0-9-]*)$') {
        $invocationContractValid = $false
        break
    }
    $argumentName = $Matches['name']
    if (-not $seenScannerArguments.Add($argumentName)) {
        $invocationContractValid = $false
        break
    }
    $argumentValue = $ScannerArguments[$argumentIndex + 1]
    switch ($argumentName.ToLowerInvariant()) {
        'path' {
            if ($null -eq $argumentValue -or
                $argumentValue -isnot [string]) {
                $invocationContractValid = $false
            } else {
                $Path = [string]$argumentValue
            }
        }
        'gitcommandtimeoutmilliseconds' {
            $parsedGitTimeout = 0
            if ($null -eq $argumentValue -or
                -not [int]::TryParse(
                    [string]$argumentValue,
                    [System.Globalization.NumberStyles]::Integer,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [ref]$parsedGitTimeout
                ) -or
                $parsedGitTimeout -lt 250 -or
                $parsedGitTimeout -gt 15000) {
                $invocationContractValid = $false
            } else {
                $GitCommandTimeoutMilliseconds = $parsedGitTimeout
            }
        }
        'scandeadlinemilliseconds' {
            $parsedScanDeadline = 0
            if ($null -eq $argumentValue -or
                -not [int]::TryParse(
                    [string]$argumentValue,
                    [System.Globalization.NumberStyles]::Integer,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [ref]$parsedScanDeadline
                ) -or
                $parsedScanDeadline -lt 1 -or
                $parsedScanDeadline -gt 120000) {
                $invocationContractValid = $false
            } else {
                $ScanDeadlineMilliseconds = $parsedScanDeadline
            }
        }
        default {
            $invocationContractValid = $false
        }
    }
    if (-not $invocationContractValid) {
        break
    }
}
if (-not $invocationContractValid) {
    [Console]::Error.WriteLine(
        'Private marker scan failed closed (integrity: invocation-contract).'
    )
    exit 2
}

$maximumScanMilliseconds = $ScanDeadlineMilliseconds
$scanClock = [System.Diagnostics.Stopwatch]::StartNew()

try {
function Assert-PrivateMarkerScanDeadline {
    # Git child だけでなく、列挙・decode・regex・serialize・emit を同じ
    # monotonic clock に収め、CPU 側へ期限外処理を逃がさない。
    if ($scanClock.ElapsedMilliseconds -ge $maximumScanMilliseconds) {
        throw 'Private marker scan exceeded its scan-wide time budget.'
    }
}

function Stop-PrivateMarkerIntegrityFailure {
    param([string]$Reason)

    # raw path、Git stderr、環境値を出さず、固定 ASCII code だけを返す。
    Assert-PrivateMarkerScanDeadline
    [Console]::Error.WriteLine(
        "Private marker scan failed closed (integrity: $Reason)."
    )
    exit 2
}

function ConvertTo-PrivateMarkerDiagnosticText {
    param(
        [AllowNull()]
        [string]$Value,
        [int]$MaximumCodeUnits = 512
    )

    if ($null -eq $Value) {
        return '<null>'
    }

    # Terminal 制御・bidi 制御・Unicode 改行を必ず可視化し、
    # path や環境変数名から偽の診断行を作れないようにする。
    $builder = New-Object System.Text.StringBuilder
    $length = [Math]::Min($Value.Length, $MaximumCodeUnits)
    for ($index = 0; $index -lt $length; $index++) {
        $character = $Value[$index]
        $category = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory(
            $character
        )
        if ($category -in @(
            [System.Globalization.UnicodeCategory]::Control,
            [System.Globalization.UnicodeCategory]::Format,
            [System.Globalization.UnicodeCategory]::LineSeparator,
            [System.Globalization.UnicodeCategory]::ParagraphSeparator,
            [System.Globalization.UnicodeCategory]::Surrogate
        )) {
            [void]$builder.Append('\u')
            [void]$builder.Append(
                ([int]$character).ToString(
                    'X4',
                    [System.Globalization.CultureInfo]::InvariantCulture
                )
            )
        } else {
            [void]$builder.Append($character)
        }
    }
    if ($Value.Length -gt $MaximumCodeUnits) {
        [void]$builder.Append('...<truncated>')
    }
    return $builder.ToString()
}

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Split-Path -Parent $scriptRoot
}

try {
    $root = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
}
catch {
    # provider例外を再throwするとPowerShell自身のframingがscanner絶対pathを
    # stderrへ付加する。固定ASCII診断を一度だけ書き、host側例外化を避ける。
    Assert-PrivateMarkerScanDeadline
    [Console]::Error.WriteLine(
        'Private marker scan failed closed (integrity: scan-root-missing).'
    )
    exit 2
}
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw 'Private marker scan path must be a directory.'
}
$processBoundary = Join-Path $scriptRoot 'private-marker-process.ps1'
if (-not (Test-Path -LiteralPath $processBoundary -PathType Leaf)) {
    $safeProcessBoundary = ConvertTo-PrivateMarkerDiagnosticText $processBoundary
    throw "Missing process boundary script: $safeProcessBoundary"
}
. $processBoundary

# この repository 自身と、sandbox issue の一次情報として参照する
# openai/codex だけを許可する。032 由来の別 skill allowlist は持ち込まない。
$allowedRepoUrlPattern = '^https://github\.com/(?:h8nc4y/codex-windows-sandbox-troubleshooting(?:\.git)?|openai/codex)$'

$maximumScanRules = 256
$maximumRulePatternCharacters = 4096
$rules = New-Object System.Collections.Generic.List[object]

function Add-ScanRule {
    param(
        [string]$Name,
        [string]$Pattern,
        [ValidateSet('literal', 'regex')]
        [string]$Kind,
        # Optional: suppress regex matches whose value is a known-safe placeholder.
        # This keeps documentation examples from becoming noisy findings.
        [string]$Allowlist = ''
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) {
        return
    }
    if ($Pattern.Length -gt $maximumRulePatternCharacters) {
        throw 'Private marker rule exceeded its pattern-length limit.'
    }
    if ($rules.Count -ge $maximumScanRules) {
        throw 'Private marker scan exceeded its rule-count limit.'
    }

    $rules.Add([pscustomobject]@{
        Name = $Name
        Pattern = $Pattern
        Kind = $Kind
        Allowlist = $Allowlist
        Matcher = if ($Kind -eq 'regex') {
            [regex]::new(
                $Pattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
            )
        } else {
            $null
        }
        AllowlistMatcher = if ([string]::IsNullOrEmpty($Allowlist)) {
            $null
        } else {
            [regex]::new(
                $Allowlist,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
            )
        }
    }) | Out-Null
}

Add-ScanRule -Name 'openai-api-key-prefix' -Pattern '(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}' -Kind 'regex'
Add-ScanRule -Name 'github-classic-token-prefix' -Pattern ('g' + 'hp_') -Kind 'literal'
Add-ScanRule -Name 'github-fine-grained-token-prefix' -Pattern ('github' + '_pat_') -Kind 'literal'
Add-ScanRule -Name 'slack-bot-token-prefix' -Pattern ('xo' + 'xb-') -Kind 'literal'
Add-ScanRule -Name 'bearer-token-header' -Pattern ('Bearer' + ' ') -Kind 'literal'
Add-ScanRule -Name 'private-key-block' -Pattern ('BEGIN ' + 'PRIVATE KEY') -Kind 'literal'
Add-ScanRule -Name 'email-address' -Pattern '\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b' -Kind 'regex'
# windows-absolute-path detects private-looking absolute Windows paths while allowing
# documented placeholders. The regex stops before bracketed placeholder segments and
# can also greedily include trailing prose, so the allowlist suppresses either:
#   (a) values ending at a path separator with only placeholder or parent words,
#   (b) full placeholder-only paths, with optional trailing prose, or
#   (c) this skill が説明する既知の system install location.
# Real-looking paths with non-placeholder child segments remain findings.
# Keep literal absolute paths out of comments so this script does not flag itself.
$winPathPlaceholderWord = '(?:path|to|repo|you|your|example|placeholder|dir|folder|project|projects)'
$winPathParentWord = '(?:users|user|home|documents|appdata|local|roaming)'
$winPathSystemLocation = '(?:program[ ]files\\git|windows\\system32)'
$windowsPathPlaceholderAllowlist = '(?ix)^[A-Za-z]:\\(?:' +
    # (a) Placeholder or parent words only, ending at a separator.
    "(?:(?:$winPathPlaceholderWord|$winPathParentWord)\\)+" +
    '|' +
    # (b) Full placeholder-only paths, optionally followed by prose.
    "(?:$winPathPlaceholderWord\\?)+(?:\s.*)?" +
    '|' +
    # (c) Git for Windows と System32 WSL shim の文書化済み path.
    "$winPathSystemLocation\\.*" +
    ')$'
Add-ScanRule -Name 'windows-absolute-path' -Pattern '\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\?){2,}' -Kind 'regex' -Allowlist $windowsPathPlaceholderAllowlist

# Additional cloud / key-block prefixes for higher secret recall.
# Prefixes are split so this scanner does not match its own rule definitions.
Add-ScanRule -Name 'aws-access-key-id' -Pattern ('A' + 'KIA') -Kind 'literal'
Add-ScanRule -Name 'gcp-api-key-prefix' -Pattern ('AIza' + '[0-9A-Za-z_\-]{35}') -Kind 'regex'
Add-ScanRule -Name 'slack-user-token-prefix' -Pattern ('xo' + 'xp-') -Kind 'literal'
Add-ScanRule -Name 'slack-legacy-app-token-prefix' -Pattern ('xo' + 'xa-') -Kind 'literal'
Add-ScanRule -Name 'slack-app-level-token-prefix' -Pattern ('xa' + 'pp-') -Kind 'literal'
Add-ScanRule -Name 'stripe-live-secret-key' -Pattern ('(s' + 'k|rk)_live_[0-9A-Za-z]{16,}') -Kind 'regex'
Add-ScanRule -Name 'pem-private-key-block' -Pattern ('BEGIN ' + '(RSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY') -Kind 'regex'

$localMarkerIndex = 0

function Add-LocalMarker {
    param([string]$Marker)

    $trimmed = $Marker.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
        return
    }
    if ($trimmed.Length -gt $maximumRulePatternCharacters) {
        throw 'Local private marker exceeded its length limit.'
    }

    $script:localMarkerIndex++
    Add-ScanRule -Name "local-private-marker-$script:localMarkerIndex" -Pattern $trimmed -Kind 'literal'
}

$localMarkerFile = Join-Path $root '.private-markers.local'

$githubUrlPattern = 'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?'
$githubUrlMatcher = [regex]::new(
    $githubUrlPattern,
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
$allowedRepoUrlMatcher = [regex]::new(
    $allowedRepoUrlPattern,
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
$findings = New-Object System.Collections.Generic.List[object]

# Binary noiseを避けつつ、secretを含みやすい拡張子と名前を明示的に含める。
# Extensionless と high-signal dotfile（.npmrc等）も text candidate に含める。
$textExtensions = @(
    '.md', '.markdown', '.txt', '.ps1', '.psm1', '.psd1', '.yml', '.yaml',
    '.json', '.jsonc', '.toml', '.ini', '.cfg', '.conf', '.xml', '.csv',
    '.sh', '.bash', '.bat', '.cmd', '.py', '.js', '.ts', '.css', '.html',
    '.htm', '.editorconfig', '.gitattributes', '.gitignore', '.env', '.pem',
    '.key'
)
$textExtensionSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$textExtensions, [System.StringComparer]::OrdinalIgnoreCase)
$textFileNameSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        '.env',
        '.npmrc',
        '.yarnrc',
        '.netrc',
        '.pypirc',
        '.git-credentials'
    ),
    [System.StringComparer]::OrdinalIgnoreCase
)

function Test-IsTextFile {
    param([string]$FullPath)

    $fileName = [System.IO.Path]::GetFileName($FullPath)
    if ($textFileNameSet.Contains($fileName) -or
        $fileName.StartsWith('.env.', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $extension = [System.IO.Path]::GetExtension($FullPath)
    if ([string]::IsNullOrEmpty($extension)) {
        # Treat extensionless files as text.
        return $true
    }
    return $textExtensionSet.Contains($extension)
}

function Get-ProcessEnvironmentSnapshot {
    $snapshot = @{}
    $environment = [Environment]::GetEnvironmentVariables('Process')
    foreach ($name in $environment.Keys) {
        $snapshot["$name"] = [string]$environment[$name]
    }
    return $snapshot
}

function Get-ChangedEnvironmentVariableNames {
    param([hashtable]$Expected)

    $actual = Get-ProcessEnvironmentSnapshot
    $differentNames = New-Object System.Collections.Generic.List[string]
    foreach ($name in @($Expected.Keys + $actual.Keys) | Sort-Object -Unique) {
        if ($Expected.ContainsKey($name) -ne $actual.ContainsKey($name) -or
            ($Expected.ContainsKey($name) -and $Expected[$name] -cne $actual[$name])) {
            # 秘密値を出力しない。境界違反の診断に必要な変数名だけを保持する。
            $differentNames.Add(
                (ConvertTo-PrivateMarkerDiagnosticText "$name")
            ) | Out-Null
        }
    }
    return @($differentNames)
}

$maximumTrackedEntries = 10000
$maximumTextBytes = 5MB
$maximumTotalTextBytes = 50MB
$maximumGitListBytes = 8MB
$maximumGitDebugBytes = $maximumGitListBytes + ($maximumTrackedEntries * 192)
$maximumLineCharacters = 1MB
$maximumLinesPerTarget = 100000
$maximumTotalScannedLines = 500000
$maximumMatchesPerRulePerLine = 256
$maximumFindingsPerFile = 64
$maximumTotalFindings = 512
$maximumFindingOutputBytes = 64KB
$totalTextBytes = 0L
$totalScannedLines = 0L
$scanTargets = New-Object System.Collections.Generic.List[object]
$findingCountByFile = [System.Collections.Generic.Dictionary[string, int]]::new(
    [System.StringComparer]::Ordinal
)
try {
    $fullRoot = [System.IO.Path]::GetFullPath($root)
    $rootAnchor = [System.IO.Path]::GetPathRoot($fullRoot)
    $trimmedRoot = $fullRoot.TrimEnd([char]92, [char]47)
    # drive root / POSIX root の末尾separatorはroot identityそのもの。
    # current-directory semanticsへ崩さないため、anchorを保持する。
    $canonicalRoot = if ([string]::IsNullOrEmpty($trimmedRoot) -or
        $trimmedRoot -match '^[A-Za-z]:$') {
        $rootAnchor
    } else {
        $trimmedRoot
    }
}
catch {
    throw 'Private marker scan root could not be canonicalized.'
}
$rootPrefix = if ($canonicalRoot.EndsWith(
        [string][System.IO.Path]::DirectorySeparatorChar
    ) -or
    $canonicalRoot.EndsWith(
        [string][System.IO.Path]::AltDirectorySeparatorChar
    )) {
    $canonicalRoot
} else {
    $canonicalRoot + [System.IO.Path]::DirectorySeparatorChar
}
$pathComparison = if (Test-PrivateMarkerWindowsHost) {
    [StringComparison]::OrdinalIgnoreCase
} else {
    [StringComparison]::Ordinal
}
$gitIndexArguments = @(
    '-C',
    $canonicalRoot,
    '-c',
    'core.quotepath=false',
    'ls-files',
    '-z',
    '--stage',
    '--'
)
$gitIndexDebugArguments = @(
    '-C',
    $canonicalRoot,
    '-c',
    'core.quotepath=false',
    'ls-files',
    '-z',
    '--stage',
    '--debug',
    '--'
)

function Add-BoundedFinding {
    param(
        [string]$File,
        [string]$Source,
        [int]$Line,
        [string]$Rule
    )

    Assert-PrivateMarkerScanDeadline
    $safeFile = ConvertTo-PrivateMarkerDiagnosticText $File
    $safeSource = ConvertTo-PrivateMarkerDiagnosticText $Source
    $safeRule = ConvertTo-PrivateMarkerDiagnosticText $Rule
    $fileFindingCount = 0
    [void]$findingCountByFile.TryGetValue($safeFile, [ref]$fileFindingCount)
    if ($fileFindingCount -ge $maximumFindingsPerFile) {
        throw "Private marker scan exceeded the per-file finding limit: $safeFile."
    }
    if ($findings.Count -ge $maximumTotalFindings) {
        throw 'Private marker scan exceeded its total finding limit.'
    }

    $findingCountByFile[$safeFile] = $fileFindingCount + 1
    $findings.Add([pscustomobject]@{
        File = $safeFile
        Source = $safeSource
        Line = $Line
        Rule = $safeRule
        Match = '<redacted>'
    }) | Out-Null
}

function Invoke-BoundedLineAction {
    param(
        [string]$Content,
        [string]$Context,
        [scriptblock]$Action
    )

    # Regex.Split / -split は行数に比例する配列を複製するため使わない。
    # 1行ずつ bounded substring を渡し、行長・file行数・全体行数を独立に制限する。
    $offset = 0
    $lineNumber = 1
    while ($true) {
        Assert-PrivateMarkerScanDeadline
        if ($lineNumber -gt $maximumLinesPerTarget) {
            throw "Text scan target exceeded its line-count limit: $Context."
        }
        $script:totalScannedLines++
        if ($script:totalScannedLines -gt $maximumTotalScannedLines) {
            throw 'Private marker scan exceeded its total line-count limit.'
        }

        $carriageReturnIndex = $Content.IndexOf([char]13, $offset)
        $lineFeedIndex = $Content.IndexOf([char]10, $offset)
        if ($carriageReturnIndex -lt 0) {
            $lineEnd = $lineFeedIndex
        } elseif ($lineFeedIndex -lt 0) {
            $lineEnd = $carriageReturnIndex
        } else {
            $lineEnd = [Math]::Min($carriageReturnIndex, $lineFeedIndex)
        }

        if ($lineEnd -lt 0) {
            $lineLength = $Content.Length - $offset
        } else {
            $lineLength = $lineEnd - $offset
        }
        if ($lineLength -gt $maximumLineCharacters) {
            throw "Text scan target contains an overlong line: $Context."
        }

        $line = $Content.Substring($offset, $lineLength)
        & $Action $line $lineNumber
        if ($lineEnd -lt 0) {
            break
        }

        $offset = $lineEnd + 1
        if ($Content[$lineEnd] -eq [char]13 -and
            $offset -lt $Content.Length -and
            $Content[$offset] -eq [char]10) {
            $offset++
        }
        if ($offset -ge $Content.Length) {
            break
        }
        $lineNumber++
    }
}

function Get-RemainingGitTimeoutMilliseconds {
    Assert-PrivateMarkerScanDeadline
    $remaining = $maximumScanMilliseconds - [int]$scanClock.ElapsedMilliseconds
    if ($remaining -le 0) {
        throw 'Private marker scan exceeded its overall Git time budget.'
    }
    return [Math]::Min($GitCommandTimeoutMilliseconds, $remaining)
}

function Invoke-ScannerGit {
    param(
        [string[]]$Arguments,
        [int]$MaximumStandardOutputBytes,
        [byte[]]$StandardInputBytes = $null
    )

    try {
        return Invoke-PrivateMarkerProcess `
            -FileName $gitExe.Source `
            -Arguments $Arguments `
            -StandardInputBytes $StandardInputBytes `
            -WorkingDirectory $canonicalRoot `
            -SanitizeGitEnvironment `
            -IsolationRoot $gitIsolationRoot `
            -TimeoutMilliseconds (Get-RemainingGitTimeoutMilliseconds) `
            -MaximumStandardOutputBytes $MaximumStandardOutputBytes
    }
    catch {
        # provider/native例外が raw root path を含んでも外へ流さない。
        throw 'Git process boundary failed before returning a bounded result.'
    }
}

function Assert-HealthyGitBoundary {
    param(
        [pscustomobject]$Result,
        [string]$Context,
        [switch]$AllowNonzeroExit
    )

    if ($Result.TimedOut -or
        $Result.OutputLimitExceeded -or
        $Result.InputWriteFailed -or
        $Result.PipeLeakDetected -or
        -not $Result.StreamsCompleted -or
        -not $Result.TreeStopped) {
        throw "$Context did not complete inside the bounded process boundary."
    }
    if (-not $AllowNonzeroExit -and $Result.ExitCode -ne 0) {
        throw "$Context failed with exit code $($Result.ExitCode)."
    }
}

function Assert-GitIndexSnapshotsUnchanged {
    # raw stage listingだけではflags-only変化を表せないため、通常 listing と
    # --debug metadataを必ず同じphaseで開始snapshotへ照合する。
    $indexSnapshotProbe = Invoke-ScannerGit `
        -Arguments $gitIndexArguments `
        -MaximumStandardOutputBytes $maximumGitListBytes
    Assert-HealthyGitBoundary `
        -Result $indexSnapshotProbe `
        -Context 'Git index verification'
    if (-not (Test-ByteArraysEqual `
            -Left $initialGitIndexBytes `
            -Right $indexSnapshotProbe.StandardOutputBytes)) {
        throw 'Git index changed during the private marker scan.'
    }

    $indexDebugSnapshotProbe = Invoke-ScannerGit `
        -Arguments $gitIndexDebugArguments `
        -MaximumStandardOutputBytes $maximumGitDebugBytes
    Assert-HealthyGitBoundary `
        -Result $indexDebugSnapshotProbe `
        -Context 'Git index metadata verification'
    if (-not (Test-ByteArraysEqual `
            -Left $initialGitIndexDebugBytes `
            -Right $indexDebugSnapshotProbe.StandardOutputBytes)) {
        throw 'Git index metadata changed during the private marker scan.'
    }
}

function Test-GitMarkerInAncestry {
    $directory = New-Object System.IO.DirectoryInfo($canonicalRoot)
    $nameComparison = if (Test-PrivateMarkerWindowsHost) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    while ($null -ne $directory) {
        Assert-PrivateMarkerScanDeadline
        # Marker 自体を直接解決すると dangling symlink / junction を「存在しない」と誤認し得る。
        # 親 directory を非再帰で列挙し、reparse target を辿らず entry 名だけを確認する。
        try {
            $ancestryEntries = @(
                Get-ChildItem `
                    -LiteralPath $directory.FullName `
                    -Force `
                    -Filter '.git' `
                    -ErrorAction Stop |
                    Select-Object -First 2
            )
        }
        catch {
            throw 'Private marker scan could not inspect the .git ancestry.'
        }
        foreach ($entry in $ancestryEntries) {
            if ([string]::Equals($entry.Name, '.git', $nameComparison)) {
                return $true
            }
        }
        $directory = $directory.Parent
    }
    return $false
}

function Get-PrivateMarkerLocalLeaf {
    # leafを直接Test-Path/Get-Itemすると、dangling linkはtarget解決後に
    # 「不存在」と見える。rootを非再帰で列挙し、entry自体を追跡する。
    try {
        $localMarkerEntries = @(
            Get-ChildItem `
                -LiteralPath $canonicalRoot `
                -Force `
                -Filter '.private-markers.local' `
                -ErrorAction Stop |
                Where-Object {
                    [string]::Equals(
                        $_.Name,
                        '.private-markers.local',
                        $pathComparison
                    )
                } |
                Select-Object -First 2
        )
    }
    catch {
        throw 'Local private marker parent could not be inspected safely.'
    }
    if ($localMarkerEntries.Count -gt 1) {
        throw 'Local private marker path was ambiguous.'
    }
    if ($localMarkerEntries.Count -eq 0) {
        return $null
    }
    return $localMarkerEntries[0]
}

function Test-ByteArraysEqual {
    param(
        [byte[]]$Left,
        [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function Test-SafeWorktreeParentChain {
    param([string]$RelativePath)

    $safeRelativePath = ConvertTo-PrivateMarkerDiagnosticText $RelativePath
    # Root 自体と leaf までの全 parent を確認し、途中の junction / symlink 経由で
    # explicit scan root 外の worktree content を読まない。
    try {
        $rootItem = Get-Item `
            -LiteralPath $canonicalRoot `
            -Force `
            -ErrorAction Stop
    }
    catch {
        throw 'Explicit scan root could not be inspected safely.'
    }
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Explicit scan root must not be a symlink or reparse point.'
    }
    if (-not $rootItem.PSIsContainer) {
        throw 'Explicit scan root must remain a directory.'
    }

    $components = @($RelativePath -split '/')
    $currentPath = $canonicalRoot
    for ($componentIndex = 0; $componentIndex -lt $components.Count - 1; $componentIndex++) {
        Assert-PrivateMarkerScanDeadline
        $currentPath = Join-Path $currentPath $components[$componentIndex]
        try {
            $parentItem = Get-Item `
                -LiteralPath $currentPath `
                -Force `
                -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            # Parent ごと消えた tracked file は worktree content が無いため index のみ検査する。
            return $false
        }
        catch {
            throw "Tracked worktree parent path could not be inspected: $safeRelativePath."
        }
        if (($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Tracked worktree parent directory is a symlink or reparse point: $safeRelativePath."
        }
        if (-not $parentItem.PSIsContainer) {
            throw "Tracked worktree parent path is not a directory: $safeRelativePath."
        }
    }
    return $true
}

function Add-TextTarget {
    param(
        [string]$RelativePath,
        [string]$Source,
        [byte[]]$Bytes
    )

    $safeRelativePath = ConvertTo-PrivateMarkerDiagnosticText $RelativePath
    $safeSource = ConvertTo-PrivateMarkerDiagnosticText $Source
    if ($Bytes.Length -gt $maximumTextBytes) {
        throw "Text scan target exceeds the per-file byte limit: $safeRelativePath ($safeSource)."
    }
    $script:totalTextBytes += $Bytes.Length
    if ($script:totalTextBytes -gt $maximumTotalTextBytes) {
        throw 'Private marker scan exceeded its total text byte limit.'
    }
    if ([Array]::IndexOf($Bytes, [byte]0) -ge 0) {
        throw "Text scan target contains a NUL byte: $safeRelativePath ($safeSource)."
    }
    $content = ConvertFrom-PrivateMarkerUtf8Bytes `
        -Bytes $Bytes `
        -Context "$safeRelativePath ($safeSource)"
    $scanTargets.Add([pscustomobject]@{
        File = $safeRelativePath
        Source = $safeSource
        Content = $content
    }) | Out-Null
}

function Read-StableWorktreeBytes {
    param(
        [string]$FullPath,
        [string]$RelativePath
    )

    $safeRelativePath = ConvertTo-PrivateMarkerDiagnosticText $RelativePath
    if (-not (Test-SafeWorktreeParentChain -RelativePath $RelativePath)) {
        throw "Tracked worktree parent path disappeared before bounded read: $safeRelativePath."
    }
    try {
        $itemBefore = Get-Item `
            -LiteralPath $FullPath `
            -Force `
            -ErrorAction Stop
    }
    catch {
        throw "Tracked worktree path could not be inspected: $safeRelativePath."
    }
    if (($itemBefore.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Tracked worktree path is a symlink or reparse point: $safeRelativePath."
    }
    if ($itemBefore.PSIsContainer) {
        throw "Tracked worktree path is not a regular file: $safeRelativePath."
    }
    if ($itemBefore.Length -gt $maximumTextBytes) {
        throw "Tracked worktree file exceeds the per-file byte limit: $safeRelativePath."
    }

    try {
        $stream = New-Object System.IO.FileStream(
            $FullPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
    }
    catch {
        throw "Tracked worktree file could not be opened: $safeRelativePath."
    }
    try {
        if ($stream.Length -gt $maximumTextBytes) {
            throw "Tracked worktree file grew beyond the per-file byte limit: $safeRelativePath."
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            Assert-PrivateMarkerScanDeadline
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "Tracked worktree file ended during bounded read: $safeRelativePath."
            }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) {
            throw "Tracked worktree file changed during bounded read: $safeRelativePath."
        }

        # Handle を保持したまま path chain と leaf を再確認し、読取り直後の差替え窓を閉じる。
        if (-not (Test-SafeWorktreeParentChain -RelativePath $RelativePath)) {
            throw "Tracked worktree parent path changed while it was scanned: $safeRelativePath."
        }
        try {
            $itemAfter = Get-Item `
                -LiteralPath $FullPath `
                -Force `
                -ErrorAction Stop
        }
        catch {
            throw "Tracked worktree path disappeared after bounded read: $safeRelativePath."
        }
        if (($itemAfter.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $itemAfter.PSIsContainer -or
            $itemAfter.Length -ne $itemBefore.Length -or
            $itemAfter.LastWriteTimeUtc.Ticks -ne $itemBefore.LastWriteTimeUtc.Ticks) {
            throw "Tracked worktree file changed while it was scanned: $safeRelativePath."
        }
    }
    finally {
        $stream.Dispose()
    }
    return ,$bytes
}

function Get-SafeFallbackFiles {
    $files = New-Object System.Collections.Generic.List[object]
    $pending = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    try {
        $fallbackRoot = Get-Item `
            -LiteralPath $canonicalRoot `
            -Force `
            -ErrorAction Stop
    }
    catch {
        throw 'Working-tree fallback root could not be inspected safely.'
    }
    $pending.Push($fallbackRoot)
    $visitedEntries = 0
    while ($pending.Count -gt 0) {
        Assert-PrivateMarkerScanDeadline
        $directory = $pending.Pop()
        try {
            $remainingEntryCapacity =
                ($maximumTrackedEntries - $visitedEntries) + 1
            $directoryEntries = @(
                Get-ChildItem `
                    -LiteralPath $directory.FullName `
                    -Force `
                    -ErrorAction Stop |
                    Select-Object -First $remainingEntryCapacity
            )
        }
        catch {
            throw 'Working-tree fallback could not enumerate a directory safely.'
        }
        foreach ($item in $directoryEntries) {
            Assert-PrivateMarkerScanDeadline
            $visitedEntries++
            if ($visitedEntries -gt $maximumTrackedEntries) {
                throw 'Working-tree fallback exceeded its entry limit.'
            }
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Working-tree fallback encountered a symlink or reparse point.'
            }
            # `.git` は directory だけでなく gitfile 形式の leaf も列挙対象外にする。
            if ([string]::Equals($item.Name, '.git', $pathComparison)) {
                continue
            }
            if ($item.PSIsContainer) {
                if ($item.Name -notin @('node_modules', '.cache')) {
                    $pending.Push($item)
                }
                continue
            }
            if ($item.Name -ne '.private-markers.local' -and
                (Test-IsTextFile $item.FullName)) {
                $files.Add($item) | Out-Null
            }
        }
    }
    return $files.ToArray()
}

# Empty directory でも root reparse を見逃さないよう、列挙や local marker 読取りより先に固定する。
[void](Test-SafeWorktreeParentChain -RelativePath '.')

$localMarkerItem = Get-PrivateMarkerLocalLeaf
$hasLocalMarker = $null -ne $localMarkerItem
if ($hasLocalMarker) {
    if (($localMarkerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $localMarkerItem.PSIsContainer) {
        throw 'Local private marker file must be a regular local file.'
    }
    $localMarkerBytes = Read-StableWorktreeBytes `
        -FullPath $localMarkerFile `
        -RelativePath '.private-markers.local'
    $localMarkerText = ConvertFrom-PrivateMarkerUtf8Bytes `
        -Bytes $localMarkerBytes `
        -Context '.private-markers.local'
    Invoke-BoundedLineAction `
        -Content $localMarkerText `
        -Context '.private-markers.local' `
        -Action {
            param($line, $lineNumber)
            Add-LocalMarker -Marker $line
        }
}
$environmentMarkers = [Environment]::GetEnvironmentVariable(
    'CODEX_WINDOWS_SANDBOX_TROUBLESHOOTING_PRIVATE_MARKERS'
)
if (-not [string]::IsNullOrWhiteSpace($environmentMarkers)) {
    Invoke-BoundedLineAction `
        -Content $environmentMarkers `
        -Context 'CODEX_WINDOWS_SANDBOX_TROUBLESHOOTING_PRIVATE_MARKERS' `
        -Action {
            param($line, $lineNumber)
            Add-LocalMarker -Marker $line
        }
}

$verifyGitIndexAtScanEnd = $false
$initialGitIndexBytes = $null
$initialGitIndexDebugBytes = $null
$gitExe = @(
    Get-Command git `
        -CommandType Application `
        -ErrorAction SilentlyContinue
) | Select-Object -First 1
if ($null -eq $gitExe) {
    if (Test-GitMarkerInAncestry) {
        Stop-PrivateMarkerIntegrityFailure -Reason 'git-probe'
    }
    $scanMode = 'working-tree'
    foreach ($file in Get-SafeFallbackFiles) {
        $relative = $file.FullName.Substring($canonicalRoot.Length)
        $relative = $relative.TrimStart([char]92, [char]47)
        $relative = $relative.Replace([string][char]92, '/')
        Add-TextTarget `
            -RelativePath $relative `
            -Source 'working-tree' `
            -Bytes (Read-StableWorktreeBytes -FullPath $file.FullName -RelativePath $relative)
    }
} else {
    $environmentBeforeGit = Get-ProcessEnvironmentSnapshot
    $changedEnvironmentNames = @()
    $gitIsolationRoot = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) ("codex-windows-sandbox-troubleshooting-git-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $gitIsolationRoot | Out-Null
    try {
        $rootProbe = Invoke-ScannerGit `
            -Arguments @('-C', $canonicalRoot, 'rev-parse', '--show-toplevel') `
            -MaximumStandardOutputBytes 65536
        Assert-HealthyGitBoundary `
            -Result $rootProbe `
            -Context 'Git root probe' `
            -AllowNonzeroExit

        if ($rootProbe.ExitCode -ne 0) {
            $rootError = ConvertFrom-PrivateMarkerUtf8Bytes `
                -Bytes $rootProbe.StandardErrorBytes `
                -Context 'Git root probe stderr'
            $hasGitMarkerInAncestry = Test-GitMarkerInAncestry
            if ($hasGitMarkerInAncestry) {
                Stop-PrivateMarkerIntegrityFailure -Reason 'git-probe'
            }
            $explicitNotRepository = $rootProbe.ExitCode -eq 128 -and
                $rootError -match '(?m)^fatal: not a git repository\b'
            if (-not $explicitNotRepository) {
                throw "Git root probe failed closed with exit code $($rootProbe.ExitCode)."
            }

            $scanMode = 'working-tree'
            foreach ($file in Get-SafeFallbackFiles) {
                $relative = $file.FullName.Substring($canonicalRoot.Length)
                $relative = $relative.TrimStart([char]92, [char]47)
                $relative = $relative.Replace([string][char]92, '/')
                Add-TextTarget `
                    -RelativePath $relative `
                    -Source 'working-tree' `
                    -Bytes (Read-StableWorktreeBytes -FullPath $file.FullName -RelativePath $relative)
            }
        } else {
            $reportedRootText = ConvertFrom-PrivateMarkerUtf8Bytes `
                -Bytes $rootProbe.StandardOutputBytes `
                -Context 'Git root probe stdout'
            $reportedRootLines = @(
                $reportedRootText -split '\r?\n' |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
            if ($reportedRootLines.Count -ne 1) {
                throw 'Git root probe returned malformed output.'
            }
            try {
                $reportedRoot = [System.IO.Path]::GetFullPath(
                    $reportedRootLines[0]
                ).TrimEnd([char]92, [char]47)
            }
            catch {
                throw 'Git root probe returned an invalid path.'
            }
            if (-not [string]::Equals(
                $canonicalRoot,
                $reportedRoot,
                $pathComparison
            )) {
                throw 'Scan path must be the exact Git worktree root; subdirectories are rejected.'
            }

            $indexProbe = Invoke-ScannerGit `
                -Arguments $gitIndexArguments `
                -MaximumStandardOutputBytes $maximumGitListBytes
            Assert-HealthyGitBoundary -Result $indexProbe -Context 'Git index enumeration'
            $indexText = ConvertFrom-PrivateMarkerUtf8Bytes `
                -Bytes $indexProbe.StandardOutputBytes `
                -Context 'Git index enumeration'
            if ($indexText.Length -gt 0 -and -not $indexText.EndsWith("`0")) {
                throw 'Git index enumeration returned an unterminated record.'
            }

            # ls-files --stage は intent-to-add を empty blob として表示するため、
            # worktree 対 index の raw 差分も厳密に解析して zero-stage entry を拒否する。
            $rawDiffProbe = Invoke-ScannerGit `
                -Arguments @(
                    '-C',
                    $canonicalRoot,
                    'diff',
                    '--raw',
                    '-z',
                    '--no-abbrev',
                    '--no-ext-diff',
                    '--no-textconv',
                    '--'
                ) `
                -MaximumStandardOutputBytes $maximumGitListBytes
            Assert-HealthyGitBoundary -Result $rawDiffProbe -Context 'Git worktree/index diff'
            $rawDiffText = ConvertFrom-PrivateMarkerUtf8Bytes `
                -Bytes $rawDiffProbe.StandardOutputBytes `
                -Context 'Git worktree/index diff'
            if ($rawDiffText.Length -gt 0 -and -not $rawDiffText.EndsWith("`0")) {
                throw 'Git worktree/index diff returned an unterminated record.'
            }
            $rawDiffParts = @(
                if ($rawDiffText.Length -gt 0) {
                    $rawDiffText.Substring(0, $rawDiffText.Length - 1) -split "`0"
                }
            )
            $rawIndex = 0
            while ($rawIndex -lt $rawDiffParts.Count) {
                $header = [regex]::Match(
                    $rawDiffParts[$rawIndex],
                    '^:(?<oldMode>[0-9]{6}) (?<newMode>[0-9]{6}) (?<oldOid>[0-9a-f]{40}|[0-9a-f]{64}) (?<newOid>[0-9a-f]{40}|[0-9a-f]{64}) (?<status>[A-Z])(?<score>[0-9]{0,3})$'
                )
                if (-not $header.Success) {
                    throw 'Git worktree/index diff returned a malformed header.'
                }
                $rawIndex++
                $pathCount = if ($header.Groups['status'].Value -in @('R', 'C')) {
                    2
                } else {
                    1
                }
                if ($rawIndex + $pathCount -gt $rawDiffParts.Count) {
                    throw 'Git worktree/index diff omitted a path record.'
                }
                for ($pathIndex = 0; $pathIndex -lt $pathCount; $pathIndex++) {
                    if ([string]::IsNullOrEmpty($rawDiffParts[$rawIndex + $pathIndex])) {
                        throw 'Git worktree/index diff returned an empty path.'
                    }
                }
                if ($header.Groups['oldMode'].Value -eq '000000' -and
                    $header.Groups['status'].Value -eq 'A') {
                    throw 'Git index contains an intent-to-add entry.'
                }
                $rawIndex += $pathCount
            }

            $records = @(
                if ($indexText.Length -gt 0) {
                    $indexText.Substring(0, $indexText.Length - 1) -split "`0"
                }
            )
            if ($records.Count -gt $maximumTrackedEntries) {
                throw 'Git index enumeration exceeded its entry limit.'
            }

            # `ls-files --stage` のOIDだけでは、通常のempty blobと
            # CE_INTENT_TO_ADD付きempty blobを区別できない。debug streamの
            # header順序をstage列挙と照合し、extended flagを直接検査する。
            $indexDebugProbe = Invoke-ScannerGit `
                -Arguments $gitIndexDebugArguments `
                -MaximumStandardOutputBytes $maximumGitDebugBytes
            Assert-HealthyGitBoundary `
                -Result $indexDebugProbe `
                -Context 'Git index metadata enumeration'
            $indexDebugText = ConvertFrom-PrivateMarkerUtf8Bytes `
                -Bytes $indexDebugProbe.StandardOutputBytes `
                -Context 'Git index metadata enumeration'
            $debugBlockPattern = [regex]::new(
                '\G  ctime: [0-9]{1,20}:[0-9]{1,10}\n' +
                '  mtime: [0-9]{1,20}:[0-9]{1,10}\n' +
                '  dev: [0-9]{1,20}\tino: [0-9]{1,20}\n' +
                '  uid: [0-9]{1,20}\tgid: [0-9]{1,20}\n' +
                '  size: [0-9]{1,20}\tflags: (?<flags>[0-9a-fA-F]{1,16})\n',
                [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
            )
            $debugOffset = 0
            foreach ($record in $records) {
                Assert-PrivateMarkerScanDeadline
                $expectedPrefix = "$record`0"
                if (($debugOffset + $expectedPrefix.Length) -gt
                        $indexDebugText.Length -or
                    [string]::CompareOrdinal(
                        $indexDebugText,
                        $debugOffset,
                        $expectedPrefix,
                        0,
                        $expectedPrefix.Length
                    ) -ne 0) {
                    throw 'Git index metadata did not match the staged entry order.'
                }
                $debugOffset += $expectedPrefix.Length
                $debugMatch = $debugBlockPattern.Match(
                    $indexDebugText,
                    $debugOffset
                )
                if (-not $debugMatch.Success) {
                    throw 'Git index metadata returned a malformed debug block.'
                }
                $debugFlags = [uint64]0
                if (-not [uint64]::TryParse(
                    $debugMatch.Groups['flags'].Value,
                    [System.Globalization.NumberStyles]::HexNumber,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [ref]$debugFlags
                )) {
                    throw 'Git index metadata returned invalid flags.'
                }
                if (($debugFlags -band [uint64]0x20000000) -ne 0) {
                    $tabOffset = $record.IndexOf([char]9)
                    $intentPath = if ($tabOffset -ge 0) {
                        $record.Substring($tabOffset + 1)
                    } else {
                        '<malformed>'
                    }
                    $safeIntentPath =
                        ConvertTo-PrivateMarkerDiagnosticText $intentPath
                    throw "Git index contains an intent-to-add entry: $safeIntentPath."
                }
                $debugOffset = $debugMatch.Index + $debugMatch.Length
            }
            if ($debugOffset -ne $indexDebugText.Length) {
                throw 'Git index metadata returned trailing bytes.'
            }

            $pathComparer = if (Test-PrivateMarkerWindowsHost) {
                [System.StringComparer]::OrdinalIgnoreCase
            } else {
                [System.StringComparer]::Ordinal
            }
            $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
                $pathComparer
            )
            $indexEntries = New-Object System.Collections.Generic.List[object]
            foreach ($record in $records) {
                Assert-PrivateMarkerScanDeadline
                $parsed = [regex]::Match(
                    $record,
                    '(?s)^(?<mode>[0-9]{6}) (?<oid>[0-9a-f]{40}|[0-9a-f]{64}) (?<stage>[0-3])\t(?<path>.+)$'
                )
                if (-not $parsed.Success) {
                    throw 'Git index enumeration returned a malformed record.'
                }
                $mode = $parsed.Groups['mode'].Value
                $oid = $parsed.Groups['oid'].Value.ToLowerInvariant()
                $stage = $parsed.Groups['stage'].Value
                $relative = $parsed.Groups['path'].Value
                $safeRelative =
                    ConvertTo-PrivateMarkerDiagnosticText $relative
                if ($stage -ne '0') {
                    throw "Git index contains an unresolved conflict: $safeRelative."
                }
                if ($mode -notin @('100644', '100755')) {
                    throw "Git index contains a symlink, gitlink, or unsupported mode: $safeRelative."
                }
                if ($oid -match '^0+$') {
                    throw "Git index contains an intent-to-add entry: $safeRelative."
                }
                if ([string]::IsNullOrWhiteSpace($relative) -or
                    $relative -match '[\x00-\x1F\x7F]' -or
                    $relative -match '\\' -or
                    [System.IO.Path]::IsPathRooted($relative) -or
                    -not $seenPaths.Add($relative)) {
                    throw 'Git index contains an unsafe or duplicate path.'
                }
                if ([string]::Equals(
                    $relative,
                    '.private-markers.local',
                    $pathComparison
                )) {
                    throw 'The local private marker file must remain untracked.'
                }

                try {
                    $fullPath = [System.IO.Path]::GetFullPath(
                        (Join-Path $canonicalRoot $relative)
                    )
                }
                catch {
                    throw 'Git index contains a path that cannot be canonicalized.'
                }
                if (-not $fullPath.StartsWith($rootPrefix, $pathComparison)) {
                    throw 'Git index path escaped the explicit scan root.'
                }

                $worktreeItem = $null
                if (Test-SafeWorktreeParentChain -RelativePath $relative) {
                    try {
                        $worktreeItem = Get-Item `
                            -LiteralPath $fullPath `
                            -Force `
                            -ErrorAction Stop
                    }
                    catch [System.Management.Automation.ItemNotFoundException] {
                        # leaf が無い場合も staged index blob は後段で検査する。
                        $worktreeItem = $null
                    }
                    catch {
                        throw "Tracked worktree path could not be inspected: $safeRelative."
                    }
                }
                if ($null -ne $worktreeItem -and
                    (($worktreeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                        $worktreeItem.PSIsContainer)) {
                    throw "Tracked worktree path is not a regular local file: $safeRelative."
                }

                if (-not (Test-IsTextFile $relative)) {
                    continue
                }

                $indexEntries.Add([pscustomobject]@{
                    Oid = $oid
                    RelativePath = $relative
                    DiagnosticPath = $safeRelative
                    FullPath = $fullPath
                    WorktreeItem = $worktreeItem
                    InitialWorktreePresent = $null -ne $worktreeItem
                    InitialWorktreeBytes = $null
                }) | Out-Null
            }

            # text candidate の unique blob を1回の binary-safe batch で読む。
            # suspended process 境界を OID ごとに起動せず、process 数と runtime を一定に保つ。
            $blobCache = @{}
            $blobOids = New-Object System.Collections.Generic.List[string]
            $blobOidSet = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::Ordinal
            )
            foreach ($entry in $indexEntries) {
                Assert-PrivateMarkerScanDeadline
                if ($blobOidSet.Add($entry.Oid)) {
                    $blobOids.Add($entry.Oid) | Out-Null
                }
            }
            if ($blobOids.Count -gt 0) {
                $batchInputBytes = [System.Text.Encoding]::ASCII.GetBytes(
                    (($blobOids -join "`n") + "`n")
                )
                $batchOutputLimit = [int](
                    $maximumTotalTextBytes + ($blobOids.Count * 160) + 1
                )
                $batchProbe = Invoke-ScannerGit `
                    -Arguments @(
                        '-C',
                        $canonicalRoot,
                        'cat-file',
                        '--batch'
                    ) `
                    -MaximumStandardOutputBytes $batchOutputLimit `
                    -StandardInputBytes $batchInputBytes
                Assert-HealthyGitBoundary `
                    -Result $batchProbe `
                    -Context 'Git index blob batch read'

                $batchOffset = 0
                $batchBlobTotal = 0L
                foreach ($expectedOid in $blobOids) {
                    Assert-PrivateMarkerScanDeadline
                    $headerEnd = -1
                    $headerSearchLimit = [Math]::Min(
                        $batchProbe.StandardOutputBytes.Length,
                        $batchOffset + 256
                    )
                    for ($offset = $batchOffset;
                        $offset -lt $headerSearchLimit;
                        $offset++) {
                        if ($batchProbe.StandardOutputBytes[$offset] -eq 10) {
                            $headerEnd = $offset
                            break
                        }
                    }
                    if ($headerEnd -lt 0) {
                        throw 'Git index blob batch returned a malformed header.'
                    }
                    for ($offset = $batchOffset;
                        $offset -lt $headerEnd;
                        $offset++) {
                        if ($batchProbe.StandardOutputBytes[$offset] -gt 127) {
                            throw 'Git index blob batch returned a non-ASCII header.'
                        }
                    }
                    $batchHeader = [System.Text.Encoding]::ASCII.GetString(
                        $batchProbe.StandardOutputBytes,
                        $batchOffset,
                        $headerEnd - $batchOffset
                    )
                    $batchHeaderMatch = [regex]::Match(
                        $batchHeader,
                        '^(?<oid>[0-9a-fA-F]{40}|[0-9a-fA-F]{64}) blob (?<size>0|[1-9][0-9]*)$'
                    )
                    if (-not $batchHeaderMatch.Success -or
                        -not $batchHeaderMatch.Groups['oid'].Value.Equals(
                            $expectedOid,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )) {
                        throw 'Git index blob batch returned an unexpected object.'
                    }
                    $blobSize = 0L
                    if (-not [long]::TryParse(
                        $batchHeaderMatch.Groups['size'].Value,
                        [System.Globalization.NumberStyles]::None,
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        [ref]$blobSize
                    ) -or
                        $blobSize -gt $maximumTextBytes) {
                        throw 'Git index blob size is invalid or exceeds the limit.'
                    }
                    $batchBlobTotal += $blobSize
                    if ($batchBlobTotal -gt $maximumTotalTextBytes) {
                        throw 'Git index blobs exceeded the total text byte limit.'
                    }

                    $blobStart = $headerEnd + 1
                    $blobEnd = $blobStart + [int]$blobSize
                    if ($blobEnd -ge $batchProbe.StandardOutputBytes.Length -or
                        $batchProbe.StandardOutputBytes[$blobEnd] -ne 10) {
                        throw 'Git index blob batch returned an invalid byte boundary.'
                    }
                    $indexBytes = New-Object byte[] ([int]$blobSize)
                    if ($blobSize -gt 0) {
                        [Array]::Copy(
                            $batchProbe.StandardOutputBytes,
                            $blobStart,
                            $indexBytes,
                            0,
                            [int]$blobSize
                        )
                    }
                    $blobCache[$expectedOid] = [pscustomobject]@{
                        Bytes = $indexBytes
                    }
                    $batchOffset = [int]($blobEnd + 1)
                }
                if ($batchOffset -ne $batchProbe.StandardOutputBytes.Length) {
                    throw 'Git index blob batch returned trailing bytes.'
                }
            }

            foreach ($entry in $indexEntries) {
                Assert-PrivateMarkerScanDeadline
                if (-not $blobCache.ContainsKey($entry.Oid)) {
                    throw "Git index blob batch omitted an object: $($entry.DiagnosticPath)."
                }
                $indexBytes = [byte[]]$blobCache[$entry.Oid].Bytes
                Add-TextTarget `
                    -RelativePath $entry.RelativePath `
                    -Source 'index' `
                    -Bytes $indexBytes

                if ($null -ne $entry.WorktreeItem) {
                    $worktreeBytes = Read-StableWorktreeBytes `
                        -FullPath $entry.FullPath `
                        -RelativePath $entry.RelativePath
                    $entry.InitialWorktreeBytes = $worktreeBytes
                    if (-not (Test-ByteArraysEqual -Left $indexBytes -Right $worktreeBytes)) {
                        Add-TextTarget `
                            -RelativePath $entry.RelativePath `
                            -Source 'working-tree' `
                            -Bytes $worktreeBytes
                    }
                }
            }

            $initialGitIndexBytes = [byte[]]$indexProbe.StandardOutputBytes
            $initialGitIndexDebugBytes =
                [byte[]]$indexDebugProbe.StandardOutputBytes
            $verifyGitIndexAtScanEnd = $true
            $scanMode = 'git-tracked'
        }
    }
    finally {
        $changedEnvironmentNames = @(
            Get-ChangedEnvironmentVariableNames -Expected $environmentBeforeGit
        )
        if (-not $verifyGitIndexAtScanEnd -and
            (Test-Path -LiteralPath $gitIsolationRoot)) {
            Remove-Item -LiteralPath $gitIsolationRoot -Recurse -Force
        }
    }
    if ($changedEnvironmentNames.Count -gt 0) {
        if ($verifyGitIndexAtScanEnd -and
            (Test-Path -LiteralPath $gitIsolationRoot)) {
            Remove-Item -LiteralPath $gitIsolationRoot -Recurse -Force
        }
        throw "Hermetic Git boundary changed scanner environment variables: $($changedEnvironmentNames -join ', ')."
    }
}

$finalGitEnvironmentChanges = @()
try {
    foreach ($target in $scanTargets) {
        Assert-PrivateMarkerScanDeadline
        Invoke-BoundedLineAction `
            -Content $target.Content `
            -Context "$($target.File) ($($target.Source))" `
            -Action {
                param($line, $lineNumber)

                # 同一行の URL は bounded NextMatch で探索し、ruleごとの finding は1件に畳む。
                $urlMatchCount = 0
                $urlMatch = $githubUrlMatcher.Match($line)
                while ($urlMatch.Success) {
                    Assert-PrivateMarkerScanDeadline
                    $urlMatchCount++
                    if ($urlMatchCount -gt $maximumMatchesPerRulePerLine) {
                        throw 'Private marker scan exceeded its per-line URL match limit.'
                    }
                    if (-not $allowedRepoUrlMatcher.IsMatch($urlMatch.Value)) {
                        Add-BoundedFinding `
                            -File $target.File `
                            -Source $target.Source `
                            -Line $lineNumber `
                            -Rule 'non-allowlisted-github-repo-url'
                        break
                    }
                    $urlMatch = $urlMatch.NextMatch()
                }

                foreach ($rule in $rules) {
                    Assert-PrivateMarkerScanDeadline
                    $matched = $false
                    if ($rule.Kind -eq 'literal') {
                        $matched = $line.Contains($rule.Pattern)
                    } elseif ($null -eq $rule.AllowlistMatcher) {
                        $matched = $rule.Matcher.IsMatch($line)
                    } else {
                        # Allowlist付き regex も全match配列を作らず、上限内で判定する。
                        # System path の match は trailing prose まで含み得るため、
                        # match終端ではなく開始位置の次から再探索し、同じ行に続く
                        # private-looking path を取りこぼさない。
                        $ruleMatchCount = 0
                        $ruleMatch = $rule.Matcher.Match($line)
                        while ($ruleMatch.Success) {
                            Assert-PrivateMarkerScanDeadline
                            $ruleMatchCount++
                            if ($ruleMatchCount -gt $maximumMatchesPerRulePerLine) {
                                throw 'Private marker scan exceeded its per-line rule match limit.'
                            }
                            if (-not $rule.AllowlistMatcher.IsMatch(
                                    $ruleMatch.Value
                                )) {
                                $matched = $true
                                break
                            }
                            $nextSearchIndex = $ruleMatch.Index + 1
                            if ($nextSearchIndex -gt $line.Length) {
                                break
                            }
                            $ruleMatch = $rule.Matcher.Match(
                                $line,
                                $nextSearchIndex
                            )
                        }
                    }

                    if ($matched) {
                        Add-BoundedFinding `
                            -File $target.File `
                            -Source $target.Source `
                            -Line $lineNumber `
                            -Rule $rule.Name
                    }
                }
            }
    }

    if ($verifyGitIndexAtScanEnd) {
        # marker解析後、content再検証へ入る前に開始時と同じraw stage/debug
        # listingを再取得し、解析中の追加・差替えを先に拒否する。
        Assert-GitIndexSnapshotsUnchanged

        # indexのpre-content snapshot取得後に、開始時に読んだ全tracked textの
        # worktree bytes/presenceも再確認する。indexが不変でも解析後にleafが
        # 差替え・追加・削除された場合は成功を返さない。
        foreach ($entry in $indexEntries) {
            Assert-PrivateMarkerScanDeadline
            $currentWorktreeItem = $null
            if (Test-SafeWorktreeParentChain `
                    -RelativePath $entry.RelativePath) {
                try {
                    $currentWorktreeItem = Get-Item `
                        -LiteralPath $entry.FullPath `
                        -Force `
                        -ErrorAction Stop
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    $currentWorktreeItem = $null
                }
                catch {
                    throw "Tracked worktree path could not be revalidated: $($entry.DiagnosticPath)."
                }
            }
            if ($null -ne $currentWorktreeItem -and
                (($currentWorktreeItem.Attributes -band
                        [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    $currentWorktreeItem.PSIsContainer)) {
                throw "Tracked worktree path changed to an unsafe entry: $($entry.DiagnosticPath)."
            }
            if ($entry.InitialWorktreePresent) {
                if ($null -eq $currentWorktreeItem) {
                    throw "Tracked worktree file disappeared during the scan: $($entry.DiagnosticPath)."
                }
                $finalWorktreeBytes = Read-StableWorktreeBytes `
                    -FullPath $entry.FullPath `
                    -RelativePath $entry.RelativePath
                if (-not (Test-ByteArraysEqual `
                        -Left $entry.InitialWorktreeBytes `
                        -Right $finalWorktreeBytes)) {
                    throw "Tracked worktree file changed during the scan: $($entry.DiagnosticPath)."
                }
            } elseif ($null -ne $currentWorktreeItem) {
                throw "Tracked worktree file appeared during the scan: $($entry.DiagnosticPath)."
            }
        }
    }

    # local markerはscan ruleそのものを増やす入力なので、tracked fileと同様に
    # 成功直前のpresence/bytesを開始snapshotへ照合する。途中の作成・削除・
    # 差替えで古いrule集合のsuccessを返さない。
    Assert-PrivateMarkerScanDeadline
    [void](Test-SafeWorktreeParentChain -RelativePath '.')
    $finalLocalMarkerItem = Get-PrivateMarkerLocalLeaf
    $finalHasLocalMarker = $null -ne $finalLocalMarkerItem
    if ($finalHasLocalMarker -ne $hasLocalMarker) {
        throw 'Local private marker presence changed during the scan.'
    }
    if ($finalHasLocalMarker) {
        if (($finalLocalMarkerItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $finalLocalMarkerItem.PSIsContainer) {
            throw 'Local private marker file changed to an unsafe entry.'
        }
        $finalLocalMarkerBytes = Read-StableWorktreeBytes `
            -FullPath $localMarkerFile `
            -RelativePath '.private-markers.local'
        if (-not (Test-ByteArraysEqual `
                -Left $localMarkerBytes `
                -Right $finalLocalMarkerBytes)) {
            throw 'Local private marker content changed during the scan.'
        }
    }

    if ($verifyGitIndexAtScanEnd) {
        # worktree/local再検証中にindexだけが変わる最終windowを閉じる。
        # stageとdebugの双方を再取得し、content再検証後の同一性も要求する。
        Assert-GitIndexSnapshotsUnchanged
    }
}
finally {
    if ($verifyGitIndexAtScanEnd) {
        $finalGitEnvironmentChanges = @(
            Get-ChangedEnvironmentVariableNames -Expected $environmentBeforeGit
        )
        if (Test-Path -LiteralPath $gitIsolationRoot) {
            Remove-Item -LiteralPath $gitIsolationRoot -Recurse -Force
        }
    }
}
if ($finalGitEnvironmentChanges.Count -gt 0) {
    throw "Hermetic Git boundary changed scanner environment variables: $($finalGitEnvironmentChanges -join ', ')."
}

if ($findings.Count -gt 0) {
    # header と全 finding を明示 LF の単一 payload へ積み、actual UTF-8
    # byte 数を確認してから一度だけ出す。partial table を残さない。
    $outputBuilder = New-Object System.Text.StringBuilder
    $outputPrefix = "Private marker scan failed (scan target: $scanMode):"
    $outputHeader = "File`tSource`tLine`tRule`tMatch"
    [void]$outputBuilder.Append($outputPrefix)
    [void]$outputBuilder.Append([char]10)
    [void]$outputBuilder.Append($outputHeader)
    [void]$outputBuilder.Append([char]10)
    $outputByteCount = (
        [System.Text.Encoding]::UTF8.GetByteCount($outputPrefix) +
        1 +
        [System.Text.Encoding]::UTF8.GetByteCount($outputHeader) +
        1
    )
    foreach ($finding in $findings | Sort-Object File, Source, Line, Rule) {
        Assert-PrivateMarkerScanDeadline
        $outputLine = "{0}`t{1}`t{2}`t{3}`t{4}" -f @(
            $finding.File,
            $finding.Source,
            $finding.Line,
            $finding.Rule,
            $finding.Match
        )
        $outputByteCount += (
            [System.Text.Encoding]::UTF8.GetByteCount($outputLine) + 1
        )
        if ($outputByteCount -gt $maximumFindingOutputBytes) {
            Assert-PrivateMarkerScanDeadline
            [Console]::Error.WriteLine(
                'Private marker scan aborted: scan-diagnostic-output-limit'
            )
            exit 1
        }
        [void]$outputBuilder.Append($outputLine)
        [void]$outputBuilder.Append([char]10)
    }
    $outputText = $outputBuilder.ToString()
    [byte[]]$outputBytes =
        [System.Text.Encoding]::UTF8.GetBytes($outputText)
    if ($outputBytes.Length -ne $outputByteCount -or
        $outputBytes.Length -gt $maximumFindingOutputBytes) {
        Assert-PrivateMarkerScanDeadline
        [Console]::Error.WriteLine(
            'Private marker scan aborted: scan-diagnostic-output-limit'
        )
        exit 1
    }

    # Console.Out は host 所有の writer なので close/dispose せず、期限確認の
    # 直後に単一 write だけを行う。
    Assert-PrivateMarkerScanDeadline
    [Console]::Out.Write($outputText)
    [Console]::Out.Flush()
    exit 1
}

# clean 判定も emit 直前に再確認し、最終 probe 後の期限超過を成功にしない。
Assert-PrivateMarkerScanDeadline
[Console]::Out.WriteLine(
    "Private marker scan passed (scan target: $scanMode)."
)
[Console]::Out.Flush()
exit 0
}
catch {
    # helper/provider/Git/isolation/cleanupの例外本文にはabsolute pathや
    # ambient値が含まれ得るため、全境界失敗を固定ASCII診断へ畳む。
    [Console]::Error.WriteLine(
        'Private marker scan failed closed (integrity: scanner-boundary).'
    )
    exit 2
}
