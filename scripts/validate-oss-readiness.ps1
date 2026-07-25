[CmdletBinding()]
param(
    [string]$Path = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Split-Path -Parent $scriptRoot
}

$root = (Resolve-Path -LiteralPath $Path).Path
$failures = New-Object System.Collections.Generic.List[string]

function Add-Failure {
    param([string]$Message)
    $failures.Add($Message) | Out-Null
}

function Get-RepoFilePath {
    param([string]$RelativePath)
    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        return [System.IO.Path]::GetFullPath($RelativePath)
    }
    return Join-Path $root $RelativePath
}

function Get-RepoUtf8Text {
    param([string]$RelativePath)

    return [System.IO.File]::ReadAllText(
        (Get-RepoFilePath -RelativePath $RelativePath),
        (New-Object System.Text.UTF8Encoding($false, $true))
    )
}

function Assert-FileExists {
    param([string]$RelativePath)

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Missing required file: $RelativePath"
    }
}

function Assert-FileContains {
    param(
        [string]$RelativePath,
        [string]$Pattern,
        [string]$Description
    )

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing file: $RelativePath ($Description)"
        return
    }

    try {
        $content = Get-RepoUtf8Text -RelativePath $RelativePath
    }
    catch {
        Add-Failure "$RelativePath must be valid UTF-8 ($Description)"
        return
    }
    if ($content -notmatch $Pattern) {
        Add-Failure "$RelativePath is missing: $Description"
    }
}

function Assert-FileDoesNotContain {
    param(
        [string]$RelativePath,
        [string]$Pattern,
        [string]$Description
    )

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing file: $RelativePath ($Description)"
        return
    }

    try {
        $content = Get-RepoUtf8Text -RelativePath $RelativePath
    }
    catch {
        Add-Failure "$RelativePath must be valid UTF-8 ($Description)"
        return
    }
    if ($content -match $Pattern) {
        Add-Failure "$RelativePath must not contain: $Description"
    }
}

function Assert-FileMatchCount {
    param(
        [string]$RelativePath,
        [string]$Pattern,
        [int]$ExpectedCount,
        [string]$Description
    )

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing file: $RelativePath ($Description)"
        return
    }

    try {
        $content = Get-RepoUtf8Text -RelativePath $RelativePath
    }
    catch {
        Add-Failure "$RelativePath must be valid UTF-8 ($Description)"
        return
    }
    $actualCount = [regex]::Matches($content, $Pattern).Count
    if ($actualCount -ne $ExpectedCount) {
        Add-Failure "$RelativePath must contain $ExpectedCount match(es) for $Description; found $actualCount."
    }
}

function Assert-FileHasUtf8Bom {
    param([string]$RelativePath)

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing file: $RelativePath (UTF-8 BOM contract)"
        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($filePath)
    if ($bytes.Length -lt 3 -or
        $bytes[0] -ne 0xEF -or
        $bytes[1] -ne 0xBB -or
        $bytes[2] -ne 0xBF) {
        Add-Failure "$RelativePath must keep a UTF-8 BOM because Windows PowerShell 5.1 executes its Japanese comments."
    }
}

function Assert-FinalScanDeadlineContract {
    param([string]$RelativePath)

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing file: $RelativePath (final scan deadline contract)"
        return
    }

    # scan clock 開始後に到達する finding、固定 failure、clean success は、
    # actual write の直前に共通時計を確認する。binder leak を防ぐ公開引数
    # failure と、期限検査自身も畳む最外 catch は clock の外側として別に固定する。
    try {
        $source = Get-RepoUtf8Text -RelativePath $RelativePath
    }
    catch {
        Add-Failure "$RelativePath must be valid UTF-8 (final scan deadline contract)"
        return
    }
    $findingWritePattern =
        '(?m)^[ \t]*\[Console\]::Out\.Write\(\$outputText\)[ \t]*$'
    $guardedFindingWritePattern = (
        '(?m)^[ \t]*Assert-PrivateMarkerScanDeadline[ \t]*\r?\n' +
        '[ \t]*\[Console\]::Out\.Write\(\$outputText\)[ \t]*$'
    )
    $failureWritePattern =
        '(?m)^[ \t]*\[Console\]::Error\.WriteLine\([ \t]*$'
    $guardedFailureWritePattern = (
        '(?m)^[ \t]*Assert-PrivateMarkerScanDeadline[ \t]*\r?\n' +
        '[ \t]*\[Console\]::Error\.WriteLine\([ \t]*$'
    )
    $successWritePattern = (
        '(?m)^[ \t]*Assert-PrivateMarkerScanDeadline[ \t]*\r?\n' +
        '[ \t]*\[Console\]::Out\.WriteLine\([ \t]*\r?\n' +
        '[ \t]*"Private marker scan passed \(scan target: \$scanMode\)\."'
    )
    $findingWriteCount =
        [regex]::Matches($source, $findingWritePattern).Count
    $guardedFindingWriteCount =
        [regex]::Matches($source, $guardedFindingWritePattern).Count
    $failureWriteCount =
        [regex]::Matches($source, $failureWritePattern).Count
    $guardedFailureWriteCount =
        [regex]::Matches($source, $guardedFailureWritePattern).Count
    $openStandardOutputCount = [regex]::Matches(
        $source,
        '\[Console\]::OpenStandardOutput\('
    ).Count
    $writeHostCount = [regex]::Matches(
        $source,
        '(?m)^[ \t]*Write-Host\b'
    ).Count
    $outputLimitDiagnosticCount = [regex]::Matches(
        $source,
        'Private marker scan aborted: scan-diagnostic-output-limit'
    ).Count
    $invocationContractDiagnosticCount = [regex]::Matches(
        $source,
        'Private marker scan failed closed \(integrity: invocation-contract\)\.'
    ).Count
    $scannerBoundaryDiagnosticCount = [regex]::Matches(
        $source,
        'Private marker scan failed closed \(integrity: scanner-boundary\)\.'
    ).Count
    $scanRootDiagnosticCount = [regex]::Matches(
        $source,
        'Private marker scan failed closed \(integrity: scan-root-missing\)\.'
    ).Count
    $integrityReasonDiagnosticCount = [regex]::Matches(
        $source,
        'Private marker scan failed closed \(integrity: \$Reason\)\.'
    ).Count
    $fixedOuterCatchPattern = (
        '(?s)catch\s*\{\s*' +
        '(?:\#[^\r\n]*\r?\n\s*)*' +
        '\[Console\]::Error\.WriteLine\(\s*' +
        "'Private marker scan failed closed \(integrity: scanner-boundary\)\.'\s*" +
        '\)\s*exit 2\s*\}\s*$'
    )

    if ($findingWriteCount -ne 1 -or
        $guardedFindingWriteCount -ne $findingWriteCount) {
        Add-Failure "$RelativePath must guard its single finding stdout write with an immediate scan-wide deadline check."
    }
    if ($failureWriteCount -ne 6 -or
        $guardedFailureWriteCount -ne 4 -or
        $outputLimitDiagnosticCount -ne 2 -or
        $scanRootDiagnosticCount -ne 1 -or
        $integrityReasonDiagnosticCount -ne 1) {
        Add-Failure "$RelativePath must guard every scan-clock failure diagnostic with an immediate deadline check."
    }
    if ($invocationContractDiagnosticCount -ne 1 -or
        $scannerBoundaryDiagnosticCount -ne 1 -or
        $source -notmatch $fixedOuterCatchPattern) {
        Add-Failure "$RelativePath must keep public invocation and outer scanner failures fixed, redacted, and outside recursive deadline checks."
    }
    if ($source -notmatch $successWritePattern) {
        Add-Failure "$RelativePath must recheck the scan-wide deadline immediately before success output."
    }
    if ($openStandardOutputCount -ne 0 -or $writeHostCount -ne 0) {
        Add-Failure "$RelativePath must use the host-owned Console writers without OpenStandardOutput or Write-Host."
    }
}

function Get-WorkflowJobLines {
    param(
        [string]$RelativePath,
        [string]$JobName
    )

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing workflow file: $RelativePath"
        return @()
    }

    # workflow は BOM-less UTF-8。PS5.1 の locale decode に依存せず、
    # job 境界を exact indentation で切り出す。
    try {
        $workflowSource = [System.IO.File]::ReadAllText(
            $filePath,
            (New-Object System.Text.UTF8Encoding($false, $true))
        )
    }
    catch {
        Add-Failure "Workflow file '$RelativePath' must be valid UTF-8."
        return @()
    }
    $lines = @($workflowSource -split '\r?\n')
    $jobStart = -1
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $jobMatch = [regex]::Match(
            $lines[$index],
            '^  (?<name>[A-Za-z0-9_-]+):[ \t]*$'
        )
        if ($jobMatch.Success -and
            $jobMatch.Groups['name'].Value -ceq $JobName) {
            $jobStart = $index
            break
        }
    }
    if ($jobStart -lt 0) {
        Add-Failure "Workflow job '$JobName' is missing."
        return @()
    }

    $jobEnd = $lines.Count
    for ($index = $jobStart + 1; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match '^  [A-Za-z0-9_-]+:[ \t]*$') {
            $jobEnd = $index
            break
        }
    }
    return @($lines[$jobStart..($jobEnd - 1)])
}

function Assert-WorkflowJobSet {
    param(
        [string]$RelativePath,
        [string[]]$ExpectedJobNames
    )

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        return
    }
    try {
        $source = [System.IO.File]::ReadAllText(
            $filePath,
            (New-Object System.Text.UTF8Encoding($false, $true))
        )
    }
    catch {
        return
    }
    $lines = @($source -split '\r?\n')
    $jobsKeyIndexes = @(
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index] -match '^jobs:[ \t]*$') {
                $index
            }
        }
    )
    if ($jobsKeyIndexes.Count -ne 1) {
        Add-Failure "Workflow must declare exactly one top-level jobs mapping."
        return
    }
    $jobsStart = $jobsKeyIndexes[0] + 1
    $jobsEnd = $lines.Count
    for ($index = $jobsStart; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match '^[A-Za-z0-9_-]+:[ \t]*$') {
            $jobsEnd = $index
            break
        }
    }
    $actualJobNames = @(
        for ($index = $jobsStart; $index -lt $jobsEnd; $index++) {
            $match = [regex]::Match(
                $lines[$index],
                '^  (?<name>[A-Za-z0-9_-]+):[ \t]*$'
            )
            if ($match.Success) {
                $match.Groups['name'].Value
            }
        }
    )
    $expectedSorted = @($ExpectedJobNames | Sort-Object)
    $actualSorted = @($actualJobNames | Sort-Object)
    if ($actualJobNames.Count -ne $ExpectedJobNames.Count -or
        ($actualSorted -join "`n") -cne ($expectedSorted -join "`n")) {
        Add-Failure "Workflow jobs must be exactly: $($ExpectedJobNames -join ', ') (found: $($actualJobNames -join ', '))."
    }
}

function Assert-WorkflowEnvelope {
    param([string]$RelativePath)

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        return
    }
    try {
        $source = [System.IO.File]::ReadAllText(
            $filePath,
            (New-Object System.Text.UTF8Encoding($false, $true))
        )
    }
    catch {
        return
    }
    $lines = @($source -split '\r?\n')

    # workflow-level scopeも固定し、extra trigger、write permission、
    # 別 top-level keyをjob validatorの外へ隠せないようにする。
    $topLevelEntries = @(
        $lines | Where-Object {
            $_ -match '^(?![ #\r\n])[A-Za-z0-9_-]+:[ \t]*'
        }
    )
    $expectedTopLevel = @(
        'name: Validate',
        'on:',
        'permissions:',
        'jobs:'
    )
    if ($topLevelEntries.Count -ne $expectedTopLevel.Count -or
        (@($topLevelEntries | ForEach-Object { $_.TrimEnd() }) -join "`n") -cne
            ($expectedTopLevel -join "`n")) {
        Add-Failure 'Workflow top-level keys must be exactly name/on/permissions/jobs with name Validate.'
    }

    $onIndexes = @(
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index] -match '^on:[ \t]*$') { $index }
        }
    )
    $permissionIndexes = @(
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index] -match '^permissions:[ \t]*$') { $index }
        }
    )
    $jobsIndexes = @(
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index] -match '^jobs:[ \t]*$') { $index }
        }
    )
    if ($onIndexes.Count -ne 1 -or
        $permissionIndexes.Count -ne 1 -or
        $jobsIndexes.Count -ne 1 -or
        $onIndexes[0] -ge $permissionIndexes[0] -or
        $permissionIndexes[0] -ge $jobsIndexes[0]) {
        Add-Failure 'Workflow on/permissions/jobs sections must each appear once in canonical order.'
        return
    }

    $triggerActiveLines = @(
        $lines[($onIndexes[0] + 1)..($permissionIndexes[0] - 1)] |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and
                -not $_.TrimStart().StartsWith('#')
            } |
            ForEach-Object { $_.TrimEnd() }
    )
    $permissionActiveLines = @(
        $lines[($permissionIndexes[0] + 1)..($jobsIndexes[0] - 1)] |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and
                -not $_.TrimStart().StartsWith('#')
            } |
            ForEach-Object { $_.TrimEnd() }
    )
    $expectedTriggerLines = @(
        '  pull_request:',
        '  push:',
        '    branches:',
        '      - main'
    )
    $expectedPermissionLines = @('  contents: read')
    if (($triggerActiveLines -join "`n") -cne
            ($expectedTriggerLines -join "`n") -or
        ($permissionActiveLines -join "`n") -cne
            ($expectedPermissionLines -join "`n")) {
        Add-Failure 'Workflow triggers and permissions must be exactly pull_request, push main, and contents read.'
    }
}

function Get-WorkflowSteps {
    param(
        [string[]]$Lines,
        [string]$JobName
    )

    $stepStartCount = @(
        $Lines | Where-Object { $_ -match '^      -[ \t]+' }
    ).Count
    $namedStepCount = @(
        $Lines | Where-Object { $_ -match '^      -[ \t]+name:[ \t]+' }
    ).Count
    if ($stepStartCount -ne $namedStepCount) {
        Add-Failure "Workflow job '$JobName' must give every active step an explicit name."
    }

    $steps = New-Object System.Collections.Generic.List[object]
    $currentStep = $null
    foreach ($line in $Lines) {
        $nameMatch = [regex]::Match(
            $line,
            '^      -[ \t]+name:[ \t]*(?<value>[^#\r\n]+?)[ \t]*$'
        )
        if ($nameMatch.Success) {
            if ($null -ne $currentStep) {
                $steps.Add($currentStep) | Out-Null
            }
            $currentStep = [pscustomobject]@{
                Name = $nameMatch.Groups['value'].Value.Trim("'`"")
                Shell = ''
                Run = ''
                Uses = ''
                ShellCount = 0
                RunCount = 0
                UsesCount = 0
            }
            continue
        }
        if ($null -eq $currentStep) {
            continue
        }

        $shellMatch = [regex]::Match(
            $line,
            '^        shell:[ \t]*(?<value>[^#\r\n]+?)[ \t]*$'
        )
        if ($shellMatch.Success) {
            $currentStep.Shell =
                $shellMatch.Groups['value'].Value.Trim("'`"")
            $currentStep.ShellCount++
            continue
        }
        $runMatch = [regex]::Match(
            $line,
            '^        run:[ \t]*(?<value>[^#\r\n]+?)[ \t]*$'
        )
        if ($runMatch.Success) {
            $currentStep.Run =
                $runMatch.Groups['value'].Value.Trim("'`"")
            $currentStep.RunCount++
            continue
        }
        $usesMatch = [regex]::Match(
            $line,
            '^        uses:[ \t]*(?<value>[^#\r\n]+?)[ \t]*(?:#.*)?$'
        )
        if ($usesMatch.Success) {
            $currentStep.Uses =
                $usesMatch.Groups['value'].Value.Trim("'`"")
            $currentStep.UsesCount++
        }
    }
    if ($null -ne $currentStep) {
        $steps.Add($currentStep) | Out-Null
    }
    return $steps.ToArray()
}

function Assert-WorkflowJobValue {
    param(
        [string[]]$Lines,
        [string]$JobName,
        [string]$Key,
        [string]$ExpectedValue
    )

    $pattern = (
        '^    ' +
        [regex]::Escape($Key) +
        ':[ \t]*' +
        [regex]::Escape($ExpectedValue) +
        '[ \t]*(?:#.*)?$'
    )
    $keyPattern = '^    ' + [regex]::Escape($Key) + ':[ \t]*'
    $keyLines = @($Lines | Where-Object { $_ -match $keyPattern })
    $matchingLines = @($keyLines | Where-Object { $_ -match $pattern })
    if ($keyLines.Count -ne 1 -or $matchingLines.Count -ne 1) {
        Add-Failure "Workflow job '$JobName' must declare exactly one '${Key}: $ExpectedValue' value (total keys $($keyLines.Count), expected values $($matchingLines.Count))."
    }
}

function Assert-WorkflowStepCount {
    param(
        [object[]]$Steps,
        [string]$JobName,
        [int]$ExpectedCount
    )

    if ($Steps.Count -ne $ExpectedCount) {
        Add-Failure "Workflow job '$JobName' must contain exactly $ExpectedCount named steps (found $($Steps.Count))."
    }
}

function Assert-WorkflowJobShape {
    param(
        [string[]]$Lines,
        [string]$JobName,
        [int]$ExpectedStepCount,
        [int]$ExpectedShellCount,
        [int]$ExpectedRunCount
    )

    # expected keyを残した無効化やextra actionを許さないよう、indent別に
    # 全 active job/step/property を数える。
    $jobEntryCount = @(
        $Lines | Where-Object { $_ -match '^    (?![ #\r\n]).+$' }
    ).Count
    $nameKeyCount = @(
        $Lines | Where-Object { $_ -match '^    name:[ \t]*' }
    ).Count
    $stepsKeyCount = @(
        $Lines | Where-Object { $_ -match '^    steps:[ \t]*' }
    ).Count
    $stepItemCount = @(
        $Lines | Where-Object { $_ -match '^      -[ \t]+' }
    ).Count
    $stepPropertyCount = @(
        $Lines | Where-Object { $_ -match '^        (?![ #\r\n]).+$' }
    ).Count
    $shellKeyCount = @(
        $Lines | Where-Object { $_ -match '^        shell:[ \t]*' }
    ).Count
    $runKeyCount = @(
        $Lines | Where-Object { $_ -match '^        run:[ \t]*' }
    ).Count
    $usesKeyCount = @(
        $Lines | Where-Object { $_ -match '^        uses:[ \t]*' }
    ).Count
    $expectedStepPropertyCount =
        1 + $ExpectedShellCount + $ExpectedRunCount

    if ($jobEntryCount -ne 4 -or
        $nameKeyCount -ne 1 -or
        $stepsKeyCount -ne 1) {
        Add-Failure "Workflow job '$JobName' must contain only one name/runs-on/timeout-minutes/steps mapping."
    }
    if ($stepItemCount -ne $ExpectedStepCount) {
        Add-Failure "Workflow job '$JobName' must contain exactly $ExpectedStepCount step items (found $stepItemCount)."
    }
    if ($stepPropertyCount -ne $expectedStepPropertyCount -or
        $shellKeyCount -ne $ExpectedShellCount -or
        $runKeyCount -ne $ExpectedRunCount -or
        $usesKeyCount -ne 1) {
        Add-Failure "Workflow job '$JobName' contains an unexpected, missing, or duplicate step-level key."
    }
}

function Assert-WorkflowStep {
    param(
        [object[]]$Steps,
        [string]$JobName,
        [string]$Name,
        [string]$Shell,
        [string]$Run
    )

    $selectedSteps = @($Steps | Where-Object { $_.Name -ceq $Name })
    if ($selectedSteps.Count -ne 1) {
        Add-Failure "Workflow job '$JobName' must contain exactly one active step named '$Name' (found $($selectedSteps.Count))."
        return
    }
    $step = $selectedSteps[0]
    if ($step.ShellCount -ne 1 -or
        $step.RunCount -ne 1 -or
        $step.UsesCount -ne 0) {
        Add-Failure "Workflow job '$JobName' step '$Name' must contain exactly one shell/run and no uses key."
    }
    if (-not $step.Shell.Equals(
        $Shell,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Add-Failure "Workflow job '$JobName' step '$Name' must use shell '$Shell' (found '$($step.Shell)')."
    }
    if ($step.Run -cne $Run) {
        Add-Failure "Workflow job '$JobName' step '$Name' must run '$Run' (found '$($step.Run)')."
    }
}

function Assert-WorkflowUsesStep {
    param(
        [object[]]$Steps,
        [string]$JobName,
        [string]$Name,
        [string]$Uses
    )

    $selectedSteps = @($Steps | Where-Object { $_.Name -ceq $Name })
    if ($selectedSteps.Count -ne 1) {
        Add-Failure "Workflow job '$JobName' must contain exactly one active step named '$Name' (found $($selectedSteps.Count))."
        return
    }
    $step = $selectedSteps[0]
    if ($step.UsesCount -ne 1 -or
        $step.ShellCount -ne 0 -or
        $step.RunCount -ne 0) {
        Add-Failure "Workflow job '$JobName' step '$Name' must contain exactly one uses key and no shell/run key."
    }
    if ($step.Uses -cne $Uses) {
        Add-Failure "Workflow job '$JobName' step '$Name' must use '$Uses' (found '$($step.Uses)')."
    }
}

function Assert-WorkflowCanonicalSource {
    param([string]$RelativePath)

    $actual = Get-RepoUtf8Text -RelativePath $RelativePath
    $expected = @'
name: Validate

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read

jobs:
  validate:
    name: Validate skill repository
    # windows-latest is intentional: this job verifies both the current pwsh
    # runtime and the Windows PowerShell 5.1 / Job Object boundary supplied by
    # the hosted Windows image. The self-test owns those compatibility checks.
    runs-on: windows-latest
    timeout-minutes: 10
    steps:
      - name: Check out repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5

      - name: Validate OSS readiness
        shell: pwsh
        run: ./scripts/validate-oss-readiness.ps1

      - name: Test private marker scan (PowerShell 7)
        shell: pwsh
        run: ./scripts/test-scan-private-markers.ps1

      - name: Test private marker scan (Windows PowerShell 5.1)
        shell: powershell
        run: .\scripts\test-scan-private-markers.ps1

      - name: Scan for private markers
        shell: pwsh
        run: ./scripts/scan-private-markers.ps1

      - name: Check whitespace
        shell: pwsh
        # A fresh checkout has no worktree/index diff, so `git diff --check`
        # would be vacuous here. Diff the committed tree against the empty
        # tree (the SHA-1 empty-tree constant) so whitespace errors in
        # committed content actually fail the job (exit 2 on findings).
        run: git diff-tree -r --check 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD

  validate-ubuntu:
    name: Validate POSIX process containment
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - name: Check out repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5

      - name: Validate OSS readiness
        shell: pwsh
        run: ./scripts/validate-oss-readiness.ps1

      - name: Test private marker scan (PowerShell 7 on Ubuntu)
        shell: pwsh
        run: ./scripts/test-scan-private-markers.ps1

      - name: Scan for private markers
        shell: pwsh
        run: ./scripts/scan-private-markers.ps1

      - name: Check whitespace
        shell: pwsh
        run: git diff-tree -r --check 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD
'@
    $actualNormalized = $actual.Replace("`r`n", "`n").TrimEnd(
        [char]13,
        [char]10
    )
    $expectedNormalized = $expected.Replace("`r`n", "`n").TrimEnd(
        [char]13,
        [char]10
    )
    if ($actualNormalized -cne $expectedNormalized) {
        Add-Failure 'Workflow source must match the reviewed canonical form exactly; quoted/flow keys and unconsumed active indentation are forbidden.'
    }
}

function Assert-WorkflowContract {
    param([string]$RelativePath)

    $checkoutRevision =
        'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09'
    Assert-WorkflowCanonicalSource -RelativePath $RelativePath
    Assert-WorkflowEnvelope -RelativePath $RelativePath
    Assert-WorkflowJobSet `
        -RelativePath $RelativePath `
        -ExpectedJobNames @('validate', 'validate-ubuntu')

    $windowsJobName = 'validate'
    $windowsJobLines = @(Get-WorkflowJobLines `
        -RelativePath $RelativePath `
        -JobName $windowsJobName)
    $windowsSteps = @(Get-WorkflowSteps `
        -Lines $windowsJobLines `
        -JobName $windowsJobName)
    Assert-WorkflowJobValue `
        -Lines $windowsJobLines `
        -JobName $windowsJobName `
        -Key 'name' `
        -ExpectedValue 'Validate skill repository'
    Assert-WorkflowJobValue `
        -Lines $windowsJobLines `
        -JobName $windowsJobName `
        -Key 'runs-on' `
        -ExpectedValue 'windows-latest'
    Assert-WorkflowJobValue `
        -Lines $windowsJobLines `
        -JobName $windowsJobName `
        -Key 'timeout-minutes' `
        -ExpectedValue '10'
    Assert-WorkflowStepCount `
        -Steps $windowsSteps `
        -JobName $windowsJobName `
        -ExpectedCount 6
    Assert-WorkflowJobShape `
        -Lines $windowsJobLines `
        -JobName $windowsJobName `
        -ExpectedStepCount 6 `
        -ExpectedShellCount 5 `
        -ExpectedRunCount 5
    Assert-WorkflowUsesStep `
        -Steps $windowsSteps `
        -JobName $windowsJobName `
        -Name 'Check out repository' `
        -Uses $checkoutRevision
    Assert-WorkflowStep `
        -Steps $windowsSteps `
        -JobName $windowsJobName `
        -Name 'Validate OSS readiness' `
        -Shell 'pwsh' `
        -Run './scripts/validate-oss-readiness.ps1'
    Assert-WorkflowStep `
        -Steps $windowsSteps `
        -JobName $windowsJobName `
        -Name 'Test private marker scan (PowerShell 7)' `
        -Shell 'pwsh' `
        -Run './scripts/test-scan-private-markers.ps1'
    Assert-WorkflowStep `
        -Steps $windowsSteps `
        -JobName $windowsJobName `
        -Name 'Test private marker scan (Windows PowerShell 5.1)' `
        -Shell 'powershell' `
        -Run '.\scripts\test-scan-private-markers.ps1'
    Assert-WorkflowStep `
        -Steps $windowsSteps `
        -JobName $windowsJobName `
        -Name 'Scan for private markers' `
        -Shell 'pwsh' `
        -Run './scripts/scan-private-markers.ps1'
    Assert-WorkflowStep `
        -Steps $windowsSteps `
        -JobName $windowsJobName `
        -Name 'Check whitespace' `
        -Shell 'pwsh' `
        -Run 'git diff-tree -r --check 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD'

    $ubuntuJobName = 'validate-ubuntu'
    $ubuntuJobLines = @(Get-WorkflowJobLines `
        -RelativePath $RelativePath `
        -JobName $ubuntuJobName)
    $ubuntuSteps = @(Get-WorkflowSteps `
        -Lines $ubuntuJobLines `
        -JobName $ubuntuJobName)
    Assert-WorkflowJobValue `
        -Lines $ubuntuJobLines `
        -JobName $ubuntuJobName `
        -Key 'name' `
        -ExpectedValue 'Validate POSIX process containment'
    Assert-WorkflowJobValue `
        -Lines $ubuntuJobLines `
        -JobName $ubuntuJobName `
        -Key 'runs-on' `
        -ExpectedValue 'ubuntu-24.04'
    Assert-WorkflowJobValue `
        -Lines $ubuntuJobLines `
        -JobName $ubuntuJobName `
        -Key 'timeout-minutes' `
        -ExpectedValue '10'
    Assert-WorkflowStepCount `
        -Steps $ubuntuSteps `
        -JobName $ubuntuJobName `
        -ExpectedCount 5
    Assert-WorkflowJobShape `
        -Lines $ubuntuJobLines `
        -JobName $ubuntuJobName `
        -ExpectedStepCount 5 `
        -ExpectedShellCount 4 `
        -ExpectedRunCount 4
    Assert-WorkflowUsesStep `
        -Steps $ubuntuSteps `
        -JobName $ubuntuJobName `
        -Name 'Check out repository' `
        -Uses $checkoutRevision
    Assert-WorkflowStep `
        -Steps $ubuntuSteps `
        -JobName $ubuntuJobName `
        -Name 'Validate OSS readiness' `
        -Shell 'pwsh' `
        -Run './scripts/validate-oss-readiness.ps1'
    Assert-WorkflowStep `
        -Steps $ubuntuSteps `
        -JobName $ubuntuJobName `
        -Name 'Test private marker scan (PowerShell 7 on Ubuntu)' `
        -Shell 'pwsh' `
        -Run './scripts/test-scan-private-markers.ps1'
    Assert-WorkflowStep `
        -Steps $ubuntuSteps `
        -JobName $ubuntuJobName `
        -Name 'Scan for private markers' `
        -Shell 'pwsh' `
        -Run './scripts/scan-private-markers.ps1'
    Assert-WorkflowStep `
        -Steps $ubuntuSteps `
        -JobName $ubuntuJobName `
        -Name 'Check whitespace' `
        -Shell 'pwsh' `
        -Run 'git diff-tree -r --check 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD'

    # workflow内の全 third-party action は tag/branchではなく40桁SHAだけを
    # 許可する。job shapeがuses数も固定するため、追加actionも同時に拒否する。
    $workflowSource = Get-RepoUtf8Text -RelativePath $RelativePath
    $usesLines = @(
        $workflowSource -split '\r?\n' |
            Where-Object { $_ -match '^        uses:[ \t]*' }
    )
    $pinnedUsesLines = @(
        $usesLines | Where-Object {
            $_ -match (
                '^        uses:[ \t]*' +
                '[A-Za-z0-9_.-]+/[A-Za-z0-9_.\-/]+@' +
                '[0-9a-f]{40}[ \t]*(?:#.*)?$'
            )
        }
    )
    if ($usesLines.Count -ne 2 -or
        $pinnedUsesLines.Count -ne $usesLines.Count) {
        Add-Failure 'Workflow must contain exactly two third-party action uses, each pinned to a full 40-character SHA.'
    }
}

function Test-WorkflowContractMutationGuards {
    param([string]$RelativePath)

    $source = Get-RepoUtf8Text -RelativePath $RelativePath
    $newline = if ($source.Contains("`r`n")) { "`r`n" } else { "`n" }
    $cases = @(
        [pscustomobject]@{
            Name = 'extra-top-level-key'
            Source = $source + $newline + 'concurrency: synthetic' + $newline
        },
        [pscustomobject]@{
            Name = 'quoted-top-level-key'
            Source = $source.Replace(
                'permissions:',
                '"permissions":'
            )
        },
        [pscustomobject]@{
            Name = 'extra-trigger'
            Source = $source.Replace(
                "  pull_request:$newline",
                "  pull_request:$newline  schedule:$newline"
            )
        },
        [pscustomobject]@{
            Name = 'permission-escalation'
            Source = $source.Replace(
                '  contents: read',
                '  contents: write'
            )
        },
        [pscustomobject]@{
            Name = 'extra-job'
            Source = $source + (
                "${newline}  synthetic-job:${newline}" +
                "    name: Synthetic${newline}" +
                "    runs-on: ubuntu-24.04${newline}" +
                "    timeout-minutes: 10${newline}" +
                "    steps:${newline}"
            )
        },
        [pscustomobject]@{
            Name = 'quoted-job-key'
            Source = $source.Replace(
                '  validate:',
                "  'validate':"
            )
        },
        [pscustomobject]@{
            Name = 'flow-extra-job'
            Source = $source.Replace(
                'jobs:',
                'jobs: { synthetic: { runs-on: ubuntu-24.04, steps: [] } }'
            )
        },
        [pscustomobject]@{
            Name = 'job-level-permission'
            Source = $source.Replace(
                "    timeout-minutes: 10${newline}    steps:",
                (
                    "    timeout-minutes: 10${newline}" +
                    "    permissions:${newline}" +
                    "      contents: read${newline}" +
                    '    steps:'
                )
            )
        },
        [pscustomobject]@{
            Name = 'extra-step'
            Source = $source.Replace(
                "      - name: Validate OSS readiness${newline}",
                (
                    "      - name: Synthetic extra${newline}" +
                    "        shell: pwsh${newline}" +
                    "        run: ./synthetic.ps1${newline}${newline}" +
                    "      - name: Validate OSS readiness${newline}"
                )
            )
        },
        [pscustomobject]@{
            Name = 'unnamed-step'
            Source = $source.Replace(
                '      - name: Validate OSS readiness',
                '      - run: ./scripts/validate-oss-readiness.ps1'
            )
        },
        [pscustomobject]@{
            Name = 'duplicate-step-property'
            Source = $source.Replace(
                (
                    "      - name: Validate OSS readiness${newline}" +
                    '        shell: pwsh'
                ),
                (
                    "      - name: Validate OSS readiness${newline}" +
                    "        shell: pwsh${newline}" +
                    '        shell: pwsh'
                )
            )
        },
        [pscustomobject]@{
            Name = 'unconsumed-active-indentation'
            Source = $source.Replace(
                (
                    "      - name: Validate OSS readiness${newline}" +
                    "        shell: pwsh${newline}" +
                    '        run: ./scripts/validate-oss-readiness.ps1'
                ),
                (
                    "      - name: Validate OSS readiness${newline}" +
                    "        shell: pwsh${newline}" +
                    "        run: ./scripts/validate-oss-readiness.ps1${newline}" +
                    "        env:${newline}" +
                    '          SYNTHETIC_ACTIVE: value'
                )
            )
        },
        [pscustomobject]@{
            Name = 'runner-drift'
            Source = $source.Replace(
                '    runs-on: windows-latest',
                '    runs-on: windows-2022'
            )
        },
        [pscustomobject]@{
            Name = 'timeout-drift'
            Source = $source.Replace(
                '    timeout-minutes: 10',
                '    timeout-minutes: 11'
            )
        },
        [pscustomobject]@{
            Name = 'checkout-tag'
            Source = $source.Replace(
                'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
                'actions/checkout@v5'
            )
        }
    )

    $undetectedCases = New-Object System.Collections.Generic.List[string]
    $originalFailures = $script:failures
    try {
        foreach ($case in $cases) {
            $fixturePath = Join-Path (
                [System.IO.Path]::GetTempPath()
            ) (
                '036-workflow-validator-' +
                [System.Guid]::NewGuid().ToString('N') +
                '.yml'
            )
            try {
                [System.IO.File]::WriteAllText(
                    $fixturePath,
                    $case.Source,
                    [System.Text.UTF8Encoding]::new($false)
                )
                $script:failures =
                    New-Object System.Collections.Generic.List[string]
                Assert-WorkflowContract -RelativePath $fixturePath
                if ($script:failures.Count -eq 0) {
                    $undetectedCases.Add($case.Name) | Out-Null
                }
            }
            finally {
                if ([System.IO.File]::Exists($fixturePath)) {
                    [System.IO.File]::Delete($fixturePath)
                }
            }
        }
    }
    finally {
        $script:failures = $originalFailures
    }
    foreach ($caseName in $undetectedCases) {
        Add-Failure "Workflow validator mutation was not rejected: $caseName."
    }
}

function Test-ContainsMixedPermissionConfigFence {
    param([string[]]$Lines)

    # Permission profiles and the legacy sandbox settings are separate
    # configuration systems. Walk Markdown fences so a future copy-paste
    # example cannot make the selected permission profile ineffective.
    $insideFence = $false
    $fenceCharacter = ''
    $fenceLength = 0
    $fenceLines = New-Object System.Collections.Generic.List[string]

    foreach ($line in $Lines) {
        if (-not $insideFence) {
            if ($line -match '^ {0,3}(`{3,}|~{3,})(.*)$') {
                $insideFence = $true
                $fenceCharacter = $Matches[1].Substring(0, 1)
                $fenceLength = $Matches[1].Length
                $fenceLines.Clear()
            }
            continue
        }

        if ($line -match '^ {0,3}(`{3,}|~{3,})(.*)$' -and
            $Matches[1].Substring(0, 1) -eq $fenceCharacter -and
            $Matches[1].Length -ge $fenceLength -and
            [string]::IsNullOrWhiteSpace($Matches[2])) {
            $fenceText = $fenceLines -join "`n"
            $hasLegacySettings = (
                $fenceText -match '(?m)^\s*sandbox_mode\s*=' -or
                $fenceText -match '(?m)^\s*\[sandbox_workspace_write(?:\.|\])'
            )
            $hasPermissionProfile = (
                $fenceText -match '(?m)^\s*default_permissions\s*=' -or
                $fenceText -match '(?m)^\s*\[permissions(?:\.|\])'
            )
            if ($hasLegacySettings -and $hasPermissionProfile) {
                return $true
            }
            $insideFence = $false
            $fenceCharacter = ''
            $fenceLength = 0
            $fenceLines.Clear()
            continue
        }

        $fenceLines.Add($line) | Out-Null
    }

    return $false
}

function Assert-NoMixedPermissionConfigFence {
    param([string]$RelativePath)

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing file: $RelativePath (permission config examples)"
        return
    }

    try {
        $lines = [System.IO.File]::ReadAllLines(
            $filePath,
            (New-Object System.Text.UTF8Encoding($false, $true))
        )
    }
    catch {
        Add-Failure "$RelativePath must be valid UTF-8 (permission config examples)"
        return
    }

    if (Test-ContainsMixedPermissionConfigFence -Lines $lines) {
        Add-Failure "$RelativePath contains a fenced example that mixes legacy sandbox settings with permission profiles."
    }
}

function Test-PermissionConfigFenceGuard {
    # Pin every selector/table combination. A one-sided check can otherwise
    # miss three valid spellings of the same unsupported mixed configuration.
    $cases = @(
        @{
            Name = 'sandbox_mode plus default_permissions'
            Lines = @('```toml', 'sandbox_mode = "workspace-write"', 'default_permissions = ":workspace"', '```')
            Expected = $true
        },
        @{
            Name = 'sandbox_mode plus permissions table'
            Lines = @('```toml', 'sandbox_mode = "workspace-write"', '[permissions.dev]', 'extends = ":workspace"', '```')
            Expected = $true
        },
        @{
            Name = 'sandbox_workspace_write plus default_permissions'
            Lines = @('```toml', 'default_permissions = ":workspace"', '[sandbox_workspace_write]', 'network_access = false', '```')
            Expected = $true
        },
        @{
            Name = 'sandbox_workspace_write plus permissions table'
            Lines = @('```toml', '[permissions.dev]', 'extends = ":workspace"', '[sandbox_workspace_write]', 'network_access = false', '```')
            Expected = $true
        },
        @{
            Name = 'permission profile only'
            Lines = @('```toml', 'default_permissions = "dev"', '[permissions.dev]', 'extends = ":workspace"', '```')
            Expected = $false
        },
        @{
            Name = 'legacy settings only'
            Lines = @('```toml', 'sandbox_mode = "workspace-write"', '[sandbox_workspace_write]', 'network_access = false', '```')
            Expected = $false
        }
    )

    foreach ($case in $cases) {
        $actual = Test-ContainsMixedPermissionConfigFence -Lines $case.Lines
        if ($actual -ne $case.Expected) {
            Add-Failure "Permission config fence guard failed synthetic case: $($case.Name)"
        }
    }
}

function Test-SkillFrontmatter {
    $skillPath = Get-RepoFilePath -RelativePath 'SKILL.md'
    if (-not (Test-Path -LiteralPath $skillPath -PathType Leaf)) {
        return
    }

    try {
        $lines = [System.IO.File]::ReadAllLines(
            $skillPath,
            (New-Object System.Text.UTF8Encoding($false, $true))
        )
    }
    catch {
        Add-Failure 'SKILL.md must be valid UTF-8.'
        return
    }
    if ($lines.Count -lt 4 -or $lines[0] -ne '---') {
        Add-Failure 'SKILL.md must start with YAML frontmatter.'
        return
    }

    $closingIndex = -1
    for ($index = 1; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -eq '---') {
            $closingIndex = $index
            break
        }
    }

    if ($closingIndex -lt 0) {
        Add-Failure 'SKILL.md frontmatter must be closed with --- before content.'
        return
    }

    $frontmatter = $lines[1..($closingIndex - 1)] -join "`n"
    if ($frontmatter -notmatch '(?m)^name:\s*codex-windows-sandbox-troubleshooting\s*$') {
        Add-Failure 'SKILL.md frontmatter must declare name: codex-windows-sandbox-troubleshooting.'
    }
    if ($frontmatter -notmatch '(?m)^description:\s*\S') {
        Add-Failure 'SKILL.md frontmatter must include a non-empty description.'
    }
    if ($frontmatter.Length -gt 1024) {
        Add-Failure 'SKILL.md frontmatter must stay under 1024 characters.'
    }
}

$requiredFiles = @(
    '.editorconfig',
    '.gitattributes',
    '.gitignore',
    '.github/ISSUE_TEMPLATE/bug_report.yml',
    '.github/ISSUE_TEMPLATE/config.yml',
    '.github/pull_request_template.md',
    '.github/workflows/validate.yml',
    'CHANGELOG.md',
    'CODE_OF_CONDUCT.md',
    'CONTRIBUTING.md',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'SKILL.md',
    'docs/SKILL.ja.md',
    'examples/layer-triage-checklist.md',
    'examples/cli-bisect-commands.md',
    'examples/config-toml-permissions.md',
    'scripts/private-marker-process.ps1',
    'scripts/scan-private-markers.ps1',
    'scripts/test-scan-private-markers.ps1',
    'scripts/validate-oss-readiness.ps1'
)

foreach ($requiredFile in $requiredFiles) {
    Assert-FileExists -RelativePath $requiredFile
}

Assert-FileContains -RelativePath 'README.md' -Pattern '(?im)^##\s+Install' -Description 'installation instructions'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?im)^##\s+Validation' -Description 'validation instructions'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?im)^##\s+Contributing' -Description 'contribution guidance'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?im)^##\s+Security' -Description 'security reporting guidance'
Assert-FileContains -RelativePath 'README.md' -Pattern 'CONTRIBUTING\.md' -Description 'link to CONTRIBUTING.md'
Assert-FileContains -RelativePath 'README.md' -Pattern 'SECURITY\.md' -Description 'link to SECURITY.md'
Assert-FileContains -RelativePath 'README.md' -Pattern 'docs/SKILL\.ja\.md' -Description 'link to the Japanese skill version'
Assert-FileContains -RelativePath '.gitignore' -Pattern '\.private-markers\.local' -Description 'ignore local private marker files'
Assert-FileContains -RelativePath 'CONTRIBUTING.md' -Pattern '(?im)no token or secret value ever belongs' -Description 'secret-safe contribution guidance'
Assert-FileContains -RelativePath 'SECURITY.md' -Pattern '(?im)private vulnerability reporting' -Description 'private vulnerability reporting guidance'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'private-marker-process\.ps1' -Description 'shared bounded process boundary in scanner'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'private-marker-process\.ps1' -Description 'shared bounded process boundary in scanner self-test'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'PosixSignal.*IsSuccessfulResult' -Description 'POSIX cleanup result regression coverage'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'CODEX_WINDOWS_SANDBOX_TROUBLESHOOTING_PRIVATE_MARKERS' -Description '036 local marker environment contract'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'h8nc4y/codex-windows-sandbox-troubleshooting' -Description '036 repository URL allowlist'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'openai/codex' -Description 'upstream Codex URL allowlist'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern '\[object\[\]\]\$ScannerArguments\s*=\s*@\(\$args\)' -Description 'binder-free raw public invocation boundary'
Assert-FileDoesNotContain -RelativePath 'scripts/scan-private-markers.ps1' -Pattern '\A(?:\uFEFF)?\s*(?:\[CmdletBinding\(\)\]|param\s*\()' -Description 'public PowerShell binder before fixed diagnostics'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern '(?s)\[int\]::TryParse\(.*?\[ref\]\$parsedScanDeadline.*?\$parsedScanDeadline\s+-lt\s+1.*?\$parsedScanDeadline\s+-gt\s+120000' -Description 'fixed scan-wide deadline parser range'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'Private marker scan failed closed \(integrity: invocation-contract\)\.' -Description 'fixed public invocation failure'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'Private marker scan failed closed \(integrity: scanner-boundary\)\.' -Description 'fixed outer scanner boundary failure'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'maximumFindingOutputBytes' -Description 'actual UTF-8 finding output cap'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern '(?s)\[Console\]::OutputEncoding\s*=\s*New-Object System\.Text\.UTF8Encoding\(\$false\)' -Description 'BOM-less UTF-8 Console.Out contract'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern "Stop-PrivateMarkerIntegrityFailure -Reason 'git-probe'" -Description 'fixed Git metadata probe failure'
Assert-FinalScanDeadlineContract -RelativePath 'scripts/scan-private-markers.ps1'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'LastSyntheticFailureProcessId' -Description 'Windows synthetic launch-failure PID probe'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern "ValidateSet\('', 'assign', 'resume', 'close'\)" -Description 'Windows launch-failure selectors'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'ConfigureSyntheticCloseFailures' -Description 'Windows synthetic Job close-failure seam'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'LastDisposedStandardStreamCount' -Description 'explicit standard-stream disposal evidence'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'LastLaunchCleanupFailureCount' -Description 'aggregated Windows launch cleanup evidence'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'TryCloseOwnedHandle' -Description 'non-short-circuiting native handle cleanup'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'TryDisposeOwned' -Description 'non-short-circuiting stream and safe-handle cleanup'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'ProcessBoundary\.Close\(processHandle\)' -Description 'verified process-handle cleanup aggregation'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern '\$Environment\.Clear\(\)' -Description 'hermetic child environment reset'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern '\[string\]\$ExecutablePath' -Description 'executable-derived hermetic PATH allowlist'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'Fallback process termination failed' -Description 'verified Windows terminate fallback'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'Launch-failure cleanup exceeded 5000 ms' -Description 'bounded Windows launch-failure wait'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'CreateProcessW' -Description 'direct binary-safe Windows process launch'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'new byte\[8192\]' -Description 'fixed-size raw stream buffer'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern '(?s)\$clock = \[System\.Diagnostics\.Stopwatch\]::StartNew\(\).*?\$containedProcess = \[PrivateMarker\.ContainedProcess\]::Start\(' -Description 'timeout clock before Windows launch'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern '(?s)\$clock = \[System\.Diagnostics\.Stopwatch\]::StartNew\(\).*?\$processStarted = \$process\.Start\(\)' -Description 'timeout clock before POSIX launch'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern '\$clock\.ElapsedMilliseconds -lt \$TimeoutMilliseconds;' -Description 'POSIX gate deadline ownership'
Assert-FileMatchCount -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'if \(\$clock\.ElapsedMilliseconds -ge \$TimeoutMilliseconds\)' -ExpectedCount 2 -Description 'initial and post-cleanup elapsed-only deadline rejection'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'TestOnlyPostExitDelayMilliseconds' -Description 'deterministic post-exit deadline regression seam'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'TestOnlyExpireDeadlineAfterInitialCheck' -Description 'post-stream cleanup deadline regression seam'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'foreach \(\$launchFailureMode in @\(' -Description 'Windows launch-failure cleanup regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '(?s)invalid-\$metadataScope-git-metadata-\$metadataKind.*expectedGitMetadataDiagnostic' -Description 'root and ancestor Git metadata regressions'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'linked-worktree-source' -Description 'Git-proven linked worktree control-file regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'uppercase-git-entry' -Description 'OS-aware .git versus .GIT regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'synthetic_nested_git_directory_marker' -Description 'nested Git directory exclusion regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'scan-diagnostic-output-limit' -Description 'finding output amplification regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'invalidInvocationCases' -Description 'fixed public invocation failure regressions'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'missingHelperResult' -Description 'fixed helper-load boundary regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'isolationCreateResult' -Description 'fixed isolation-create boundary regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'hermeticEnvironmentResult' -Description 'runtime hermetic environment allowlist regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'Test-FirstProcessInvocationIsRawTransport' -Description 'first eager process-call AST ownership validator'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'Test-FirstProcessInvocationPolicy' -Description 'shared AST-first process ownership policy'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'safe-application-get-command' -Description 'safe native application resolution AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'dynamic-scriptblock-get-variable-foreach' -Description 'runtime ScriptBlock AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'ambient-scriptblock-get-variable-foreach' -Description 'ambient ScriptBlock AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'ambient-scriptblock-sort-property' -Description 'indirect property ScriptBlock AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'unknown-scriptblock-consumer' -Description 'positive eager command-set AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'unknown-scriptblock-consumer-wrapper' -Description 'positive wrapper command-set AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'unknown-scriptblock-member-execute' -Description 'positive member invocation-set AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'ambient-allowlisted-member-find-all' -Description 'receiver-bound member invocation AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'assigned-ambient-allowlisted-receiver' -Description 'receiver assignment provenance AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'ambient-foreach-allowlisted-receiver' -Description 'foreach enumeration provenance AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'Test-PrivateMarkerAssignmentDominatesReference' -Description 'receiver assignment dominance classifier'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'conditional-assignment-allowlisted-receiver' -Description 'conditional receiver assignment AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'zero-iteration-assignment-allowlisted-receiver' -Description 'zero-iteration receiver assignment AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'untyped-parameter-allowlisted-receiver' -Description 'receiver parameter provenance AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'module-qualified-raw-target' -Description 'module-qualified raw target AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'global-qualified-raw-target' -Description 'global-qualified raw target AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'local-function-call-before-definition' -Description 'definition-order AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'conditional-local-function-definition' -Description 'unconditional definition ownership AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'Test-PrivateMarkerMemberCanInvokeStoredCode' -Description 'stored-code member invocation classifier'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'dynamic-new-item-provider' -Description 'dynamic provider mutation AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'InvokeMemberExpressionAst' -Description 'invoked scriptblock AST classification'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '\.InvokeReturnAsIs\(\)' -Description 'InvokeReturnAsIs AST regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '\[byte\[\]\]\$rawTransportInput' -Description 'exact binary standard-stream fixture'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'native git cat-file batch transport' -Description 'native Git byte-exact stdin/stdout fixture'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'InputEncoding\.GetPreamble' -Description 'caller console input encoding restoration regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'worktree-mutation' -Description 'working-tree TOCTOU regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'local-marker-mutation' -Description 'local marker TOCTOU regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'initial dangling local-marker leaf' -Description 'dangling local marker entry regression'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'Get-PrivateMarkerLocalLeaf' -Description 'non-following local marker entry lookup'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '\$scannerTempRoot' -Description 'suite-owned scanner temp namespace'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '\$foreignScannerIsolationRoot' -Description 'parallel scanner temp ownership regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'backslash-name fixture' -Description 'backslash Git path regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'post-exit delay deadline' -Description 'already-exited process deadline regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'post-stream cleanup deadline' -Description 'post-cleanup process deadline regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'process timeout clock to own launch' -Description 'process launch and success deadline source-order regression'
Assert-FileMatchCount -RelativePath 'scripts/scan-private-markers.ps1' -Pattern '(?m)^\s*Assert-GitIndexSnapshotsUnchanged\s*$' -ExpectedCount 2 -Description 'pre- and post-content raw index snapshot verification'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'exactly three raw stage listings' -Description 'post-content index mutation regression'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'exactly three raw debug listings' -Description 'post-content index metadata mutation regression'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern '\$rootAnchor' -Description 'filesystem-root canonicalization preservation'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'InitialWorktreeBytes' -Description 'working-tree final byte snapshot'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'Tracked worktree file changed during the scan' -Description 'working-tree drift rejection'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'Local private marker presence changed during the scan' -Description 'local marker presence drift rejection'
Assert-FileContains -RelativePath 'scripts/scan-private-markers.ps1' -Pattern 'Local private marker content changed during the scan' -Description 'local marker byte drift rejection'
Assert-FileContains -RelativePath 'README.md' -Pattern '(?ms)^## Validation.*Windows PowerShell 5\.1.*UTF-8\s+BOM' -Description 'PowerShell 5.1 BOM exception in validation guidance'

Assert-FileHasUtf8Bom -RelativePath 'scripts/scan-private-markers.ps1'
Assert-FileHasUtf8Bom -RelativePath 'scripts/test-scan-private-markers.ps1'
Assert-FileHasUtf8Bom -RelativePath 'scripts/private-marker-process.ps1'
Assert-FileHasUtf8Bom -RelativePath 'scripts/validate-oss-readiness.ps1'

# job blockを切り出してrunner/timeout/stepを所有job内だけで検証し、
# duplicate、extra、unnamed、job跨ぎregexによる誤合格を拒否する。
$workflowPath = '.github/workflows/validate.yml'
Assert-WorkflowContract -RelativePath $workflowPath
Test-WorkflowContractMutationGuards -RelativePath $workflowPath

# Skill-specific invariants: the canonical error strings must stay verbatim in
# both language versions (they are what readers search for), and the
# no-sandbox-bypass safety posture must stay machine-checkable.
Assert-FileContains -RelativePath 'SKILL.md' -Pattern 'CreateProcessAsUserW failed: 5' -Description 'verbatim CreateProcessAsUserW error string'
Assert-FileContains -RelativePath 'SKILL.md' -Pattern "couldn't create signal pipe" -Description 'verbatim signal pipe error string'
Assert-FileContains -RelativePath 'SKILL.md' -Pattern 'SetNamedSecurityInfoW failed: 5' -Description 'verbatim SetNamedSecurityInfoW error string'
Assert-FileContains -RelativePath 'SKILL.md' -Pattern 'FilesystemPermissionToml' -Description 'verbatim config parse error enum name'
Assert-FileContains -RelativePath 'SKILL.md' -Pattern '(?im)does not recommend bypassing or disabling the sandbox' -Description 'no-sandbox-bypass safety posture statement'
Assert-FileContains -RelativePath 'SKILL.md' -Pattern '(?ims)permission profiles.*do not compose.*sandbox_mode' -Description 'permission profiles versus legacy sandbox settings contract'
Assert-FileContains -RelativePath 'docs/SKILL.ja.md' -Pattern 'CreateProcessAsUserW failed: 5' -Description 'verbatim CreateProcessAsUserW error string (Japanese version)'
Assert-FileContains -RelativePath 'docs/SKILL.ja.md' -Pattern 'FilesystemPermissionToml' -Description 'verbatim config parse error enum name (Japanese version)'
Assert-FileContains -RelativePath 'docs/SKILL.ja.md' -Pattern '(?ims)permission profile.*sandbox_mode.*併用' -Description 'permission profiles versus legacy sandbox settings contract (Japanese version)'

foreach ($permissionDocument in @(
    'SKILL.md',
    'docs/SKILL.ja.md',
    'examples/config-toml-permissions.md',
    'examples/layer-triage-checklist.md'
)) {
    Assert-NoMixedPermissionConfigFence -RelativePath $permissionDocument
}

Test-PermissionConfigFenceGuard
Test-SkillFrontmatter

if ($failures.Count -gt 0) {
    Write-Host 'OSS readiness validation failed:'
    foreach ($failure in $failures) {
        Write-Host "- $failure"
    }
    exit 1
}

Write-Host "OSS readiness validation passed for $root"
exit 0
