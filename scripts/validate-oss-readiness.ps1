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
    return Join-Path $root $RelativePath
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

    $content = Get-Content -LiteralPath $filePath -Raw
    if ($content -notmatch $Pattern) {
        Add-Failure "$RelativePath is missing: $Description"
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

    if (Test-ContainsMixedPermissionConfigFence -Lines (Get-Content -LiteralPath $filePath)) {
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

    $lines = Get-Content -LiteralPath $skillPath
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
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern 'validate-oss-readiness\.ps1' -Description 'OSS readiness validation in CI'
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern 'scan-private-markers\.ps1' -Description 'private marker scan in CI'
Assert-FileContains -RelativePath '.github/workflows/validate.yml' -Pattern 'test-scan-private-markers\.ps1' -Description 'private marker scan self-test in CI'

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
