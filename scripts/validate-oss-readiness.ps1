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

function Test-NativePosixGateWrapperContract {
    param([string]$Source)

    $ordinal = [System.StringComparison]::Ordinal
    $equalsOrdinal = {
        param($Actual, [string]$Expected)
        return [string]::Equals(
            [string]$Actual,
            $Expected,
            $ordinal
        )
    }
    $nearestFunctionOwner = {
        param($Node)
        $cursor = $Node.Parent
        while ($null -ne $cursor) {
            if ($cursor -is
                [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
                return $null
            }
            if ($cursor -is
                [System.Management.Automation.Language.FunctionDefinitionAst]) {
                return $cursor
            }
            $cursor = $cursor.Parent
        }
        return $null
    }
    $directInvocation = {
        param($Statement)
        if ($Statement -isnot
            [System.Management.Automation.Language.PipelineAst] -or
            $Statement.PipelineElements.Count -ne 1) {
            return $null
        }
        $commandExpression = $Statement.PipelineElements[0]
        if ($commandExpression -isnot
            [System.Management.Automation.Language.CommandExpressionAst] -or
            $commandExpression.Expression -isnot
                [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            return $null
        }
        return $commandExpression.Expression
    }
    $variableName = {
        param($Ast, [string]$Expected)
        return (
            $Ast -is
                [System.Management.Automation.Language.VariableExpressionAst] -and
            (& $equalsOrdinal $Ast.VariablePath.UserPath $Expected)
        )
    }
    $base64AssignmentContract = {
        param(
            $Assignment,
            [string]$TargetVariable,
            [string]$SourceVariable
        )
        if ($Assignment -isnot
            [System.Management.Automation.Language.AssignmentStatementAst] -or
            -not (& $variableName $Assignment.Left $TargetVariable) -or
            $Assignment.Right -isnot
                [System.Management.Automation.Language.CommandExpressionAst] -or
            $Assignment.Right.Expression -isnot
                [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            return $false
        }
        $base64Call = $Assignment.Right.Expression
        if (-not $base64Call.Static -or
            $base64Call.Expression -isnot
                [System.Management.Automation.Language.TypeExpressionAst] -or
            -not (& $equalsOrdinal $base64Call.Expression.TypeName.FullName 'Convert') -or
            -not (& $equalsOrdinal $base64Call.Member.Value 'ToBase64String') -or
            $base64Call.Arguments.Count -ne 1 -or
            $base64Call.Arguments[0] -isnot
                [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            return $false
        }
        $getBytesCall = $base64Call.Arguments[0]
        if ($getBytesCall.Static -or
            -not (& $equalsOrdinal $getBytesCall.Member.Value 'GetBytes') -or
            $getBytesCall.Arguments.Count -ne 1 -or
            -not (& $variableName $getBytesCall.Arguments[0] $SourceVariable) -or
            $getBytesCall.Expression -isnot
                [System.Management.Automation.Language.MemberExpressionAst]) {
            return $false
        }
        $utf8Property = $getBytesCall.Expression
        return (
            $utf8Property.Static -and
            $utf8Property.Expression -is
                [System.Management.Automation.Language.TypeExpressionAst] -and
            (& $equalsOrdinal $utf8Property.Expression.TypeName.FullName 'System.Text.Encoding') -and
            (& $equalsOrdinal $utf8Property.Member.Value 'UTF8')
        )
    }
    $base64DecodeAssignmentContract = {
        param(
            $Assignment,
            [string]$TargetVariable,
            [string]$Placeholder
        )
        if ($Assignment -isnot
            [System.Management.Automation.Language.AssignmentStatementAst] -or
            -not (& $variableName $Assignment.Left $TargetVariable) -or
            $Assignment.Right -isnot
                [System.Management.Automation.Language.CommandExpressionAst] -or
            $Assignment.Right.Expression -isnot
                [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            return $false
        }
        $getStringCall = $Assignment.Right.Expression
        if ($getStringCall.Static -or
            -not (& $equalsOrdinal $getStringCall.Member.Value 'GetString') -or
            $getStringCall.Arguments.Count -ne 1 -or
            $getStringCall.Expression -isnot
                [System.Management.Automation.Language.MemberExpressionAst]) {
            return $false
        }
        $utf8Property = $getStringCall.Expression
        if (-not $utf8Property.Static -or
            $utf8Property.Expression -isnot
                [System.Management.Automation.Language.TypeExpressionAst] -or
            -not (& $equalsOrdinal $utf8Property.Expression.TypeName.FullName 'Text.Encoding') -or
            -not (& $equalsOrdinal $utf8Property.Member.Value 'UTF8') -or
            $getStringCall.Arguments[0] -isnot
                [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            return $false
        }
        $decodeCall = $getStringCall.Arguments[0]
        return (
            $decodeCall.Static -and
            $decodeCall.Expression -is
                [System.Management.Automation.Language.TypeExpressionAst] -and
            (& $equalsOrdinal $decodeCall.Expression.TypeName.FullName 'Convert') -and
            (& $equalsOrdinal $decodeCall.Member.Value 'FromBase64String') -and
            $decodeCall.Arguments.Count -eq 1 -and
            $decodeCall.Arguments[0] -is
                [System.Management.Automation.Language.StringConstantExpressionAst] -and
            (& $equalsOrdinal $decodeCall.Arguments[0].Value $Placeholder)
        )
    }

    # outer sourceもParser ASTを正本にし、comment内のwrapper/cleanup decoyを拒否する。
    $sourceTokens = $null
    $sourceParseErrors = $null
    $sourceAst =
        [System.Management.Automation.Language.Parser]::ParseInput(
            $Source,
            [ref]$sourceTokens,
            [ref]$sourceParseErrors
        )
    if ($sourceParseErrors.Count -ne 0) {
        return $false
    }
    $processFunctions = @(
        $sourceAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.FunctionDefinitionAst] -and
                [string]::Equals(
                    $node.Name,
                    'Invoke-PrivateMarkerProcess',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        )
    )
    if ($processFunctions.Count -ne 1 -or
        [System.Array]::IndexOf(
            @($sourceAst.EndBlock.Statements),
            $processFunctions[0]
        ) -lt 0) {
        return $false
    }
    $processFunction = $processFunctions[0]

    $wrapperAssignments = @(
        $sourceAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is
                    [System.Management.Automation.Language.VariableExpressionAst] -and
                [string]::Equals(
                    $node.Left.VariablePath.UserPath,
                    'posixWrapperTemplate',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        ) |
            Where-Object {
                [object]::ReferenceEquals(
                    (& $nearestFunctionOwner $_),
                    $processFunction
                )
            }
    )
    if ($wrapperAssignments.Count -ne 1) {
        return $false
    }
    $wrapperAssignment = $wrapperAssignments[0]
    if ($wrapperAssignment.Right -isnot
        [System.Management.Automation.Language.CommandExpressionAst] -or
        $wrapperAssignment.Right.Expression -isnot
            [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $wrapperAssignment.Right.Expression.StringConstantType -ne
            [System.Management.Automation.Language.StringConstantType]::SingleQuotedHereString) {
        return $false
    }
    $wrapperBlock = $wrapperAssignment.Parent
    $wrapperBlockStatements = @($wrapperBlock.Statements)
    $wrapperIndex =
        [System.Array]::IndexOf(
            $wrapperBlockStatements,
            $wrapperAssignment
        )
    if ($wrapperBlock -isnot
        [System.Management.Automation.Language.StatementBlockAst] -or
        $wrapperIndex -lt 1 -or
        $wrapperIndex -ge ($wrapperBlockStatements.Count - 1) -or
        $wrapperBlockStatements[$wrapperIndex - 1] -isnot
            [System.Management.Automation.Language.AssignmentStatementAst] -or
        -not (& $variableName $wrapperBlockStatements[$wrapperIndex - 1].Left 'testOnlyFailurePhaseBase64') -or
        $wrapperBlockStatements[$wrapperIndex + 1] -isnot
            [System.Management.Automation.Language.AssignmentStatementAst] -or
        -not (& $variableName $wrapperBlockStatements[$wrapperIndex + 1].Left 'posixWrapperScript')) {
        return $false
    }
    $wrapperScriptAssignment =
        $wrapperBlockStatements[$wrapperIndex + 1]

    # wrapper生成sequenceを実行される既知のelse/try経路へ固定する。
    # if(false)、loop、switch、nested try等でtextだけ残す変異を拒否する。
    $nativeGateChoiceIf = $wrapperBlock.Parent
    $posixHostElseBlock = $nativeGateChoiceIf.Parent
    $posixHostIf = $posixHostElseBlock.Parent
    $processTryBlock = $posixHostIf.Parent
    $processTry = $processTryBlock.Parent
    if ($nativeGateChoiceIf -isnot
        [System.Management.Automation.Language.IfStatementAst] -or
        -not [object]::ReferenceEquals(
            $nativeGateChoiceIf.ElseClause,
            $wrapperBlock
        ) -or
        $posixHostElseBlock -isnot
            [System.Management.Automation.Language.StatementBlockAst] -or
        $posixHostIf -isnot
            [System.Management.Automation.Language.IfStatementAst] -or
        -not [object]::ReferenceEquals(
            $posixHostIf.ElseClause,
            $posixHostElseBlock
        ) -or
        [System.Array]::IndexOf(
            @($posixHostElseBlock.Statements),
            $nativeGateChoiceIf
        ) -lt 0 -or
        $processTryBlock -isnot
            [System.Management.Automation.Language.StatementBlockAst] -or
        $processTry -isnot
            [System.Management.Automation.Language.TryStatementAst] -or
        -not [object]::ReferenceEquals($processTry.Body, $processTryBlock) -or
        [System.Array]::IndexOf(
            @($processTryBlock.Statements),
            $posixHostIf
        ) -lt 0 -or
        -not [object]::ReferenceEquals(
            $processTry.Parent,
            $processFunction.Body.EndBlock
        ) -or
        [System.Array]::IndexOf(
            @($processFunction.Body.EndBlock.Statements),
            $processTry
        ) -lt 0) {
        return $false
    }

    # 6個のbase64 source assignmentをwrapper直前のexact sequenceとして固定する。
    $expectedBase64Assignments = @(
        [pscustomobject]@{ Target = 'payloadBase64'; Source = 'payloadJson' }
        [pscustomobject]@{
            Target = 'readyPathBase64'
            Source = 'posixGateReadyPath'
        }
        [pscustomobject]@{
            Target = 'releasePathBase64'
            Source = 'posixGateReleasePath'
        }
        [pscustomobject]@{
            Target = 'statusPathBase64'
            Source = 'posixGateStatusPath'
        }
        [pscustomobject]@{
            Target = 'statusStagingPathBase64'
            Source = 'posixGateStatusStagingPath'
        }
        [pscustomobject]@{
            Target = 'testOnlyFailurePhaseBase64'
            Source = 'TestOnlyNativePosixGateFailurePhase'
        }
    )
    if ($wrapperIndex -lt $expectedBase64Assignments.Count) {
        return $false
    }
    for ($base64Index = 0;
        $base64Index -lt $expectedBase64Assignments.Count;
        $base64Index++) {
        $base64StatementIndex =
            $wrapperIndex - $expectedBase64Assignments.Count + $base64Index
        if (-not (& $base64AssignmentContract $wrapperBlockStatements[$base64StatementIndex] $expectedBase64Assignments[$base64Index].Target $expectedBase64Assignments[$base64Index].Source)) {
            return $false
        }
    }

    # successor RHSは6段のString.Replace chainだけを許可する。
    $replacePairs = @(
        [pscustomobject]@{
            Placeholder = '__PAYLOAD__'
            Source = 'payloadBase64'
        }
        [pscustomobject]@{
            Placeholder = '__TEST_ONLY_FAILURE_PHASE__'
            Source = 'testOnlyFailurePhaseBase64'
        }
        [pscustomobject]@{
            Placeholder = '__STATUS_STAGING_PATH__'
            Source = 'statusStagingPathBase64'
        }
        [pscustomobject]@{
            Placeholder = '__STATUS_PATH__'
            Source = 'statusPathBase64'
        }
        [pscustomobject]@{
            Placeholder = '__RELEASE_PATH__'
            Source = 'releasePathBase64'
        }
        [pscustomobject]@{
            Placeholder = '__READY_PATH__'
            Source = 'readyPathBase64'
        }
    )
    if ($wrapperScriptAssignment.Right -isnot
        [System.Management.Automation.Language.CommandExpressionAst]) {
        return $false
    }
    $replaceCursor = $wrapperScriptAssignment.Right.Expression
    foreach ($replacePair in $replacePairs) {
        if ($replaceCursor -isnot
            [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
            $replaceCursor.Static -or
            -not (& $equalsOrdinal $replaceCursor.Member.Value 'Replace') -or
            $replaceCursor.Arguments.Count -ne 2 -or
            $replaceCursor.Arguments[0] -isnot
                [System.Management.Automation.Language.StringConstantExpressionAst] -or
            -not (& $equalsOrdinal $replaceCursor.Arguments[0].Value $replacePair.Placeholder) -or
            -not (& $variableName $replaceCursor.Arguments[1] $replacePair.Source)) {
            return $false
        }
        $replaceCursor = $replaceCursor.Expression
    }
    if (-not (& $variableName $replaceCursor 'posixWrapperTemplate')) {
        return $false
    }
    $wrapper = $wrapperAssignment.Right.Expression.Value

    $cleanupForEachAsts = @(
        $sourceAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.ForEachStatementAst] -and
                [string]::Equals(
                    $node.Variable.VariablePath.UserPath,
                    'gatePath',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        ) |
            Where-Object {
                [object]::ReferenceEquals(
                    (& $nearestFunctionOwner $_),
                    $processFunction
                )
            }
    )
    if ($cleanupForEachAsts.Count -ne 1) {
        return $false
    }
    $cleanupForEach = $cleanupForEachAsts[0]
    $cleanupBlock = $cleanupForEach.Parent
    $cleanupTry = $cleanupBlock.Parent
    # cleanup collectionは @(<exact 4 variables>) というAST shape自体を固定する。
    # 変数をtext上に残したままindex/range/wrapperで実行対象から落とす変異を許さない。
    $cleanupCondition = $cleanupForEach.Condition
    if ($cleanupCondition -isnot
        [System.Management.Automation.Language.PipelineAst] -or
        $cleanupCondition.PipelineElements.Count -ne 1 -or
        $cleanupCondition.PipelineElements[0] -isnot
            [System.Management.Automation.Language.CommandExpressionAst] -or
        $cleanupCondition.PipelineElements[0].Expression -isnot
            [System.Management.Automation.Language.ArrayExpressionAst]) {
        return $false
    }
    $cleanupArrayExpression =
        $cleanupCondition.PipelineElements[0].Expression
    $cleanupArrayStatements =
        @($cleanupArrayExpression.SubExpression.Statements)
    if ($cleanupArrayStatements.Count -ne 1 -or
        $cleanupArrayStatements[0] -isnot
            [System.Management.Automation.Language.PipelineAst] -or
        $cleanupArrayStatements[0].PipelineElements.Count -ne 1 -or
        $cleanupArrayStatements[0].PipelineElements[0] -isnot
            [System.Management.Automation.Language.CommandExpressionAst] -or
        $cleanupArrayStatements[0].PipelineElements[0].Expression -isnot
            [System.Management.Automation.Language.ArrayLiteralAst]) {
        return $false
    }
    $cleanupVariables = @(
        $cleanupArrayStatements[0].PipelineElements[0].Expression.Elements
    )
    $expectedCleanupVariables = @(
        'posixGateReadyPath',
        'posixGateReleasePath',
        'posixGateStatusPath',
        'posixGateStatusStagingPath'
    )
    if ($cleanupBlock -isnot
        [System.Management.Automation.Language.StatementBlockAst] -or
        $cleanupTry -isnot
            [System.Management.Automation.Language.TryStatementAst] -or
        -not [object]::ReferenceEquals($cleanupTry, $processTry) -or
        -not [object]::ReferenceEquals(
            $cleanupTry.Finally,
            $cleanupBlock
        ) -or
        [System.Array]::IndexOf(
            @($cleanupBlock.Statements),
            $cleanupForEach
        ) -ne ($cleanupBlock.Statements.Count - 1) -or
        $cleanupVariables.Count -ne $expectedCleanupVariables.Count) {
        return $false
    }
    for ($cleanupIndex = 0;
        $cleanupIndex -lt $expectedCleanupVariables.Count;
        $cleanupIndex++) {
        if ($cleanupVariables[$cleanupIndex] -isnot
            [System.Management.Automation.Language.VariableExpressionAst]) {
            return $false
        }
        if (-not (& $equalsOrdinal $cleanupVariables[$cleanupIndex].VariablePath.UserPath $expectedCleanupVariables[$cleanupIndex])) {
            return $false
        }
    }

    # cleanup bodyもguard -> try -> direct Delete -> empty catchだけへ閉じる。
    $cleanupBodyStatements = @($cleanupForEach.Body.Statements)
    if ($cleanupBodyStatements.Count -ne 1 -or
        $cleanupBodyStatements[0] -isnot
            [System.Management.Automation.Language.IfStatementAst]) {
        return $false
    }
    $cleanupGuard = $cleanupBodyStatements[0]
    if ($cleanupGuard.Clauses.Count -ne 1 -or
        $null -ne $cleanupGuard.ElseClause -or
        -not (& $equalsOrdinal $cleanupGuard.Clauses[0].Item1.Extent.Text '-not [string]::IsNullOrWhiteSpace($gatePath)') -or
        $cleanupGuard.Clauses[0].Item2.Statements.Count -ne 1 -or
        $cleanupGuard.Clauses[0].Item2.Statements[0] -isnot
            [System.Management.Automation.Language.TryStatementAst]) {
        return $false
    }
    $cleanupDeleteTry = $cleanupGuard.Clauses[0].Item2.Statements[0]
    if ($cleanupDeleteTry.Body.Statements.Count -ne 1 -or
        $cleanupDeleteTry.CatchClauses.Count -ne 1 -or
        $cleanupDeleteTry.CatchClauses[0].Body.Statements.Count -ne 0 -or
        $null -ne $cleanupDeleteTry.Finally) {
        return $false
    }
    $cleanupDelete = & $directInvocation $cleanupDeleteTry.Body.Statements[0]
    if ($null -eq $cleanupDelete -or
        -not $cleanupDelete.Static -or
        $cleanupDelete.Expression -isnot
            [System.Management.Automation.Language.TypeExpressionAst] -or
        -not (& $equalsOrdinal $cleanupDelete.Expression.TypeName.FullName 'System.IO.File') -or
        -not (& $equalsOrdinal $cleanupDelete.Member.Value 'Delete') -or
        $cleanupDelete.Arguments.Count -ne 1 -or
        -not (& $variableName $cleanupDelete.Arguments[0] 'gatePath')) {
        return $false
    }

    # embedded wrapperもParser ASTでparseし、実行scopeと親statementを閉じる。
    $wrapperTokens = $null
    $wrapperParseErrors = $null
    $wrapperAst =
        [System.Management.Automation.Language.Parser]::ParseInput(
            $wrapper,
            [ref]$wrapperTokens,
            [ref]$wrapperParseErrors
        )
    if ($wrapperParseErrors.Count -ne 0) {
        return $false
    }
    $statusFunctions = @(
        $wrapperAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.FunctionDefinitionAst] -and
                [string]::Equals(
                    $node.Name,
                    'Write-NativeGateStatus',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        )
    )
    if ($statusFunctions.Count -ne 1 -or
        [System.Array]::IndexOf(
            @($wrapperAst.EndBlock.Statements),
            $statusFunctions[0]
        ) -lt 0) {
        return $false
    }
    $statusFunction = $statusFunctions[0]
    $statusParameters = @($statusFunction.Parameters)
    $statusCleanBlockProperty =
        $statusFunction.Body.PSObject.Properties['CleanBlock']
    $statusCleanBlock = if ($null -eq $statusCleanBlockProperty) {
        $null
    } else {
        $statusCleanBlockProperty.Value
    }
    if ($null -ne $statusFunction.Body.ParamBlock -or
        $null -ne $statusFunction.Body.DynamicParamBlock -or
        $null -ne $statusFunction.Body.BeginBlock -or
        $null -ne $statusFunction.Body.ProcessBlock -or
        $null -ne $statusCleanBlock -or
        $null -eq $statusFunction.Body.EndBlock -or
        $statusParameters.Count -ne 1 -or
        -not (& $variableName $statusParameters[0].Name 'Status') -or
        $null -ne $statusParameters[0].DefaultValue -or
        $statusParameters[0].Attributes.Count -ne 1 -or
        $statusParameters[0].Attributes[0] -isnot
            [System.Management.Automation.Language.TypeConstraintAst] -or
        -not (& $equalsOrdinal $statusParameters[0].Attributes[0].TypeName.FullName 'string')) {
        return $false
    }
    $statusFunctionStatements =
        @($statusFunction.Body.EndBlock.Statements)
    if ($statusFunctionStatements.Count -ne 1 -or
        $statusFunctionStatements[0] -isnot
            [System.Management.Automation.Language.TryStatementAst]) {
        return $false
    }
    $statusTry = $statusFunctionStatements[0]
    $statusTryStatements = @($statusTry.Body.Statements)
    if ($statusTryStatements.Count -ne 2 -or
        $statusTry.CatchClauses.Count -ne 1 -or
        $statusTry.CatchClauses[0].CatchTypes.Count -ne 0 -or
        $null -ne $statusTry.Finally) {
        return $false
    }
    $statusWrite = & $directInvocation $statusTryStatements[0]
    $statusMove = & $directInvocation $statusTryStatements[1]
    if ($null -eq $statusWrite -or
        $null -eq $statusMove -or
        -not (& $equalsOrdinal $statusWrite.Expression.TypeName.FullName 'IO.File') -or
        -not (& $equalsOrdinal $statusWrite.Member.Value 'WriteAllText') -or
        $statusWrite.Arguments.Count -ne 3 -or
        -not (& $variableName $statusWrite.Arguments[0] 'statusStagingPath') -or
        -not (& $variableName $statusWrite.Arguments[1] 'Status') -or
        -not (& $equalsOrdinal $statusWrite.Arguments[2].Extent.Text '[Text.UTF8Encoding]::new($false)') -or
        -not (& $equalsOrdinal $statusMove.Expression.TypeName.FullName 'IO.File') -or
        -not (& $equalsOrdinal $statusMove.Member.Value 'Move') -or
        $statusMove.Arguments.Count -ne 2 -or
        -not (& $variableName $statusMove.Arguments[0] 'statusStagingPath') -or
        -not (& $variableName $statusMove.Arguments[1] 'statusPath')) {
        return $false
    }

    # status functionのcatchもstaging Exists/Deleteだけに閉じる。
    $statusCatchStatements =
        @($statusTry.CatchClauses[0].Body.Statements)
    if ($statusCatchStatements.Count -ne 1 -or
        $statusCatchStatements[0] -isnot
            [System.Management.Automation.Language.TryStatementAst]) {
        return $false
    }
    $statusCleanupTry = $statusCatchStatements[0]
    $statusCleanupStatements =
        @($statusCleanupTry.Body.Statements)
    if ($statusCleanupStatements.Count -ne 1 -or
        $statusCleanupStatements[0] -isnot
            [System.Management.Automation.Language.IfStatementAst] -or
        $statusCleanupTry.CatchClauses.Count -ne 1 -or
        $statusCleanupTry.CatchClauses[0].CatchTypes.Count -ne 0 -or
        $statusCleanupTry.CatchClauses[0].Body.Statements.Count -ne 0 -or
        $null -ne $statusCleanupTry.Finally) {
        return $false
    }
    $statusCleanupIf = $statusCleanupStatements[0]
    if ($statusCleanupIf.Clauses.Count -ne 1 -or
        $null -ne $statusCleanupIf.ElseClause -or
        $statusCleanupIf.Clauses[0].Item2.Statements.Count -ne 1) {
        return $false
    }
    $statusExists = & $directInvocation $statusCleanupIf.Clauses[0].Item1
    $statusDelete = & $directInvocation $statusCleanupIf.Clauses[0].Item2.Statements[0]
    if ($null -eq $statusExists -or
        -not $statusExists.Static -or
        $statusExists.Expression -isnot
            [System.Management.Automation.Language.TypeExpressionAst] -or
        -not (& $equalsOrdinal $statusExists.Expression.TypeName.FullName 'IO.File') -or
        -not (& $equalsOrdinal $statusExists.Member.Value 'Exists') -or
        $statusExists.Arguments.Count -ne 1 -or
        -not (& $variableName $statusExists.Arguments[0] 'statusStagingPath') -or
        $null -eq $statusDelete -or
        -not (& $equalsOrdinal $statusDelete.Expression.TypeName.FullName 'IO.File') -or
        -not (& $equalsOrdinal $statusDelete.Member.Value 'Delete') -or
        $statusDelete.Arguments.Count -ne 1 -or
        -not (& $variableName $statusDelete.Arguments[0] 'statusStagingPath')) {
        return $false
    }

    # wrapper全体のfilesystem callを6個の既知operationだけへ閉じる。
    $fileInvocations = @(
        $wrapperAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                $node.Expression -is
                    [System.Management.Automation.Language.TypeExpressionAst] -and
                (
                    [string]::Equals(
                        $node.Expression.TypeName.FullName,
                        'IO.File',
                        [System.StringComparison]::Ordinal
                    ) -or
                    [string]::Equals(
                        $node.Expression.TypeName.FullName,
                        'System.IO.File',
                        [System.StringComparison]::Ordinal
                    )
                )
            },
            $true
        )
    )
    if ($fileInvocations.Count -ne 6) {
        return $false
    }
    $fileInvocationKeys =
        [System.Collections.Generic.Dictionary[string, int]]::new(
            [System.StringComparer]::Ordinal
        )
    foreach ($fileInvocation in $fileInvocations) {
        if (-not (& $equalsOrdinal $fileInvocation.Expression.TypeName.FullName 'IO.File') -or
            $fileInvocation.Arguments.Count -lt 1 -or
            $fileInvocation.Arguments[0] -isnot
                [System.Management.Automation.Language.VariableExpressionAst]) {
            return $false
        }
        $fileKey = (
            [string]$fileInvocation.Member.Value + ':' +
            [string]$fileInvocation.Arguments[0].VariablePath.UserPath
        )
        if ($fileInvocationKeys.ContainsKey($fileKey)) {
            $fileInvocationKeys[$fileKey]++
        } else {
            $fileInvocationKeys[$fileKey] = 1
        }
    }
    $expectedFileInvocationKeys = @(
        'WriteAllText:statusStagingPath'
        'Move:statusStagingPath'
        'Exists:statusStagingPath'
        'Delete:statusStagingPath'
        'WriteAllText:readyPath'
        'Exists:releasePath'
    )
    if ($fileInvocationKeys.Count -ne
        $expectedFileInvocationKeys.Count) {
        return $false
    }
    foreach ($expectedFileKey in $expectedFileInvocationKeys) {
        if (-not $fileInvocationKeys.ContainsKey($expectedFileKey) -or
            $fileInvocationKeys[$expectedFileKey] -ne 1) {
            return $false
        }
    }

    # phase assignmentはOrdinal名でexact3件。zero-width変数は別物として拒否する。
    $phaseAssignmentAsts = @(
        $wrapperAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is
                    [System.Management.Automation.Language.VariableExpressionAst] -and
                [string]::Equals(
                    $node.Left.VariablePath.UserPath,
                    'nativeGatePhase',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        ) |
            Sort-Object { $_.Extent.StartOffset }
    )
    if ($phaseAssignmentAsts.Count -ne 3) {
        return $false
    }
    $expectedPhases = @(
        'type-definition',
        'platform-detection',
        'native-invocation'
    )
    for ($phaseIndex = 0;
        $phaseIndex -lt $expectedPhases.Count;
        $phaseIndex++) {
        $phaseRight = $phaseAssignmentAsts[$phaseIndex].Right
        if ($phaseRight -isnot
            [System.Management.Automation.Language.CommandExpressionAst] -or
            $phaseRight.Expression -isnot
                [System.Management.Automation.Language.StringConstantExpressionAst] -or
            -not (& $equalsOrdinal $phaseRight.Expression.Value $expectedPhases[$phaseIndex])) {
            return $false
        }
    }

    $phaseFaultIfAsts = @(
        $wrapperAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.IfStatementAst] -and
                $node.Extent.Text -cmatch (
                    '(?s)^if \(\$testOnlyNativeGateFailurePhase -ceq ' +
                    '\$nativeGatePhase\) \{\s*' +
                    "throw 'Synthetic native POSIX gate phase failure\.'\s*" +
                    '\}$'
                )
            },
            $true
        ) |
            Sort-Object { $_.Extent.StartOffset }
    )
    if ($phaseFaultIfAsts.Count -ne 3) {
        return $false
    }

    $topLevelStatements = @($wrapperAst.EndBlock.Statements)
    $topLevelTrys = @(
        $topLevelStatements |
            Where-Object {
                $_ -is
                    [System.Management.Automation.Language.TryStatementAst]
            }
    )
    if ($topLevelTrys.Count -ne 1) {
        return $false
    }
    $nativeTry = $topLevelTrys[0]
    if ($topLevelStatements.Count -ne 8 -or
        $topLevelStatements[0] -isnot
            [System.Management.Automation.Language.PipelineAst] -or
        -not (& $equalsOrdinal $topLevelStatements[0].Extent.Text 'Set-StrictMode -Version Latest') -or
        $topLevelStatements[1] -isnot
            [System.Management.Automation.Language.AssignmentStatementAst] -or
        -not (& $variableName $topLevelStatements[1].Left 'ErrorActionPreference') -or
        $topLevelStatements[1].Right -isnot
            [System.Management.Automation.Language.CommandExpressionAst] -or
        $topLevelStatements[1].Right.Expression -isnot
            [System.Management.Automation.Language.StringConstantExpressionAst] -or
        -not (& $equalsOrdinal $topLevelStatements[1].Right.Expression.Value 'Stop') -or
        -not (& $base64DecodeAssignmentContract $topLevelStatements[2] 'statusPath' '__STATUS_PATH__') -or
        -not (& $base64DecodeAssignmentContract $topLevelStatements[3] 'statusStagingPath' '__STATUS_STAGING_PATH__') -or
        -not (& $base64DecodeAssignmentContract $topLevelStatements[4] 'testOnlyNativeGateFailurePhase' '__TEST_ONLY_FAILURE_PHASE__') -or
        -not [object]::ReferenceEquals(
            $topLevelStatements[5],
            $statusFunction
        ) -or
        -not [object]::ReferenceEquals(
            $topLevelStatements[6],
            $phaseAssignmentAsts[0]
        ) -or
        -not [object]::ReferenceEquals(
            $topLevelStatements[7],
            $nativeTry
        )) {
        return $false
    }
    $typePhaseIndex =
        [System.Array]::IndexOf(
            $topLevelStatements,
            $phaseAssignmentAsts[0]
        )
    $nativeTryIndex =
        [System.Array]::IndexOf($topLevelStatements, $nativeTry)
    if ($typePhaseIndex -lt 0 -or
        $nativeTryIndex -ne ($typePhaseIndex + 1)) {
        return $false
    }

    # outer try先頭8 statementをclosed sequenceとして固定する。
    $nativeStatements = @($nativeTry.Body.Statements)
    if ($nativeStatements.Count -lt 8 -or
        -not [object]::ReferenceEquals(
            $nativeStatements[0],
            $phaseFaultIfAsts[0]
        ) -or
        $nativeStatements[1] -isnot
            [System.Management.Automation.Language.IfStatementAst] -or
        -not [object]::ReferenceEquals(
            $nativeStatements[2],
            $phaseAssignmentAsts[1]
        ) -or
        -not [object]::ReferenceEquals(
            $nativeStatements[3],
            $phaseFaultIfAsts[1]
        ) -or
        $nativeStatements[4] -isnot
            [System.Management.Automation.Language.AssignmentStatementAst] -or
        -not (& $variableName $nativeStatements[4].Left 'nativeGateIsMacOS') -or
        -not [object]::ReferenceEquals(
            $nativeStatements[5],
            $phaseAssignmentAsts[2]
        ) -or
        -not [object]::ReferenceEquals(
            $nativeStatements[6],
            $phaseFaultIfAsts[2]
        ) -or
        $nativeStatements[7] -isnot
            [System.Management.Automation.Language.AssignmentStatementAst] -or
        -not (& $variableName $nativeStatements[7].Left 'sessionResult')) {
        return $false
    }

    # Add-Typeはtype Ifのdirect command、platform/sessionはdirect member RHS。
    $typeDefinitionIf = $nativeStatements[1]
    if ($typeDefinitionIf.Clauses.Count -ne 1 -or
        $null -ne $typeDefinitionIf.ElseClause -or
        $typeDefinitionIf.Clauses[0].Item2.Statements.Count -ne 1) {
        return $false
    }
    $addTypeStatement =
        $typeDefinitionIf.Clauses[0].Item2.Statements[0]
    if ($addTypeStatement -isnot
        [System.Management.Automation.Language.PipelineAst] -or
        $addTypeStatement.PipelineElements.Count -ne 1 -or
        $addTypeStatement.PipelineElements[0] -isnot
            [System.Management.Automation.Language.CommandAst] -or
        -not (& $equalsOrdinal $addTypeStatement.PipelineElements[0].GetCommandName() 'Add-Type')) {
        return $false
    }
    $addTypeCommand = $addTypeStatement.PipelineElements[0]
    if ($addTypeCommand.CommandElements.Count -ne 3 -or
        $addTypeCommand.CommandElements[1] -isnot
            [System.Management.Automation.Language.CommandParameterAst] -or
        -not (& $equalsOrdinal $addTypeCommand.CommandElements[1].ParameterName 'TypeDefinition') -or
        $addTypeCommand.CommandElements[2] -isnot
            [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $addTypeCommand.CommandElements[2].StringConstantType -ne
            [System.Management.Automation.Language.StringConstantType]::DoubleQuotedHereString) {
        return $false
    }
    $nativeDefinitionBytes = [System.Text.Encoding]::UTF8.GetBytes(
        [string]$addTypeCommand.CommandElements[2].Value
    )
    $nativeDefinitionHasher =
        [System.Security.Cryptography.SHA256]::Create()
    try {
        $nativeDefinitionHash = (
            [System.BitConverter]::ToString(
                $nativeDefinitionHasher.ComputeHash($nativeDefinitionBytes)
            )
        ).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $nativeDefinitionHasher.Dispose()
    }
    if (-not (& $equalsOrdinal $nativeDefinitionHash 'f314d1cdd3a5d63ca73b6cfc4d7acbc4284d4f342ccc795eeaa891a61dbfd8b0')) {
        return $false
    }
    $platformRight = $nativeStatements[4].Right
    $sessionRight = $nativeStatements[7].Right
    if ($platformRight -isnot
        [System.Management.Automation.Language.CommandExpressionAst] -or
        $platformRight.Expression -isnot
            [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
        -not (& $equalsOrdinal $platformRight.Expression.Expression.TypeName.FullName 'Runtime.InteropServices.RuntimeInformation') -or
        -not (& $equalsOrdinal $platformRight.Expression.Member.Value 'IsOSPlatform') -or
        $platformRight.Expression.Arguments.Count -ne 1 -or
        -not (& $equalsOrdinal $platformRight.Expression.Arguments[0].Extent.Text '[Runtime.InteropServices.OSPlatform]::OSX') -or
        $sessionRight -isnot
            [System.Management.Automation.Language.CommandExpressionAst] -or
        $sessionRight.Expression -isnot
            [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
        -not (& $equalsOrdinal $sessionRight.Expression.Expression.TypeName.FullName 'PrivateMarker.NativePosixSession') -or
        -not (& $equalsOrdinal $sessionRight.Expression.Member.Value 'Create') -or
        $sessionRight.Expression.Arguments.Count -ne 1 -or
        -not (& $variableName $sessionRight.Expression.Arguments[0] 'nativeGateIsMacOS')) {
        return $false
    }

    return $true
}

function Assert-NativePosixGateWrapperContract {
    param([string]$RelativePath)

    try {
        $source = Get-RepoUtf8Text -RelativePath $RelativePath
    }
    catch {
        Add-Failure "$RelativePath must be valid UTF-8 (native POSIX wrapper contract)"
        return
    }
    if (-not (Test-NativePosixGateWrapperContract -Source $source)) {
        Add-Failure "$RelativePath violates the executable native POSIX wrapper contract."
    }
}

function Test-NativePosixGateWrapperMutationGuards {
    param([string]$RelativePath)

    try {
        $source = Get-RepoUtf8Text -RelativePath $RelativePath
    }
    catch {
        Add-Failure "$RelativePath must be valid UTF-8 (native POSIX wrapper mutation guards)"
        return
    }
    if (-not (Test-NativePosixGateWrapperContract -Source $source)) {
        Add-Failure 'Native POSIX wrapper mutation baseline must satisfy the contract.'
        return
    }

    $mutationTokens = $null
    $mutationParseErrors = $null
    $mutationAst =
        [System.Management.Automation.Language.Parser]::ParseInput(
            $source,
            [ref]$mutationTokens,
            [ref]$mutationParseErrors
        )
    $wrapperAssignmentForMutation = @(
        $mutationAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.AssignmentStatementAst] -and
                [string]::Equals(
                    $node.Left.Extent.Text,
                    '$posixWrapperTemplate',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        )
    )[0]
    $cleanupForEachForMutation = @(
        $mutationAst.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.ForEachStatementAst] -and
                [string]::Equals(
                    $node.Variable.VariablePath.UserPath,
                    'gatePath',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        )
    )[0]
    $wrapperForMutation =
        $wrapperAssignmentForMutation.Right.Expression.Value
    $wrapperBlockStatementsForMutation =
        @($wrapperAssignmentForMutation.Parent.Statements)
    $wrapperIndexForMutation = [System.Array]::IndexOf(
        $wrapperBlockStatementsForMutation,
        $wrapperAssignmentForMutation
    )
    $wrapperSequenceStart =
        $wrapperBlockStatementsForMutation[
            $wrapperIndexForMutation - 1
        ].Extent.StartOffset
    $wrapperSequenceEnd =
        $wrapperBlockStatementsForMutation[
            $wrapperIndexForMutation + 1
        ].Extent.EndOffset
    $wrapperSequenceForMutation = $source.Substring(
        $wrapperSequenceStart,
        $wrapperSequenceEnd - $wrapperSequenceStart
    )
    $wrapperScriptAssignmentForMutation =
        $wrapperBlockStatementsForMutation[$wrapperIndexForMutation + 1]
    $wrapperMutationTokens = $null
    $wrapperMutationParseErrors = $null
    $wrapperAstForMutation =
        [System.Management.Automation.Language.Parser]::ParseInput(
            $wrapperForMutation,
            [ref]$wrapperMutationTokens,
            [ref]$wrapperMutationParseErrors
        )
    $wrapperTopStatementsForMutation =
        @($wrapperAstForMutation.EndBlock.Statements)
    $statusFunctionForMutation = @(
        $wrapperAstForMutation.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.FunctionDefinitionAst] -and
                [string]::Equals(
                    $node.Name,
                    'Write-NativeGateStatus',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        )
    )[0]
    $statusTryForMutation =
        $statusFunctionForMutation.Body.EndBlock.Statements[0]
    $statusOuterCatchForMutation =
        $statusTryForMutation.CatchClauses[0]
    $statusCleanupTryForMutation =
        $statusOuterCatchForMutation.Body.Statements[0]
    $statusInnerCatchForMutation =
        $statusCleanupTryForMutation.CatchClauses[0]
    $addTypeForMutation = [regex]::Match(
        $wrapperForMutation,
        '(?ms)^[ \t]*Add-Type -TypeDefinition @".*?^"@[ \t]*$'
    ).Value
    $platformAssignmentForMutation = [regex]::Match(
        $wrapperForMutation,
        (
            '(?ms)^[ \t]*\$nativeGateIsMacOS =\r?\n' +
            '[ \t]*\[Runtime\.InteropServices\.RuntimeInformation\]' +
            '::IsOSPlatform\(\r?\n' +
            '[ \t]*\[Runtime\.InteropServices\.OSPlatform\]::OSX\r?\n' +
            '[ \t]*\)[ \t]*$'
        )
    ).Value
    $sessionAssignmentForMutation = [regex]::Match(
        $wrapperForMutation,
        (
            '(?ms)^[ \t]*\$sessionResult =\r?\n' +
            '[ \t]*\[PrivateMarker\.NativePosixSession\]' +
            '::Create\(\$nativeGateIsMacOS\)[ \t]*$'
        )
    ).Value
    $zeroWidthPhaseName =
        'nativeGate' + [char]0x200B + 'Phase'
    $statusFunctionText = $statusFunctionForMutation.Extent.Text
    $statusFunctionHeader =
        'function Write-NativeGateStatus([string]$Status) {'
    $statusFunctionWithBegin = $statusFunctionText.Replace(
        $statusFunctionHeader,
        (
            $statusFunctionHeader + "`n" +
            '    begin { exit 0 }' + "`n" +
            '    end {'
        )
    ) + "`n}"

    $phaseFaultBlock = @'
if ($testOnlyNativeGateFailurePhase -ceq $nativeGatePhase) {
        throw 'Synthetic native POSIX gate phase failure.'
    }
'@
    $atomicPublicationBlock = @'
[IO.File]::WriteAllText(
            $statusStagingPath,
            $Status,
            [Text.UTF8Encoding]::new($false)
        )
        [IO.File]::Move($statusStagingPath, $statusPath)
'@
    $mutations = @(
        [pscustomobject]@{
            Name = 'block-comment-wrapper-assignment'
            Source = $source.Replace(
                $wrapperAssignmentForMutation.Extent.Text,
                (
                    '<#' + "`n" +
                    $wrapperAssignmentForMutation.Extent.Text + "`n" +
                    '#>'
                )
            )
        },
        [pscustomobject]@{
            Name = 'block-comment-cleanup-foreach'
            Source = $source.Replace(
                $cleanupForEachForMutation.Extent.Text,
                (
                    '<#' + "`n" +
                    $cleanupForEachForMutation.Extent.Text + "`n" +
                    '#>'
                )
            )
        },
        [pscustomobject]@{
            Name = 'cleanup-index-subset'
            Source = $source.Replace(
                (
                    '$posixGateStatusStagingPath' + "`n" +
                    '        )) {'
                ),
                (
                    '$posixGateStatusStagingPath' + "`n" +
                    '        )[0..2]) {'
                )
            )
        },
        [pscustomobject]@{
            Name = 'cleanup-unary-array-wrapper'
            Source = $source.Replace(
                'foreach ($gatePath in @(',
                'foreach ($gatePath in ,@('
            )
        },
        [pscustomobject]@{
            Name = 'reorder-cleanup-collection'
            Source = $source.Replace(
                (
                    '$posixGateReadyPath,' + "`n" +
                    '            $posixGateReleasePath,'
                ),
                (
                    '$posixGateReleasePath,' + "`n" +
                    '            $posixGateReadyPath,'
                )
            )
        },
        [pscustomobject]@{
            Name = 'empty-cleanup-body'
            Source = $source.Replace(
                $cleanupForEachForMutation.Body.Extent.Text,
                '{ }'
            )
        },
        [pscustomobject]@{
            Name = 'cleanup-nested-false-finally'
            Source = $source.Replace(
                $cleanupForEachForMutation.Extent.Text,
                (
                    'if ($false) {' + "`n" +
                    '    try {} finally {' + "`n" +
                    '        ' +
                    $cleanupForEachForMutation.Extent.Text.Replace(
                        "`n",
                        "`n        "
                    ) + "`n" +
                    '    }' + "`n" +
                    '}'
                )
            )
        },
        [pscustomobject]@{
            Name = 'wrapper-sequence-if-false'
            Source = $source.Replace(
                $wrapperSequenceForMutation,
                (
                    'if ($false) {' + "`n" +
                    $wrapperSequenceForMutation + "`n" +
                    '}'
                )
            )
        },
        [pscustomobject]@{
            Name = 'wrapper-sequence-nested-try'
            Source = $source.Replace(
                $wrapperSequenceForMutation,
                (
                    'try {' + "`n" +
                    $wrapperSequenceForMutation + "`n" +
                    '} finally {}'
                )
            )
        },
        [pscustomobject]@{
            Name = 'wrapper-sequence-empty-loop'
            Source = $source.Replace(
                $wrapperSequenceForMutation,
                (
                    'foreach ($unusedWrapperItem in @()) {' + "`n" +
                    $wrapperSequenceForMutation + "`n" +
                    '}'
                )
            )
        },
        [pscustomobject]@{
            Name = 'wrapper-sequence-switch'
            Source = $source.Replace(
                $wrapperSequenceForMutation,
                (
                    'switch ($false) {' + "`n" +
                    '    $true {' + "`n" +
                    $wrapperSequenceForMutation + "`n" +
                    '    }' + "`n" +
                    '}'
                )
            )
        },
        [pscustomobject]@{
            Name = 'wrapper-sequence-scriptblock'
            Source = $source.Replace(
                $wrapperSequenceForMutation,
                (
                    '& {' + "`n" +
                    $wrapperSequenceForMutation + "`n" +
                    '}'
                )
            )
        },
        [pscustomobject]@{
            Name = 'wrapper-sequence-unused-function'
            Source = $source.Replace(
                $wrapperSequenceForMutation,
                (
                    'function Initialize-UnusedWrapper {' + "`n" +
                    $wrapperSequenceForMutation + "`n" +
                    '}'
                )
            )
        },
        [pscustomobject]@{
            Name = 'empty-wrapper-script-rhs'
            Source = $source.Replace(
                $wrapperScriptAssignmentForMutation.Right.Extent.Text,
                "''"
            )
        },
        [pscustomobject]@{
            Name = 'wrong-ready-base64-provenance'
            Source = $source.Replace(
                $wrapperBlockStatementsForMutation[
                    $wrapperIndexForMutation - 5
                ].Extent.Text,
                $wrapperBlockStatementsForMutation[
                    $wrapperIndexForMutation - 5
                ].Extent.Text.Replace(
                    '$posixGateReadyPath',
                    '$posixGateReleasePath'
                )
            )
        },
        [pscustomobject]@{
            Name = 'wrong-status-decode-placeholder'
            Source = $source.Replace(
                $wrapperTopStatementsForMutation[2].Extent.Text,
                $wrapperTopStatementsForMutation[2].Extent.Text.Replace(
                    '__STATUS_PATH__',
                    '__STATUS_STAGING_PATH__'
                )
            )
        },
        [pscustomobject]@{
            Name = 'wrong-wrapper-replace-source'
            Source = $source.Replace(
                $wrapperScriptAssignmentForMutation.Right.Extent.Text,
                $wrapperScriptAssignmentForMutation.Right.Extent.Text.Replace(
                    '$readyPathBase64',
                    '$releasePathBase64'
                )
            )
        },
        [pscustomobject]@{
            Name = 'duplicate-wrapper-replace-call'
            Source = $source.Replace(
                $wrapperScriptAssignmentForMutation.Right.Extent.Text,
                (
                    $wrapperScriptAssignmentForMutation.Right.Extent.Text +
                    ".Replace('__READY_PATH__', `$readyPathBase64)"
                )
            )
        },
        [pscustomobject]@{
            Name = 'status-function-begin-block'
            Source = $source.Replace(
                $statusFunctionText,
                $statusFunctionWithBegin
            )
        },
        [pscustomobject]@{
            Name = 'status-function-wrong-parameter'
            Source = $source.Replace(
                $statusFunctionHeader,
                'function Write-NativeGateStatus([object]$Status) {'
            )
        },
        [pscustomobject]@{
            Name = 'status-cleanup-false-and-condition'
            Source = $source.Replace(
                '[IO.File]::Exists($statusStagingPath)',
                '$false -and [IO.File]::Exists($statusStagingPath)'
            )
        },
        [pscustomobject]@{
            Name = 'status-cleanup-true-or-condition'
            Source = $source.Replace(
                '[IO.File]::Exists($statusStagingPath)',
                '[IO.File]::Exists($statusStagingPath) -or $true'
            )
        },
        [pscustomobject]@{
            Name = 'status-outer-typed-catch'
            Source = $source.Replace(
                $statusOuterCatchForMutation.Extent.Text,
                $statusOuterCatchForMutation.Extent.Text.Replace(
                    'catch {',
                    'catch [System.IO.IOException] {'
                )
            )
        },
        [pscustomobject]@{
            Name = 'status-inner-typed-catch'
            Source = $source.Replace(
                $statusInnerCatchForMutation.Extent.Text,
                $statusInnerCatchForMutation.Extent.Text.Replace(
                    'catch {',
                    'catch [System.IO.IOException] {'
                )
            )
        },
        [pscustomobject]@{
            Name = 'placeholder-add-type-definition'
            Source = $source.Replace(
                $addTypeForMutation,
                "Add-Type -TypeDefinition 'public class Placeholder {}'"
            )
        },
        [pscustomobject]@{
            Name = 'add-type-extra-parameter'
            Source = $source.Replace(
                'Add-Type -TypeDefinition @"',
                'Add-Type -ErrorAction Stop -TypeDefinition @"'
            )
        },
        [pscustomobject]@{
            Name = 'add-type-shadow-function'
            Source = $source.Replace(
                $addTypeForMutation,
                (
                    'function Add-Type { param($TypeDefinition) }' + "`n" +
                    '        ' + $addTypeForMutation
                )
            )
        },
        [pscustomobject]@{
            Name = 'add-type-dynamic-definition'
            Source = $source.Replace(
                $addTypeForMutation,
                (
                    '$dynamicNativeDefinition = ' +
                    $addTypeForMutation.Substring(
                        $addTypeForMutation.IndexOf('@"')
                    ) + "`n" +
                    '        Add-Type -TypeDefinition ' +
                    '$dynamicNativeDefinition'
                )
            )
        },
        [pscustomobject]@{
            Name = 'unused-function-atomic-publication'
            Source = $source.Replace(
                $atomicPublicationBlock,
                (
                    'function Invoke-UnusedAtomicPublication {' + "`n" +
                    '        ' +
                    $atomicPublicationBlock.Replace(
                        "`n",
                        "`n        "
                    ) + "`n" +
                    '    }'
                )
            )
        },
        [pscustomobject]@{
            Name = 'unused-function-add-type'
            Source = $source.Replace(
                $addTypeForMutation,
                (
                    'function Initialize-UnusedNativeGate {' + "`n" +
                    '    ' +
                    $addTypeForMutation.Replace("`n", "`n    ") + "`n" +
                    '}'
                )
            )
        },
        [pscustomobject]@{
            Name = 'scriptblock-platform-rhs'
            Source = $source.Replace(
                $platformAssignmentForMutation,
                (
                    '$nativeGateIsMacOS = {' + "`n" +
                    $platformAssignmentForMutation.Substring(
                        $platformAssignmentForMutation.IndexOf("`n") + 1
                    ) + "`n" +
                    '    }'
                )
            )
        },
        [pscustomobject]@{
            Name = 'scriptblock-session-rhs'
            Source = $source.Replace(
                $sessionAssignmentForMutation,
                (
                    '$sessionResult = {' + "`n" +
                    $sessionAssignmentForMutation.Substring(
                        $sessionAssignmentForMutation.IndexOf("`n") + 1
                    ) + "`n" +
                    '    }'
                )
            )
        },
        [pscustomobject]@{
            Name = 'system-io-get-variable-final-write'
            Source = $source.Replace(
                $atomicPublicationBlock,
                (
                    '[System.IO.File]::WriteAllText(' + "`n" +
                    '            (Get-Variable -Name statusPath -ValueOnly),' +
                    "`n" +
                    '            $Status,' + "`n" +
                    '            [Text.UTF8Encoding]::new($false)' + "`n" +
                    '        )' + "`n" +
                    '        ' + $atomicPublicationBlock
                )
            )
        },
        [pscustomobject]@{
            Name = 'zero-width-phase-with-comment-decoy'
            Source = $source.Replace(
                "`$nativeGatePhase = 'platform-detection'",
                (
                    '<#' + "`n" +
                    "`$nativeGatePhase = 'platform-detection'" + "`n" +
                    '#>' + "`n" +
                    '${' + $zeroWidthPhaseName +
                    "} = 'platform-detection'"
                )
            )
        },
        [pscustomobject]@{
            Name = 'block-comment-atomic-publication'
            Source = $source.Replace(
                $atomicPublicationBlock,
                '<#' + "`n" + $atomicPublicationBlock + "`n" + '#>'
            )
        },
        [pscustomobject]@{
            Name = 'here-string-atomic-decoy'
            Source = $source.Replace(
                $atomicPublicationBlock,
                (
                    "`$atomicPublicationDecoy = @`"" + "`n" +
                    $atomicPublicationBlock + "`n" +
                    '"@'
                )
            )
        },
        [pscustomobject]@{
            Name = 'block-comment-platform-assignment'
            Source = $source.Replace(
                "`$nativeGatePhase = 'platform-detection'",
                (
                    '<#' + "`n" +
                    "`$nativeGatePhase = 'platform-detection'" + "`n" +
                    '#>'
                )
            )
        },
        [pscustomobject]@{
            Name = 'direct-final-write-before-staging'
            Source = $source.Replace(
                (
                    '[IO.File]::WriteAllText(' + "`n" +
                    '            $statusStagingPath,'
                ),
                (
                    '[IO.File]::WriteAllText(' + "`n" +
                    '            $statusPath,' + "`n" +
                    '            $Status,' + "`n" +
                    '            [Text.UTF8Encoding]::new($false)' + "`n" +
                    '        )' + "`n" +
                    '        [IO.File]::WriteAllText(' + "`n" +
                    '            $statusStagingPath,'
                )
            )
        },
        [pscustomobject]@{
            Name = 'comment-atomic-move'
            Source = $source.Replace(
                '[IO.File]::Move($statusStagingPath, $statusPath)',
                '# [IO.File]::Move($statusStagingPath, $statusPath)'
            )
        },
        [pscustomobject]@{
            Name = 'remove-phase-fault-seams'
            Source = $source.Replace($phaseFaultBlock, '')
        },
        [pscustomobject]@{
            Name = 'reorder-phase-assignments'
            Source = $source.Replace(
                "`$nativeGatePhase = 'platform-detection'",
                "`$nativeGatePhase = '__phase-swap__'"
            ).Replace(
                "`$nativeGatePhase = 'native-invocation'",
                "`$nativeGatePhase = 'platform-detection'"
            ).Replace(
                "`$nativeGatePhase = '__phase-swap__'",
                "`$nativeGatePhase = 'native-invocation'"
            )
        },
        [pscustomobject]@{
            Name = 'comment-phase-assignment'
            Source = $source.Replace(
                "`$nativeGatePhase = 'platform-detection'",
                "# `$nativeGatePhase = 'platform-detection'"
            )
        },
        [pscustomobject]@{
            Name = 'extra-phase-assignment-before-type-operation'
            Source = $source.Replace(
                (
                    '    if ($null -eq (' +
                    "'PrivateMarker.NativePosixSession' -as [type])) {"
                ),
                (
                    "    `$nativeGatePhase = 'native-invocation'" + "`n" +
                    '    if ($null -eq (' +
                    "'PrivateMarker.NativePosixSession' -as [type])) {"
                )
            )
        },
        [pscustomobject]@{
            Name = 'comment-staging-cleanup'
            Source = $source.Replace(
                (
                    '            $posixGateStatusPath,' + "`n" +
                    '            $posixGateStatusStagingPath' + "`n"
                ),
                (
                    '            $posixGateStatusPath' + "`n" +
                    '            # $posixGateStatusStagingPath' + "`n"
                )
            )
        }
    )
    foreach ($topLevelInjection in @(
        [pscustomobject]@{ Name = 'exit'; Statement = 'exit 0' }
        [pscustomobject]@{ Name = 'return'; Statement = 'return' }
        [pscustomobject]@{
            Name = 'throw'
            Statement = "throw 'Synthetic top-level bypass.'"
        }
        [pscustomobject]@{ Name = 'break'; Statement = 'break' }
        [pscustomobject]@{ Name = 'continue'; Statement = 'continue' }
        [pscustomobject]@{
            Name = 'assignment'
            Statement = '$unexpectedTopLevelStatement = $true'
        }
    )) {
        $mutations += [pscustomobject]@{
            Name = "wrapper-top-level-$($topLevelInjection.Name)"
            Source = $source.Replace(
                "`$nativeGatePhase = 'type-definition'",
                (
                    $topLevelInjection.Statement + "`n" +
                    "`$nativeGatePhase = 'type-definition'"
                )
            )
        }
    }

    foreach ($mutation in $mutations) {
        if ($mutation.Source -ceq $source) {
            Add-Failure "Native POSIX wrapper mutation did not change source: $($mutation.Name)."
            continue
        }
        $mutatedTokens = $null
        $mutatedParseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput(
            $mutation.Source,
            [ref]$mutatedTokens,
            [ref]$mutatedParseErrors
        )
        if ($mutatedParseErrors.Count -ne 0) {
            Add-Failure "Native POSIX wrapper mutation must remain parsable: $($mutation.Name)."
        } elseif (Test-NativePosixGateWrapperContract -Source $mutation.Source) {
            Add-Failure "Native POSIX wrapper mutation was not rejected: $($mutation.Name)."
        }
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

function Assert-MacOSProcessFixtureBudgetContract {
    param([string]$RelativePath)

    $filePath = Get-RepoFilePath -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        Add-Failure "Cannot inspect missing file: $RelativePath (macOS process fixture budget contract)"
        return
    }
    try {
        $source = Get-RepoUtf8Text -RelativePath $RelativePath
    }
    catch {
        Add-Failure "$RelativePath must be valid UTF-8 (macOS process fixture budget contract)"
        return
    }

    # comment/string decoyを数えず、budget定義、対象call、native skip ancestorを
    # Parser AST上の一意なassignment/parameter/offsetとして閉じる。
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $source,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -ne 0) {
        Add-Failure "$RelativePath must parse for the macOS process fixture budget contract."
        return
    }
    $getAssignment = {
        param([string]$Name)

        $matches = @(
            $ast.FindAll(
                {
                    param($node)
                    $node -is
                        [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is
                        [System.Management.Automation.Language.VariableExpressionAst] -and
                    [string]::Equals(
                        $node.Left.VariablePath.UserPath,
                        $Name,
                        [System.StringComparison]::Ordinal
                    )
                },
                $true
            )
        )
        if ($matches.Count -ne 1) {
            return $null
        }
        return $matches[0]
    }
    $getParameterValue = {
        param(
            [System.Management.Automation.Language.CommandAst]$Command,
            [string]$Name
        )

        for ($index = 0;
            $index -lt $Command.CommandElements.Count;
            $index++) {
            $element = $Command.CommandElements[$index]
            if ($element -is
                    [System.Management.Automation.Language.CommandParameterAst] -and
                [string]::Equals(
                    $element.ParameterName,
                    $Name,
                    [System.StringComparison]::Ordinal
                )) {
                if ($index + 1 -ge $Command.CommandElements.Count -or
                    $Command.CommandElements[$index + 1] -is
                        [System.Management.Automation.Language.CommandParameterAst]) {
                    return ''
                }
                return $Command.CommandElements[$index + 1].Extent.Text
            }
        }
        return $null
    }
    $getProcessCommand = {
        param(
            [System.Management.Automation.Language.AssignmentStatementAst]
                $Assignment
        )

        if ($null -eq $Assignment) {
            return $null
        }
        $commands = @(
            $Assignment.Right.FindAll(
                {
                    param($node)
                    $node -is
                        [System.Management.Automation.Language.CommandAst] -and
                    [string]::Equals(
                        $node.GetCommandName(),
                        'Invoke-PrivateMarkerProcess',
                        [System.StringComparison]::Ordinal
                    )
                },
                $true
            )
        )
        if ($commands.Count -ne 1) {
            return $null
        }
        return $commands[0]
    }

    $availableSetSidAssignment = & $getAssignment 'availableSetSidPath'
    $nativeGateHostAssignment = & $getAssignment 'usesNativePosixSessionGate'
    $normalBudgetAssignment =
        & $getAssignment 'processTestTimeoutMilliseconds'
    $rawBudgetAssignment =
        & $getAssignment 'rawTransportTestTimeoutMilliseconds'
    $rawTransportAssignment = & $getAssignment 'rawTransportResult'
    if ($null -eq $availableSetSidAssignment -or
        $null -eq $nativeGateHostAssignment -or
        $null -eq $normalBudgetAssignment -or
        $null -eq $rawBudgetAssignment -or
        $null -eq $rawTransportAssignment) {
        Add-Failure "$RelativePath must define each macOS fixture gate/budget and raw transport assignment exactly once."
        return
    }

    $normalizedSetSid =
        $availableSetSidAssignment.Right.Extent.Text -replace '\s+', ''
    $normalizedNativeGateHost =
        $nativeGateHostAssignment.Right.Extent.Text -replace '\s+', ''
    $normalizedNormalBudget =
        $normalBudgetAssignment.Right.Extent.Text -replace '\s+', ''
    $normalizedRawBudget =
        $rawBudgetAssignment.Right.Extent.Text -replace '\s+', ''
    if ($normalizedSetSid -cne
            "@('/usr/bin/setsid','/bin/setsid')|Where-Object{Test-Path-LiteralPath`$_-PathTypeLeaf}|Select-Object-First1" -or
        $normalizedNativeGateHost -cne
            '-not(Test-PrivateMarkerWindowsHost)-and[string]::IsNullOrWhiteSpace([string]$availableSetSidPath)' -or
        $normalizedNormalBudget -cne
            'if($RequireMacOSNativePosixContainment){30000}else{10000}' -or
        $normalizedRawBudget -cne
            'if($RequireMacOSNativePosixContainment){30000}else{5000}') {
        Add-Failure "$RelativePath must keep exact host detection and macOS-only 30-second fixture budgets."
    }
    $rawTransportOffset = $rawTransportAssignment.Extent.StartOffset
    foreach ($setupAssignment in @(
        $availableSetSidAssignment,
        $nativeGateHostAssignment,
        $normalBudgetAssignment,
        $rawBudgetAssignment
    )) {
        if ($setupAssignment.Extent.StartOffset -ge $rawTransportOffset) {
            Add-Failure "$RelativePath must establish native-gate detection and budgets before its first process fixture."
            break
        }
    }

    $expectedFixtureTimeouts = [ordered]@{
        rawTransportResult = '$rawTransportTestTimeoutMilliseconds'
        rawGitInitResult = '$processTestTimeoutMilliseconds'
        rawGitHashResult = '$processTestTimeoutMilliseconds'
        rawGitBatchResult = '$processTestTimeoutMilliseconds'
        hermeticEnvironmentResult = '$processTestTimeoutMilliseconds'
        withinBoundaryResult = '$processTestTimeoutMilliseconds'
        overBoundaryResult = '$processTestTimeoutMilliseconds'
        hostilePathResult = '$processTestTimeoutMilliseconds'
        posixPipeResult = '$processTestTimeoutMilliseconds'
    }
    foreach ($fixtureName in $expectedFixtureTimeouts.Keys) {
        $fixtureAssignment = & $getAssignment $fixtureName
        $fixtureCommand = & $getProcessCommand $fixtureAssignment
        if ($null -eq $fixtureAssignment -or
            $null -eq $fixtureCommand -or
            (& $getParameterValue $fixtureCommand 'TimeoutMilliseconds') -cne
                $expectedFixtureTimeouts[$fixtureName] -or
            $fixtureAssignment.Extent.StartOffset -le
                $normalBudgetAssignment.Extent.StartOffset) {
            Add-Failure "$RelativePath process fixture '$fixtureName' must use its hoisted bounded timeout."
        }
    }

    # 25ms/5s seamはnative startupを測るfixtureではない。同一の否定guard下で
    # literal deadlineを維持し、native deadlineは専用1ms callだけが所有する。
    $sharedNativeGateGuardOffset = $null
    foreach ($seamCase in @(
        [pscustomobject]@{
            Name = 'expiredCompletedProcessResult'
            Timeout = '25'
            Seam = 'TestOnlyPostExitDelayMilliseconds'
            SeamValue = '100'
        },
        [pscustomobject]@{
            Name = 'expiredAfterInitialCheckResult'
            Timeout = '5000'
            Seam = 'TestOnlyExpireDeadlineAfterInitialCheck'
            SeamValue = ''
        }
    )) {
        $seamAssignment = & $getAssignment $seamCase.Name
        $seamCommand = & $getProcessCommand $seamAssignment
        $nativeGateGuard = $null
        $ancestor = if ($null -eq $seamAssignment) {
            $null
        } else {
            $seamAssignment.Parent
        }
        while ($null -ne $ancestor -and $null -eq $nativeGateGuard) {
            if ($ancestor -is
                    [System.Management.Automation.Language.IfStatementAst] -and
                $ancestor.Clauses.Count -eq 1 -and
                (($ancestor.Clauses[0].Item1.Extent.Text -replace '\s+', '') -ceq
                    '-not$usesNativePosixSessionGate')) {
                $nativeGateGuard = $ancestor
            }
            $ancestor = $ancestor.Parent
        }
        $belongsToGuardTrueClause = $false
        $crossesDeferredDefinition = $false
        if ($null -ne $nativeGateGuard) {
            $trueClause = $nativeGateGuard.Clauses[0].Item2
            $belongsToGuardTrueClause =
                $null -eq $nativeGateGuard.ElseClause -and
                $seamAssignment.Extent.StartOffset -ge
                    $trueClause.Extent.StartOffset -and
                $seamAssignment.Extent.EndOffset -le
                    $trueClause.Extent.EndOffset
            $ancestor = $seamAssignment.Parent
            while ($null -ne $ancestor -and
                $ancestor -ne $nativeGateGuard) {
                if ($ancestor -is
                        [System.Management.Automation.Language.FunctionDefinitionAst] -or
                    $ancestor -is
                        [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
                    $crossesDeferredDefinition = $true
                    break
                }
                $ancestor = $ancestor.Parent
            }
            if ($null -eq $sharedNativeGateGuardOffset) {
                $sharedNativeGateGuardOffset =
                    $nativeGateGuard.Extent.StartOffset
            } elseif ($sharedNativeGateGuardOffset -ne
                $nativeGateGuard.Extent.StartOffset) {
                $belongsToGuardTrueClause = $false
            }
        }
        if ($null -eq $seamAssignment -or
            $null -eq $seamCommand -or
            (& $getParameterValue $seamCommand 'TimeoutMilliseconds') -cne
                $seamCase.Timeout -or
            (& $getParameterValue $seamCommand $seamCase.Seam) -cne
                $seamCase.SeamValue -or
            -not $belongsToGuardTrueClause -or
            $crossesDeferredDefinition) {
            Add-Failure "$RelativePath post-exit seam '$($seamCase.Name)' must retain its literal deadline under the native-gate-host skip."
        }
    }

    $processCommands = @(
        $ast.FindAll(
            {
                param($node)
                $node -is
                    [System.Management.Automation.Language.CommandAst] -and
                [string]::Equals(
                    $node.GetCommandName(),
                    'Invoke-PrivateMarkerProcess',
                    [System.StringComparison]::Ordinal
                )
            },
            $true
        )
    )
    $phaseFaultCommands = @(
        $processCommands |
            Where-Object {
                $null -ne (
                    & $getParameterValue `
                        $_ `
                        'TestOnlyNativePosixGateFailurePhase'
                )
            }
    )
    $nativeDeadlineCommands = @(
        $processCommands |
            Where-Object {
                (& $getParameterValue $_ 'IsolationRoot') -ceq
                    '$nativeGateDeadlineIsolation'
            }
    )
    if ($phaseFaultCommands.Count -ne 1 -or
        (& $getParameterValue `
            $phaseFaultCommands[0] `
            'TimeoutMilliseconds') -cne
                '$processTestTimeoutMilliseconds') {
        Add-Failure "$RelativePath native phase-fault fixture must use the hoisted normal process budget."
    }
    if ($nativeDeadlineCommands.Count -ne 1 -or
        (& $getParameterValue `
            $nativeDeadlineCommands[0] `
            'TimeoutMilliseconds') -cne '1') {
        Add-Failure "$RelativePath must retain one literal one-millisecond native deadline cleanup fixture."
    }
    if ($source -cmatch '\$nativeGateTestTimeoutMilliseconds') {
        Add-Failure "$RelativePath must not reintroduce the late native-gate timeout budget."
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

  validate-macos:
    name: Validate native macOS process containment
    runs-on: macos-15
    timeout-minutes: 10
    steps:
      - name: Check out repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5

      - name: Validate OSS readiness
        shell: pwsh
        run: ./scripts/validate-oss-readiness.ps1

      - name: Test native POSIX containment on Darwin
        shell: pwsh
        run: ./scripts/test-scan-private-markers.ps1 -RequireMacOSNativePosixContainment

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
        -ExpectedJobNames @('validate', 'validate-ubuntu', 'validate-macos')

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

    $macOSJobName = 'validate-macos'
    $macOSJobLines = @(Get-WorkflowJobLines `
        -RelativePath $RelativePath `
        -JobName $macOSJobName)
    $macOSSteps = @(Get-WorkflowSteps `
        -Lines $macOSJobLines `
        -JobName $macOSJobName)
    Assert-WorkflowJobValue `
        -Lines $macOSJobLines `
        -JobName $macOSJobName `
        -Key 'name' `
        -ExpectedValue 'Validate native macOS process containment'
    Assert-WorkflowJobValue `
        -Lines $macOSJobLines `
        -JobName $macOSJobName `
        -Key 'runs-on' `
        -ExpectedValue 'macos-15'
    Assert-WorkflowJobValue `
        -Lines $macOSJobLines `
        -JobName $macOSJobName `
        -Key 'timeout-minutes' `
        -ExpectedValue '10'
    Assert-WorkflowStepCount `
        -Steps $macOSSteps `
        -JobName $macOSJobName `
        -ExpectedCount 5
    Assert-WorkflowJobShape `
        -Lines $macOSJobLines `
        -JobName $macOSJobName `
        -ExpectedStepCount 5 `
        -ExpectedShellCount 4 `
        -ExpectedRunCount 4
    Assert-WorkflowUsesStep `
        -Steps $macOSSteps `
        -JobName $macOSJobName `
        -Name 'Check out repository' `
        -Uses $checkoutRevision
    Assert-WorkflowStep `
        -Steps $macOSSteps `
        -JobName $macOSJobName `
        -Name 'Validate OSS readiness' `
        -Shell 'pwsh' `
        -Run './scripts/validate-oss-readiness.ps1'
    Assert-WorkflowStep `
        -Steps $macOSSteps `
        -JobName $macOSJobName `
        -Name 'Test native POSIX containment on Darwin' `
        -Shell 'pwsh' `
        -Run './scripts/test-scan-private-markers.ps1 -RequireMacOSNativePosixContainment'
    Assert-WorkflowStep `
        -Steps $macOSSteps `
        -JobName $macOSJobName `
        -Name 'Scan for private markers' `
        -Shell 'pwsh' `
        -Run './scripts/scan-private-markers.ps1'
    Assert-WorkflowStep `
        -Steps $macOSSteps `
        -JobName $macOSJobName `
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
    if ($usesLines.Count -ne 3 -or
        $pinnedUsesLines.Count -ne $usesLines.Count) {
        Add-Failure 'Workflow must contain exactly three third-party action uses, each pinned to a full 40-character SHA.'
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
            Name = 'macos-job-key-drift'
            Source = $source.Replace(
                '  validate-macos:',
                '  validate-darwin:'
            )
        },
        [pscustomobject]@{
            Name = 'macos-runner-drift'
            Source = $source.Replace(
                '    runs-on: macos-15',
                '    runs-on: macos-14'
            )
        },
        [pscustomobject]@{
            Name = 'macos-native-containment-proof-removed'
            Source = $source.Replace(
                './scripts/test-scan-private-markers.ps1 -RequireMacOSNativePosixContainment',
                './scripts/test-scan-private-markers.ps1'
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
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'RequireMacOSNativePosixContainment' -Description 'Darwin native-containment canary switch'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '\$posixPipeResult\.PosixSessionGate' -Description 'observed POSIX gate assertion'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern '\$Result\.ExitCode -eq 0' -Description 'target success required for POSIX evidence'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'Test-PrivateMarkerPosixContainmentEvidence' -Description 'central POSIX evidence predicate'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'ExpectedExitCode = 23' -Description 'synthetic nonzero POSIX evidence rejection'
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'nonzero-rejection=passed' -Description 'structured Darwin nonzero-evidence rejection'
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
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'PosixSessionGate = \$posixSessionGate' -Description 'reported POSIX gate selection'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'ConvertTo-PrivateMarkerPosixGateFailureReason' -Description 'fixed POSIX gate failure diagnostics'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'Resolve-PrivateMarkerPosixGateFailureReason' -Description 'closed POSIX gate timeout classification'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'Read-PrivateMarkerPosixGateStatus' -Description 'bounded POSIX gate status reader'
Assert-NativePosixGateWrapperContract -RelativePath 'scripts/private-marker-process.ps1'
Test-NativePosixGateWrapperMutationGuards -RelativePath 'scripts/private-marker-process.ps1'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'New-Object byte\[\] 65' -Description '65-byte POSIX status overflow probe'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern '\$statusLength -gt 64' -Description '64-byte POSIX status acceptance limit'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'UTF8Encoding\(\$false, \$true\)' -Description 'strict POSIX status UTF-8 decode'
Assert-FileDoesNotContain -RelativePath 'scripts/private-marker-process.ps1' -Pattern '(?s)ReadAllText\(\s*\$posixGateStatusPath' -Description 'unbounded POSIX gate status read'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'libSystem\.B\.dylib' -Description 'macOS native session library'
Assert-FileDoesNotContain -RelativePath 'scripts/private-marker-process.ps1' -Pattern '(?im)^\s*\$isMacOS\s*=' -Description 'read-only PowerShell IsMacOS automatic variable collision'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern '(?s)NativePosixSession.*?Marshal\]::GetLastWin32Error' -Description 'native setsid errno capture'
Assert-FileContains -RelativePath 'scripts/private-marker-process.ps1' -Pattern 'private-marker-posix-status-' -Description 'bounded POSIX gate status channel'
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
Assert-FileContains -RelativePath 'scripts/test-scan-private-markers.ps1' -Pattern 'native-gate-deadline' -Description 'native gate timeout and late-ready cleanup regression'
Assert-MacOSProcessFixtureBudgetContract -RelativePath 'scripts/test-scan-private-markers.ps1'
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
