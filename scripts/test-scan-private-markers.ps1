[CmdletBinding()]
param(
    [string]$Path = '',

    # macOS CI専用。Darwin runtimeと強制native setsid(2)経路を実測し、
    # genericなself-test成功だけをmacOS containment証跡にしない。
    [switch]$RequireMacOSNativePosixContainment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$selfTestScriptPath = $MyInvocation.MyCommand.Path

if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Split-Path -Parent $scriptRoot
}

$root = (Resolve-Path -LiteralPath $Path).Path
$scanner = Join-Path $root 'scripts/scan-private-markers.ps1'
if (-not (Test-Path -LiteralPath $scanner -PathType Leaf)) {
    throw "Missing scanner script: $scanner"
}
$processBoundary = Join-Path $root 'scripts/private-marker-process.ps1'
if (-not (Test-Path -LiteralPath $processBoundary -PathType Leaf)) {
    throw "Missing process boundary script: $processBoundary"
}
. $processBoundary

$currentPowerShellExecutable = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if ([string]::IsNullOrWhiteSpace($currentPowerShellExecutable) -or
    -not (Test-Path -LiteralPath $currentPowerShellExecutable -PathType Leaf)) {
    $hostExecutableName = if ($PSVersionTable.PSVersion.Major -le 5) {
        'powershell.exe'
    } elseif (Test-PrivateMarkerWindowsHost) {
        'pwsh.exe'
    } else {
        'pwsh'
    }
    $currentPowerShellExecutable = Join-Path $PSHOME $hostExecutableName
}
if (-not (Test-Path -LiteralPath $currentPowerShellExecutable -PathType Leaf)) {
    throw "Cannot resolve the current PowerShell host executable: $currentPowerShellExecutable"
}

$failures = New-Object System.Collections.Generic.List[string]
$posixGateEvidence = @{}
$macOSRuntimeCanaryPassed = $false
$macOSNativeContainmentVerified = $false
$posixNonzeroEvidenceRejected = $false

function Add-Failure {
    param([string]$Message)
    $failures.Add($Message) | Out-Null
}

function Test-PrivateMarkerPosixContainmentEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSessionGate,

        [bool]$DescendantStarted
    )

    # evidence判定を1か所へ固定し、gate/tree成功だけでtarget失敗を
    # macOS成功へ昇格させない。
    return [string]$Result.PosixSessionGate -ceq $ExpectedSessionGate -and
        $Result.PipeLeakDetected -and
        -not $Result.StreamsCompleted -and
        $Result.TreeStopped -and
        -not $Result.TimedOut -and
        -not $Result.OutputLimitExceeded -and
        -not $Result.InputWriteFailed -and
        $DescendantStarted -and
        $Result.ExitCode -eq 0
}

function Test-PrivateMarkerCommandIsDeferredDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.CommandAst]$Command
    )

    $ancestor = $Command.Parent
    while ($null -ne $ancestor) {
        if ($ancestor -is
                [System.Management.Automation.Language.FunctionDefinitionAst] -or
            $ancestor -is
                [System.Management.Automation.Language.FunctionMemberAst] -or
            $ancestor -is
                [System.Management.Automation.Language.TypeDefinitionAst]) {
            return $true
        }
        if ($ancestor -is
            [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
            # stored scriptblock は data だが、command argument や
            # .Invoke() / .InvokeReturnAsIs() 配下なら eager execution とみなす。
            $container = $ancestor.Parent
            $expressionCanExecuteScriptBlock = $false
            while ($null -ne $container) {
                if ($container -is
                        [System.Management.Automation.Language.FunctionDefinitionAst] -or
                    $container -is
                        [System.Management.Automation.Language.FunctionMemberAst] -or
                    $container -is
                        [System.Management.Automation.Language.TypeDefinitionAst]) {
                    return $true
                }
                if ($container -is
                        [System.Management.Automation.Language.CommandAst] -or
                    $container -is
                        [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
                    $expressionCanExecuteScriptBlock = $true
                    break
                }
                $container = $container.Parent
            }
            if (-not $expressionCanExecuteScriptBlock) {
                return $true
            }
        }
        $ancestor = $ancestor.Parent
    }
    return $false
}

function Test-PrivateMarkerAstIsDeferredDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Node
    )

    $ancestor = $Node.Parent
    while ($null -ne $ancestor) {
        if ($ancestor -is
                [System.Management.Automation.Language.FunctionDefinitionAst] -or
            $ancestor -is
                [System.Management.Automation.Language.FunctionMemberAst] -or
            $ancestor -is
                [System.Management.Automation.Language.TypeDefinitionAst]) {
            return $true
        }
        if ($ancestor -is
            [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
            $container = $ancestor.Parent
            while ($null -ne $container) {
                if ($container -is
                        [System.Management.Automation.Language.FunctionDefinitionAst] -or
                    $container -is
                        [System.Management.Automation.Language.FunctionMemberAst] -or
                    $container -is
                        [System.Management.Automation.Language.TypeDefinitionAst]) {
                    return $true
                }
                if ($container -is
                        [System.Management.Automation.Language.CommandAst] -or
                    $container -is
                        [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
                    break
                }
                $container = $container.Parent
            }
            if ($null -eq $container) {
                return $true
            }
        }
        $ancestor = $ancestor.Parent
    }
    return $false
}

function ConvertTo-PrivateMarkerCallableName {
    param([AllowEmptyString()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }
    $normalized = $Name
    # global scopeはcallerが事前配置したfunction/aliasを明示選択できる。
    # source-owned helperやbuiltinと同一視せず、unknown commandとして拒否する。
    if ($normalized -match '(?i)(?:^|:)global:') {
        return $normalized
    }
    while ($normalized -match
        '^(?i)(?:script|local|private):(?<rest>.+)$') {
        $normalized = $Matches['rest']
    }
    if ($normalized -match '^(?i)(?:function|alias):[\\/]*(?<rest>.+)$') {
        $normalized = $Matches['rest']
    }
    # module-qualified commandは末尾名だけをbuiltin/local helperと同一視しない。
    # provider形式を先に正規化し、それ以外の `Module\Command` はunknownの
    # ままpositive command setへ渡してfail closedさせる。
    if ($normalized -match '\\') {
        return $normalized
    }
    $builtinAliases = @{
        gcm = 'Get-Command'
        gi = 'Get-Item'
        gv = 'Get-Variable'
        sal = 'Set-Alias'
        nal = 'New-Alias'
        si = 'Set-Item'
        ni = 'New-Item'
        sv = 'Set-Variable'
        icm = 'Invoke-Command'
        iex = 'Invoke-Expression'
        percent = 'ForEach-Object'
        question = 'Where-Object'
    }
    $aliasKey = $normalized.ToLowerInvariant()
    if ($builtinAliases.ContainsKey($aliasKey)) {
        return $builtinAliases[$aliasKey]
    }
    return $normalized
}

function Get-PrivateMarkerStaticCommandValues {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.CommandAst]$Command
    )

    $values = New-Object System.Collections.Generic.List[string]
    $hasValueParameter = $false
    $isStatic = $true
    foreach ($element in @($Command.CommandElements | Select-Object -Skip 1)) {
        if ($element -is
            [System.Management.Automation.Language.CommandParameterAst]) {
            if ($element.ParameterName -eq 'Value') {
                $hasValueParameter = $true
            }
            if ($null -ne $element.Argument) {
                if ($element.Argument -isnot
                    [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $isStatic = $false
                    continue
                }
                $values.Add([string]$element.Argument.Value) | Out-Null
            }
            continue
        }
        if ($element -isnot
            [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $isStatic = $false
            continue
        }
        $values.Add([string]$element.Value) | Out-Null
    }
    return [pscustomobject]@{
        IsStatic = $isStatic
        Values = $values.ToArray()
        HasValueParameter = $hasValueParameter
    }
}

function Test-PrivateMarkerNodeBelongsToDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Node,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Definition
    )

    $ancestor = $Node.Parent
    while ($null -ne $ancestor) {
        if ($ancestor -is
            [System.Management.Automation.Language.FunctionDefinitionAst]) {
            if ($Definition -is
                [System.Management.Automation.Language.FunctionDefinitionAst]) {
                return [object]::ReferenceEquals($ancestor, $Definition)
            }
        }
        if ($ancestor -is
            [System.Management.Automation.Language.TypeDefinitionAst]) {
            return [object]::ReferenceEquals($ancestor, $Definition)
        }
        $ancestor = $ancestor.Parent
    }
    return $false
}

function Get-PrivateMarkerLexicalScopeOwner {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Node
    )

    $ancestor = $Node
    while ($null -ne $ancestor) {
        if ($ancestor -is
                [System.Management.Automation.Language.FunctionDefinitionAst] -or
            $ancestor -is
                [System.Management.Automation.Language.FunctionMemberAst] -or
            $ancestor -is
                [System.Management.Automation.Language.TypeDefinitionAst]) {
            return $ancestor
        }
        if ($ancestor -is
                [System.Management.Automation.Language.ScriptBlockAst] -and
            $null -eq $ancestor.Parent) {
            return $ancestor
        }
        $ancestor = $ancestor.Parent
    }
    return $null
}

function Test-PrivateMarkerAssignmentDominatesReference {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.AssignmentStatementAst]
        $Assignment,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$ReferenceNode
    )

    # compound assignmentはambient初期値を保持し得るため、source-ownedな
    # 完全上書きとして扱わない。代入は実行blockの直下だけを候補にする。
    if ($Assignment.Operator -ne
            [System.Management.Automation.Language.TokenKind]::Equals -or
        (
            $Assignment.Parent -isnot
                [System.Management.Automation.Language.NamedBlockAst] -and
            $Assignment.Parent -isnot
                [System.Management.Automation.Language.StatementBlockAst]
        )) {
        return $false
    }

    # bindingの直親blockがreferenceのancestorなら、そのblock内でreferenceへ
    # 到達する全経路は先行代入を通る。loop/branch内でも同じbodyの後続参照は
    # 許可する一方、body外の参照ではancestorにならず未実行経路を拒否できる。
    $ancestor = $ReferenceNode
    while ($null -ne $ancestor) {
        if ([object]::ReferenceEquals($ancestor, $Assignment.Parent)) {
            return $true
        }
        $ancestor = $ancestor.Parent
    }
    return $false
}

function Test-PrivateMarkerVariableIsSourceBound {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.VariableExpressionAst]$Variable,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$ReferenceNode,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst]$AnalysisRoot,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.AssignmentStatementAst[]]
        $AnalysisAssignments
    )

    $variableName = [string]$Variable.VariablePath.UserPath
    if ($variableName -in @(
            '_',
            'PSItem',
            'true',
            'false',
            'null',
            'this',
            'args',
            'input',
            'Matches',
            'PSScriptRoot',
            'PSHOME',
            'PSVersionTable',
            'MyInvocation',
            'LASTEXITCODE'
        )) {
        return $true
    }
    if ($variableName -match '^(?i)(?:env|function|alias):') {
        return $false
    }

    $referenceScope =
        Get-PrivateMarkerLexicalScopeOwner -Node $ReferenceNode
    if ($null -eq $referenceScope) {
        return $false
    }

    # enclosing function/scriptblock parameters and foreach variables are
    # lexical inputs owned by the reviewed source, not caller-scope lookups.
    $ancestor = $Variable.Parent
    while ($null -ne $ancestor) {
        if ($ancestor -is
                [System.Management.Automation.Language.ScriptBlockAst] -and
            $null -ne $ancestor.ParamBlock) {
            foreach ($parameter in @($ancestor.ParamBlock.Parameters)) {
                if ([string]$parameter.Name.VariablePath.UserPath -ceq
                    $variableName) {
                    # function/script entry parameters can carry caller-owned
                    # objects. Only fixed primitive/AST types are trusted;
                    # literal callback blocks own their local param values.
                    if ($ancestor.Parent -isnot
                            [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $ancestor.Parent -isnot
                            [System.Management.Automation.Language.FunctionMemberAst] -and
                        $null -ne $ancestor.Parent) {
                        return $true
                    }
                    $parameterTypeName = ''
                    foreach ($attribute in @($parameter.Attributes)) {
                        if ($attribute -is
                            [System.Management.Automation.Language.TypeConstraintAst]) {
                            $parameterTypeName =
                                [string]$attribute.TypeName.FullName
                            break
                        }
                    }
                    return $parameterTypeName -in @(
                        'byte[]',
                        'hashtable',
                        'int',
                        'string',
                        'string[]',
                        'System.Management.Automation.Language.Ast',
                        'System.Management.Automation.Language.AssignmentStatementAst[]',
                        'System.Management.Automation.Language.CommandAst',
                        'System.Management.Automation.Language.InvokeMemberExpressionAst',
                        'System.Management.Automation.Language.ScriptBlockAst',
                        'System.Management.Automation.Language.VariableExpressionAst'
                    )
                }
            }
        }
        if ($ancestor -is
                [System.Management.Automation.Language.ForEachStatementAst] -and
            [string]$ancestor.Variable.VariablePath.UserPath -ceq
                $variableName) {
            # foreach変数はsource内で宣言されても、列挙元がambient objectなら
            # receiver dispatchへそのobjectを運べる。body内の参照だけを候補にし、
            # Conditionが参照する全変数も再帰的にsource-boundであることを要求する。
            $foreachChild = $Variable
            while ($null -ne $foreachChild.Parent -and
                -not [object]::ReferenceEquals(
                    $foreachChild.Parent,
                    $ancestor
                )) {
                $foreachChild = $foreachChild.Parent
            }
            if ([object]::ReferenceEquals(
                    $foreachChild,
                    $ancestor.Body
                )) {
                $enumerationVariables = @(
                    $ancestor.Condition.FindAll(
                        {
                            param($node)
                            return $node -is
                                [System.Management.Automation.Language.VariableExpressionAst]
                        },
                        $true
                    )
                )
                foreach ($enumerationVariable in $enumerationVariables) {
                    if (-not (Test-PrivateMarkerVariableIsSourceBound `
                            -Variable $enumerationVariable `
                            -ReferenceNode $enumerationVariable `
                            -AnalysisRoot $AnalysisRoot `
                            -AnalysisAssignments $AnalysisAssignments)) {
                        return $false
                    }
                }
                return $true
            }
        }
        if ([object]::ReferenceEquals($ancestor, $referenceScope)) {
            break
        }
        $ancestor = $ancestor.Parent
    }

    $sourceRoot = $ReferenceNode
    while ($null -ne $sourceRoot.Parent) {
        $sourceRoot = $sourceRoot.Parent
    }
    # 同じpolicy評価中はvariable assignment ASTを一度だけ列挙する。foreach
    # provenanceの再帰ごとに巨大なself-test AST全体を再走査しない。
    $sourceAssignments = if ([object]::ReferenceEquals(
            $sourceRoot,
            $AnalysisRoot
        )) {
        @($AnalysisAssignments)
    } else {
        @(
            $sourceRoot.FindAll(
                {
                    param($node)
                    return $node -is
                            [System.Management.Automation.Language.AssignmentStatementAst] -and
                        $node.Left -is
                            [System.Management.Automation.Language.VariableExpressionAst]
                },
                $true
            )
        )
    }
    $priorBindings = @(
        $sourceAssignments |
            Where-Object {
                [string]$_.Left.VariablePath.UserPath -ceq
                    $variableName -and
                $_.Extent.EndOffset -le
                    $ReferenceNode.Extent.StartOffset -and
                (
                    [object]::ReferenceEquals(
                        (Get-PrivateMarkerLexicalScopeOwner -Node $_),
                        $referenceScope
                    ) -or
                    (
                        -not [object]::ReferenceEquals(
                            $referenceScope,
                            $sourceRoot
                        ) -and
                        [object]::ReferenceEquals(
                            (Get-PrivateMarkerLexicalScopeOwner -Node $_),
                            $sourceRoot
                        ) -and
                        $_.Extent.EndOffset -le
                            $referenceScope.Extent.StartOffset
                    )
                )
            }
    )
    $orderedBindings = @(
        $priorBindings | Sort-Object { $_.Extent.StartOffset } -Descending
    )
    if ($orderedBindings.Count -eq 0) {
        return $false
    }

    # 最後の無条件完全上書きを全経路のsource-owned基底にする。これが無ければ
    # conditional/0回loopが未実行の経路でambient値へ戻るため拒否する。
    $dominatingBinding = $null
    foreach ($binding in $orderedBindings) {
        if (Test-PrivateMarkerAssignmentDominatesReference `
                -Assignment $binding `
                -ReferenceNode $ReferenceNode) {
            $dominatingBinding = $binding
            break
        }
    }
    if ($null -eq $dominatingBinding) {
        return $false
    }

    # 基底より後のconditional bindingは実行される場合/されない場合の双方が
    # referenceへ到達し得る。全候補が完全上書きかつsource-boundなときだけ許可し、
    # ambient再代入やcompound assignmentを一つでも含めばfail closedにする。
    $reachingBindings = @(
        $priorBindings |
            Where-Object {
                $_.Extent.StartOffset -ge
                    $dominatingBinding.Extent.StartOffset
            } |
            Sort-Object { $_.Extent.StartOffset }
    )
    foreach ($binding in $reachingBindings) {
        if ($binding.Operator -ne
            [System.Management.Automation.Language.TokenKind]::Equals) {
            return $false
        }
        $bindingVariables = @(
            $binding.Right.FindAll(
                {
                    param($node)
                    return $node -is
                        [System.Management.Automation.Language.VariableExpressionAst]
                },
                $true
            )
        )
        foreach ($bindingVariable in $bindingVariables) {
            if (-not (Test-PrivateMarkerVariableIsSourceBound `
                    -Variable $bindingVariable `
                    -ReferenceNode $binding `
                    -AnalysisRoot $AnalysisRoot `
                    -AnalysisAssignments $AnalysisAssignments)) {
                return $false
            }
        }
    }
    return $true
}

function Test-PrivateMarkerMemberCanInvokeStoredCode {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.InvokeMemberExpressionAst]
        $MemberCall,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst]$AnalysisRoot,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.AssignmentStatementAst[]]
        $AnalysisAssignments
    )

    if ($MemberCall.Member -isnot
        [System.Management.Automation.Language.StringConstantExpressionAst]) {
        return $true
    }
    $memberName = [string]$MemberCall.Member.Value
    $receiver = $MemberCall.Expression

    # static dispatchはtype/memberの組を固定し、同名custom typeへ広げない。
    if ($receiver -is
        [System.Management.Automation.Language.TypeExpressionAst]) {
        $staticPair =
            ([string]$receiver.TypeName.FullName) + '::' + $memberName
        return $staticPair -notin @(
            'Convert::ToBase64String',
            'Environment::GetEnvironmentVariables',
            'object::ReferenceEquals',
            'string::IsNullOrEmpty',
            'string::IsNullOrWhiteSpace',
            'System.Collections.Generic.HashSet[string]::new',
            'System.Diagnostics.Process::GetCurrentProcess',
            'System.Guid::NewGuid',
            'System.IO.File::ReadAllText',
            'System.IO.File::WriteAllLines',
            'System.IO.File::WriteAllText',
            'System.IO.Path::GetTempPath',
            'System.Management.Automation.Language.Parser::ParseInput',
            'System.Management.Automation.WildcardPattern::ContainsWildcardCharacters',
            'System.Text.UTF8Encoding::new'
        )
    }

    # instance dispatchはmember名だけでなくreceiver AST shapeもpositive化する。
    # Add/FindAllという安全そうな名前をambient ScriptMethodが実装しても、
    # source内にbindingのないreceiver/argumentはここで拒否する。
    $shapeAllowed = $false
    if ($receiver -is
        [System.Management.Automation.Language.VariableExpressionAst]) {
        $shapeAllowed = $memberName -in @(
            'Add',
            'Contains',
            'ContainsKey',
            'FindAll',
            'GetCommandName',
            'LastIndexOf',
            'Substring',
            'ToArray',
            'ToLowerInvariant',
            'ToString'
        )
    } elseif ($receiver -is
        [System.Management.Automation.Language.IndexExpressionAst]) {
        $shapeAllowed = $memberName -ceq 'GetCommandName'
    } elseif ($receiver -is
        [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
        $innerMember = if ($receiver.Member -is
            [System.Management.Automation.Language.StringConstantExpressionAst]) {
            [string]$receiver.Member.Value
        } else {
            ''
        }
        $innerType = if ($receiver.Expression -is
            [System.Management.Automation.Language.TypeExpressionAst]) {
            [string]$receiver.Expression.TypeName.FullName
        } else {
            ''
        }
        $shapeAllowed = (
            ($memberName -ceq 'GetString' -and
                $innerMember -ceq 'new' -and
                $innerType -ceq 'System.Text.UTF8Encoding') -or
            ($memberName -ceq 'ToString' -and
                $innerMember -ceq 'NewGuid' -and
                $innerType -ceq 'System.Guid')
        )
    } elseif ($receiver -is
        [System.Management.Automation.Language.MemberExpressionAst]) {
        $receiverMember = if ($receiver.Member -is
            [System.Management.Automation.Language.StringConstantExpressionAst]) {
            [string]$receiver.Member.Value
        } else {
            ''
        }
        $shapeAllowed = (
            ($memberName -ceq 'FindAll' -and
                $receiverMember -in @('Right', 'Condition')) -or
            ($memberName -ceq 'Trim' -and
                $receiverMember -ceq 'Output') -or
            ($memberName -ceq 'GetBytes' -and
                $receiverMember -ceq 'UTF8' -and
                $receiver.Expression -is
                    [System.Management.Automation.Language.TypeExpressionAst] -and
                [string]$receiver.Expression.TypeName.FullName -ceq
                    'System.Text.Encoding')
        )
    } elseif ($receiver -is
        [System.Management.Automation.Language.ParenExpressionAst]) {
        $shapeAllowed = $memberName -ceq 'TrimEnd'
    }
    if (-not $shapeAllowed) {
        return $true
    }

    $memberVariables = @(
        $MemberCall.FindAll(
            {
                param($node)
                return $node -is
                    [System.Management.Automation.Language.VariableExpressionAst]
            },
            $true
        )
    )
    foreach ($variable in $memberVariables) {
        if (-not (Test-PrivateMarkerVariableIsSourceBound `
                -Variable $variable `
                -ReferenceNode $MemberCall `
                -AnalysisRoot $AnalysisRoot `
                -AnalysisAssignments $AnalysisAssignments)) {
            return $true
        }
    }
    return $false
}

function Test-PrivateMarkerCommandCanInvokeIndirectScriptBlock {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.CommandAst]$Command
    )

    $commandName =
        ConvertTo-PrivateMarkerCallableName $Command.GetCommandName()
    if ($commandName -eq 'Get-Variable') {
        return $true
    }
    $scriptBlockConsumers = @(
        'Compare-Object',
        'ForEach-Object',
        'Format-Custom',
        'Format-List',
        'Format-Table',
        'Format-Wide',
        'Group-Object',
        'Measure-Command',
        'Measure-Object',
        'Register-ArgumentCompleter',
        'Register-EngineEvent',
        'Register-ObjectEvent',
        'Register-WmiEvent',
        'Select-Object',
        'Set-PSBreakpoint',
        'Sort-Object',
        'Start-Job',
        'Start-ThreadJob',
        'Trace-Command',
        'Use-Transaction',
        'Where-Object'
    )
    if ($commandName -notin $scriptBlockConsumers) {
        return $false
    }

    $hasLiteralBlock = $false
    foreach ($element in @($Command.CommandElements)) {
        if ($element -is
            [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
            $hasLiteralBlock = $true
        }
    }
    foreach ($variable in @($Command.FindAll(
                {
                    param($node)
                    return $node -is
                        [System.Management.Automation.Language.VariableExpressionAst]
                },
                $true
            ))) {
        $insideLiteralBlock = $false
        $ancestor = $variable.Parent
        while ($null -ne $ancestor -and
            -not [object]::ReferenceEquals($ancestor, $Command)) {
            if ($ancestor -is
                [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
                $insideLiteralBlock = $true
                break
            }
            $ancestor = $ancestor.Parent
        }
        if (-not $insideLiteralBlock -and
            $variable.VariablePath.UserPath -notin @('_', 'PSItem')) {
            return $true
        }
    }
    if ($hasLiteralBlock) {
        # literal blockは同じsource AST内のCommandAstとして別途検査できる。
        return $false
    }

    # ForEach/Whereはproperty-name modeを持たず、literal blockが無ければ
    # caller scopeやparameter bindingから実行対象を持ち込めるため拒否する。
    return $commandName -in @('ForEach-Object', 'Where-Object')
}

function Test-FirstProcessInvocationPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $tokens = $null
    $parseErrors = $null
    $sourceAst = [System.Management.Automation.Language.Parser]::ParseInput(
        $Source,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        return $false
    }
    $sourceAssignments = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is
                        [System.Management.Automation.Language.VariableExpressionAst]
            },
            $true
        )
    )
    $targetCommandName = 'Invoke-PrivateMarkerProcess'

    $rawAssignments = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is
                        [System.Management.Automation.Language.VariableExpressionAst] -and
                    $node.Left.VariablePath.UserPath -eq 'rawTransportResult'
            },
            $true
        )
    )
    if ($rawAssignments.Count -ne 1 -or
        $rawAssignments[0].Right -isnot
            [System.Management.Automation.Language.PipelineAst]) {
        return $false
    }
    $rawPipelineElements = @($rawAssignments[0].Right.PipelineElements)
    if ($rawPipelineElements.Count -ne 1 -or
        $rawPipelineElements[0] -isnot
            [System.Management.Automation.Language.CommandAst] -or
        (ConvertTo-PrivateMarkerCallableName `
            $rawPipelineElements[0].GetCommandName()) -cne
            $targetCommandName) {
        return $false
    }
    $rawOuterCommand = $rawPipelineElements[0]
    if (Test-PrivateMarkerAstIsDeferredDefinition -Node $rawOuterCommand) {
        return $false
    }
    $rawTargetCalls = @(
        $rawAssignments[0].Right.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.CommandAst] -and
                    (ConvertTo-PrivateMarkerCallableName `
                        $node.GetCommandName()) -ceq
                        $targetCommandName
            },
            $true
        )
    )
    if ($rawTargetCalls.Count -ne 1 -or
        @($rawOuterCommand.FindAll(
                {
                    param($node)
                    return $node -is
                            [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
                        $node -is
                            [System.Management.Automation.Language.ScriptBlockExpressionAst]
                },
                $true
            )).Count -gt 0) {
        return $false
    }
    $rawOffset = $rawOuterCommand.Extent.StartOffset

    $functionDefinitions = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Extent.StartOffset -lt $rawOffset
            },
            $true
        )
    )
    # pre-rawで呼べるprimitive commandとtop-level local functionをpositive
    # setへ固定する。nested/unrelated definition名やambient/autoloaded commandは
    # wrapper内でも安全と推測せず、eager callへriskを伝播させる。
    $safePrimitiveCommands =
        [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    foreach ($safePrimitiveCommand in @(
            'ForEach-Object',
            'Get-ChildItem',
            'Get-Command',
            'Join-Path',
            'New-Item',
            'New-Object',
            'Out-Null',
            'Resolve-Path',
            'Select-Object',
            'Set-StrictMode',
            'Sort-Object',
            'Split-Path',
            'Test-Path',
            'Test-PrivateMarkerWindowsHost',
            'Where-Object'
        )) {
        [void]$safePrimitiveCommands.Add($safePrimitiveCommand)
    }
    $topLevelFunctionDefinitions = @(
        $functionDefinitions | Where-Object {
            $_.Parent -is
                [System.Management.Automation.Language.NamedBlockAst] -and
            [object]::ReferenceEquals($_.Parent.Parent, $sourceAst)
        }
    )
    $topLevelDefinitionEndOffsets = @{}
    foreach ($definition in $topLevelFunctionDefinitions) {
        $definitionName =
            ConvertTo-PrivateMarkerCallableName $definition.Name
        if ($topLevelDefinitionEndOffsets.ContainsKey($definitionName)) {
            # duplicate definitionはどちらが実行時bindingかを推測しない。
            $topLevelDefinitionEndOffsets[$definitionName] = -1
        } else {
            $topLevelDefinitionEndOffsets[$definitionName] =
                $definition.Extent.EndOffset
        }
    }
    foreach ($definition in $functionDefinitions) {
        if ((ConvertTo-PrivateMarkerCallableName $definition.Name) -ceq
            $targetCommandName) {
            return $false
        }
    }
    $typeDefinitions = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.TypeDefinitionAst] -and
                    $node.Extent.StartOffset -lt $rawOffset
            },
            $true
        )
    )
    $riskyFunctions =
        [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    $riskyTypes =
        [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    # runtime生成したScriptBlockはsource AST内にpayloadのCommandAstを持たない。
    # 型aliasと完全名を最初から危険集合へ置き、eager式とwrapper関数の双方で
    # `[scriptblock]::Create(...)` を positive-safe-set の外へ出す。
    [void]$riskyTypes.Add('scriptblock')
    [void]$riskyTypes.Add('System.Management.Automation.ScriptBlock')

    $riskChanged = $true
    while ($riskChanged) {
        $riskChanged = $false
        foreach ($definition in $functionDefinitions) {
            $definitionName =
                ConvertTo-PrivateMarkerCallableName $definition.Name
            if ($riskyFunctions.Contains($definitionName)) {
                continue
            }
            $definitionRisky = $false
            $ownedCommands = @(
                $definition.FindAll(
                    {
                        param($node)
                        return $node -is
                            [System.Management.Automation.Language.CommandAst]
                    },
                    $true
                ) | Where-Object {
                    Test-PrivateMarkerNodeBelongsToDefinition `
                        -Node $_ `
                        -Definition $definition
                }
            )
            foreach ($command in $ownedCommands) {
                $commandName =
                    ConvertTo-PrivateMarkerCallableName $command.GetCommandName()
                $dynamicInvocation = [string]::IsNullOrEmpty($commandName) -and
                    @('Ampersand', 'Dot') -contains
                        ([string]$command.InvocationOperator)
                $definitionCommandAvailable =
                    $safePrimitiveCommands.Contains($commandName)
                if (-not $definitionCommandAvailable -and
                    $commandName -ceq $definitionName) {
                    # self recursionはdefinition全体がinstallされた後にだけ実行される。
                    $definitionCommandAvailable = $true
                }
                if (-not $definitionCommandAvailable -and
                    $topLevelDefinitionEndOffsets.ContainsKey($commandName) -and
                    $topLevelDefinitionEndOffsets[$commandName] -gt 0 -and
                    $topLevelDefinitionEndOffsets[$commandName] -le
                        $definition.Extent.StartOffset) {
                    $definitionCommandAvailable = $true
                }
                $unknownDefinitionCommand =
                    [string]::IsNullOrEmpty($commandName) -or
                    -not $definitionCommandAvailable
                $mutatesCallableOrBootstrap = $commandName -in @(
                    'Set-Alias',
                    'New-Alias',
                    'Set-Item',
                    'Set-Content',
                    'Set-Variable',
                    'New-Variable'
                )
                if ($commandName -ceq $targetCommandName -or
                    $riskyFunctions.Contains($commandName) -or
                    $commandName -in @(
                        'Invoke-Command',
                        'Invoke-Expression'
                    ) -or
                    (Test-PrivateMarkerCommandCanInvokeIndirectScriptBlock `
                        -Command $command) -or
                    $unknownDefinitionCommand -or
                    $dynamicInvocation -or
                    $mutatesCallableOrBootstrap) {
                    $definitionRisky = $true
                    break
                }
                if ($commandName -eq 'New-Item' -and
                    (Get-PrivateMarkerStaticCommandValues `
                        -Command $command).HasValueParameter) {
                    $definitionRisky = $true
                    break
                }
            }
            if (-not $definitionRisky) {
                $ownedMemberCalls = @(
                    $definition.FindAll(
                        {
                            param($node)
                            return $node -is
                                [System.Management.Automation.Language.InvokeMemberExpressionAst]
                        },
                        $true
                    ) | Where-Object {
                        Test-PrivateMarkerNodeBelongsToDefinition `
                            -Node $_ `
                            -Definition $definition
                    }
                )
                foreach ($memberCall in $ownedMemberCalls) {
                    if (Test-PrivateMarkerMemberCanInvokeStoredCode `
                        -MemberCall $memberCall `
                        -AnalysisRoot $sourceAst `
                        -AnalysisAssignments $sourceAssignments) {
                        $definitionRisky = $true
                        break
                    }
                }
            }
            if (-not $definitionRisky) {
                $ownedFunctionReferences = @(
                    $definition.FindAll(
                        {
                            param($node)
                            return $node -is
                                [System.Management.Automation.Language.VariableExpressionAst]
                        },
                        $true
                    ) | Where-Object {
                        (Test-PrivateMarkerNodeBelongsToDefinition `
                            -Node $_ `
                            -Definition $definition) -and
                        $_.VariablePath.UserPath -match
                            '^(?i)(?:function|alias):'
                    }
                )
                foreach ($reference in $ownedFunctionReferences) {
                    $referenceName = ConvertTo-PrivateMarkerCallableName `
                        $reference.VariablePath.UserPath
                    if ($referenceName -ceq $targetCommandName -or
                        $riskyFunctions.Contains($referenceName)) {
                        $definitionRisky = $true
                        break
                    }
                }
            }
            if (-not $definitionRisky) {
                $ownedTypeReferences = @(
                    $definition.FindAll(
                        {
                            param($node)
                            return $node -is
                                    [System.Management.Automation.Language.TypeExpressionAst] -or
                                $node -is
                                    [System.Management.Automation.Language.TypeConstraintAst]
                        },
                        $true
                    ) | Where-Object {
                        Test-PrivateMarkerNodeBelongsToDefinition `
                            -Node $_ `
                            -Definition $definition
                    }
                )
                foreach ($reference in $ownedTypeReferences) {
                    if ($riskyTypes.Contains(
                        [string]$reference.TypeName.FullName
                    )) {
                        $definitionRisky = $true
                        break
                    }
                }
            }
            if ($definitionRisky -and
                $riskyFunctions.Add($definitionName)) {
                $riskChanged = $true
            }
        }

        foreach ($definition in $typeDefinitions) {
            $definitionName = [string]$definition.Name
            if ($riskyTypes.Contains($definitionName)) {
                continue
            }
            $definitionRisky = $false
            foreach ($baseType in @($definition.BaseTypes)) {
                if ($riskyTypes.Contains(
                    [string]$baseType.TypeName.FullName
                )) {
                    $definitionRisky = $true
                    break
                }
            }
            if (-not $definitionRisky) {
                $ownedCommands = @(
                    $definition.FindAll(
                        {
                            param($node)
                            return $node -is
                                [System.Management.Automation.Language.CommandAst]
                        },
                        $true
                    ) | Where-Object {
                        Test-PrivateMarkerNodeBelongsToDefinition `
                            -Node $_ `
                            -Definition $definition
                    }
                )
                foreach ($command in $ownedCommands) {
                    $commandName = ConvertTo-PrivateMarkerCallableName `
                        $command.GetCommandName()
                    $dynamicInvocation =
                        [string]::IsNullOrEmpty($commandName) -and
                        @('Ampersand', 'Dot') -contains
                            ([string]$command.InvocationOperator)
                    $definitionCommandAvailable =
                        $safePrimitiveCommands.Contains($commandName)
                    if (-not $definitionCommandAvailable -and
                        $topLevelDefinitionEndOffsets.ContainsKey($commandName) -and
                        $topLevelDefinitionEndOffsets[$commandName] -gt 0 -and
                        $topLevelDefinitionEndOffsets[$commandName] -le
                            $definition.Extent.StartOffset) {
                        $definitionCommandAvailable = $true
                    }
                    $unknownDefinitionCommand =
                        [string]::IsNullOrEmpty($commandName) -or
                        -not $definitionCommandAvailable
                    if ($commandName -ceq $targetCommandName -or
                        $riskyFunctions.Contains($commandName) -or
                        $commandName -in @(
                            'Invoke-Command',
                            'Invoke-Expression'
                        ) -or
                        (Test-PrivateMarkerCommandCanInvokeIndirectScriptBlock `
                            -Command $command) -or
                        $unknownDefinitionCommand -or
                        $dynamicInvocation) {
                        $definitionRisky = $true
                        break
                    }
                }
            }
            if (-not $definitionRisky) {
                $ownedMemberCalls = @(
                    $definition.FindAll(
                        {
                            param($node)
                            return $node -is
                                [System.Management.Automation.Language.InvokeMemberExpressionAst]
                        },
                        $true
                    ) | Where-Object {
                        Test-PrivateMarkerNodeBelongsToDefinition `
                            -Node $_ `
                            -Definition $definition
                    }
                )
                foreach ($memberCall in $ownedMemberCalls) {
                    if (Test-PrivateMarkerMemberCanInvokeStoredCode `
                        -MemberCall $memberCall `
                        -AnalysisRoot $sourceAst `
                        -AnalysisAssignments $sourceAssignments) {
                        $definitionRisky = $true
                        break
                    }
                }
            }
            if (-not $definitionRisky) {
                $ownedTypeReferences = @(
                    $definition.FindAll(
                        {
                            param($node)
                            return $node -is
                                    [System.Management.Automation.Language.TypeExpressionAst] -or
                                $node -is
                                    [System.Management.Automation.Language.TypeConstraintAst]
                        },
                        $true
                    ) | Where-Object {
                        Test-PrivateMarkerNodeBelongsToDefinition `
                            -Node $_ `
                            -Definition $definition
                    }
                )
                foreach ($reference in $ownedTypeReferences) {
                    if ($riskyTypes.Contains(
                        [string]$reference.TypeName.FullName
                    )) {
                        $definitionRisky = $true
                        break
                    }
                }
            }
            if ($definitionRisky -and
                $riskyTypes.Add($definitionName)) {
                $riskChanged = $true
            }
        }
    }

    # helper bootstrap は固定相対pathの通常代入1件からのdot-sourceだけを許す。
    $preRawDotSources = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.CommandAst] -and
                    $node.Extent.StartOffset -lt $rawOffset -and
                    ([string]$node.InvocationOperator) -eq 'Dot'
            },
            $true
        ) | Where-Object {
            -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
        }
    )
    if ($preRawDotSources.Count -gt 0) {
        if ($preRawDotSources.Count -ne 1) {
            return $false
        }
        $dotSourceElements = @($preRawDotSources[0].CommandElements)
        if ($dotSourceElements.Count -ne 1 -or
            $dotSourceElements[0] -isnot
                [System.Management.Automation.Language.VariableExpressionAst] -or
            $dotSourceElements[0].VariablePath.UserPath -cne
                'processBoundary') {
            return $false
        }
        $bootstrapAssignments = @(
            $sourceAst.FindAll(
                {
                    param($node)
                    return $node -is
                            [System.Management.Automation.Language.AssignmentStatementAst] -and
                        $node.Left -is
                            [System.Management.Automation.Language.VariableExpressionAst] -and
                        (ConvertTo-PrivateMarkerCallableName `
                            $node.Left.VariablePath.UserPath) -ceq
                            'processBoundary' -and
                        $node.Extent.StartOffset -lt
                            $preRawDotSources[0].Extent.StartOffset
                },
                $true
            ) | Where-Object {
                -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
            }
        )
        if ($bootstrapAssignments.Count -ne 1 -or
            $bootstrapAssignments[0].Right -isnot
                [System.Management.Automation.Language.PipelineAst]) {
            return $false
        }
        $bootstrapPipeline =
            @($bootstrapAssignments[0].Right.PipelineElements)
        if ($bootstrapPipeline.Count -ne 1 -or
            $bootstrapPipeline[0] -isnot
                [System.Management.Automation.Language.CommandAst] -or
            (ConvertTo-PrivateMarkerCallableName `
                $bootstrapPipeline[0].GetCommandName()) -cne 'Join-Path') {
            return $false
        }
        $bootstrapElements = @($bootstrapPipeline[0].CommandElements)
        if ($bootstrapElements.Count -ne 3 -or
            $bootstrapElements[1] -isnot
                [System.Management.Automation.Language.VariableExpressionAst] -or
            $bootstrapElements[1].VariablePath.UserPath -cne 'root' -or
            $bootstrapElements[2] -isnot
                [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $bootstrapElements[2].Value -cne
                'scripts/private-marker-process.ps1') {
            return $false
        }
    }

    $riskyStoredVariables =
        [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    $storedAssignments = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is
                        [System.Management.Automation.Language.VariableExpressionAst] -and
                    $node.Extent.StartOffset -lt $rawOffset
            },
            $true
        ) | Where-Object {
            -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
        }
    )
    foreach ($assignment in $storedAssignments) {
        $scriptBlocks = @(
            $assignment.Right.FindAll(
                {
                    param($node)
                    return $node -is
                        [System.Management.Automation.Language.ScriptBlockExpressionAst]
                },
                $true
            )
        )
        foreach ($scriptBlock in $scriptBlocks) {
            $storedRisky = $false
            foreach ($command in @($scriptBlock.FindAll(
                        {
                            param($node)
                            return $node -is
                                [System.Management.Automation.Language.CommandAst]
                        },
                        $true
                    ))) {
                $commandName = ConvertTo-PrivateMarkerCallableName `
                    $command.GetCommandName()
                $storedCommandAvailable =
                    $safePrimitiveCommands.Contains($commandName)
                if (-not $storedCommandAvailable -and
                    $topLevelDefinitionEndOffsets.ContainsKey($commandName) -and
                    $topLevelDefinitionEndOffsets[$commandName] -gt 0 -and
                    $topLevelDefinitionEndOffsets[$commandName] -le
                        $assignment.Extent.StartOffset) {
                    $storedCommandAvailable = $true
                }
                $unknownStoredCommand =
                    [string]::IsNullOrEmpty($commandName) -or
                    -not $storedCommandAvailable
                if ($commandName -ceq $targetCommandName -or
                    $riskyFunctions.Contains($commandName) -or
                    $commandName -in @(
                        'Invoke-Command',
                        'Invoke-Expression'
                    ) -or
                    (Test-PrivateMarkerCommandCanInvokeIndirectScriptBlock `
                        -Command $command) -or
                    $unknownStoredCommand -or
                    ([string]::IsNullOrEmpty($commandName) -and
                        @('Ampersand', 'Dot') -contains
                            ([string]$command.InvocationOperator))) {
                    $storedRisky = $true
                    break
                }
            }
            if (-not $storedRisky) {
                foreach ($memberCall in @($scriptBlock.FindAll(
                            {
                                param($node)
                                return $node -is
                                    [System.Management.Automation.Language.InvokeMemberExpressionAst]
                            },
                            $true
                        ))) {
                    if (Test-PrivateMarkerMemberCanInvokeStoredCode `
                        -MemberCall $memberCall `
                        -AnalysisRoot $sourceAst `
                        -AnalysisAssignments $sourceAssignments) {
                        $storedRisky = $true
                        break
                    }
                }
            }
            if ($storedRisky) {
                $storedVariableName =
                    ConvertTo-PrivateMarkerCallableName `
                        $assignment.Left.VariablePath.UserPath
                [void]$riskyStoredVariables.Add($storedVariableName)
                break
            }
        }
    }
    foreach ($storedName in $riskyStoredVariables) {
        $assignment = @($storedAssignments | Where-Object {
                (ConvertTo-PrivateMarkerCallableName `
                    $_.Left.VariablePath.UserPath) -ceq $storedName
            } | Select-Object -First 1)
        $laterReferences = @(
            $sourceAst.FindAll(
                {
                    param($node)
                    return $node -is
                        [System.Management.Automation.Language.VariableExpressionAst]
                },
                $true
            ) | Where-Object {
                $_.Extent.StartOffset -gt $assignment[0].Extent.EndOffset -and
                $_.Extent.StartOffset -lt $rawOffset -and
                (ConvertTo-PrivateMarkerCallableName `
                    $_.VariablePath.UserPath) -ceq $storedName -and
                -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
            }
        )
        if ($laterReferences.Count -gt 0) {
            return $false
        }
    }

    $eagerTypeReferences = @(
        $sourceAst.FindAll(
            {
                param($node)
                return ($node -is
                            [System.Management.Automation.Language.TypeExpressionAst] -or
                        $node -is
                            [System.Management.Automation.Language.TypeConstraintAst]) -and
                    $node.Extent.StartOffset -lt $rawOffset
            },
            $true
        ) | Where-Object {
            -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
        }
    )
    foreach ($reference in $eagerTypeReferences) {
        if ($riskyTypes.Contains([string]$reference.TypeName.FullName)) {
            return $false
        }
    }

    $eagerFunctionProviderReferences = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.VariableExpressionAst] -and
                    $node.Extent.StartOffset -lt $rawOffset -and
                    $node.VariablePath.UserPath -match
                        '^(?i)(?:function|alias):'
            },
            $true
        ) | Where-Object {
            -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
        }
    )
    foreach ($reference in $eagerFunctionProviderReferences) {
        $referenceName = ConvertTo-PrivateMarkerCallableName `
            $reference.VariablePath.UserPath
        if ($referenceName -ceq $targetCommandName -or
            $riskyFunctions.Contains($referenceName)) {
            return $false
        }
    }

    $eagerInvokeMembers = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                    $node.Extent.StartOffset -lt $rawOffset
            },
            $true
        ) | Where-Object {
            -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
        }
    )
    foreach ($memberCall in $eagerInvokeMembers) {
        if (Test-PrivateMarkerMemberCanInvokeStoredCode `
            -MemberCall $memberCall `
            -AnalysisRoot $sourceAst `
            -AnalysisAssignments $sourceAssignments) {
            return $false
        }
    }

    $allowedEagerCommands =
        [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    foreach ($allowedCommand in $safePrimitiveCommands) {
        [void]$allowedEagerCommands.Add($allowedCommand)
    }

    $eagerCommands = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.CommandAst] -and
                    $node.Extent.StartOffset -lt $rawOffset
            },
            $true
        ) | Where-Object {
            -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
        } | Sort-Object { $_.Extent.StartOffset }
    )
    foreach ($command in $eagerCommands) {
        $commandName =
            ConvertTo-PrivateMarkerCallableName $command.GetCommandName()
        if ([string]::IsNullOrEmpty($commandName)) {
            if (-not [object]::ReferenceEquals(
                    $command,
                    $preRawDotSources[0]
                )) {
                return $false
            }
            continue
        }
        if ($commandName -ceq $targetCommandName -or
            $riskyFunctions.Contains($commandName)) {
            return $false
        }
        if ($commandName -in @(
                'Set-Alias',
                'New-Alias',
                'Set-Item',
                'Set-Content',
                'Set-Variable',
                'New-Variable',
                'Copy-Item',
                'Move-Item',
                'Rename-Item',
                'Invoke-Command',
                'Invoke-Expression'
            )) {
            return $false
        }
        if (Test-PrivateMarkerCommandCanInvokeIndirectScriptBlock `
            -Command $command) {
            return $false
        }
        $arguments = Get-PrivateMarkerStaticCommandValues -Command $command
        if ($commandName -eq 'New-Item' -and
            $arguments.HasValueParameter) {
            return $false
        }
        if ($commandName -in @('Get-Command', 'Get-Item')) {
            if (-not $arguments.IsStatic -or
                $arguments.Values.Count -eq 0) {
                return $false
            }
            foreach ($value in $arguments.Values) {
                $referenceName =
                    ConvertTo-PrivateMarkerCallableName $value
                if ($referenceName -ceq $targetCommandName -or
                    $riskyFunctions.Contains($referenceName) -or
                    [System.Management.Automation.WildcardPattern]::
                        ContainsWildcardCharacters($value)) {
                    return $false
                }
            }
        }
        if ($commandName -eq 'Get-Variable') {
            # caller scopeのambient値はsource ASTから型も由来も証明できない。
            # pre-rawでは既知の代入集合との照合に降格せず、取得自体を拒否する。
            return $false
        }
        if ($commandName -eq 'New-Object') {
            if (-not $arguments.IsStatic -and $riskyTypes.Count -gt 0) {
                return $false
            }
            foreach ($value in $arguments.Values) {
                if ($riskyTypes.Contains($value)) {
                    return $false
                }
            }
        }
        if ($commandName -in @('ForEach-Object', 'Where-Object')) {
            $literalPipelineBlocks = @(
                $command.CommandElements | Where-Object {
                    $_ -is
                        [System.Management.Automation.Language.ScriptBlockExpressionAst]
                }
            )
            if ($literalPipelineBlocks.Count -eq 0) {
                # MemberName形式やambient/stored blockだけのpipelineは、実行対象を
                # source ASTで証明できない。直接記述されたblockだけを許可する。
                return $false
            }
            $dynamicPipelineVariables = @(
                $command.FindAll(
                    {
                        param($node)
                        return $node -is
                            [System.Management.Automation.Language.VariableExpressionAst]
                    },
                    $true
                ) | Where-Object {
                    $_.VariablePath.UserPath -notin @('_', 'PSItem') -and
                    -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
                }
            )
            if ($dynamicPipelineVariables.Count -gt 0) {
                # literal block内のpipeline item以外は、ambient ScriptBlockを
                # captureして実行できるため、既知の危険変数だけでなく全て拒否する。
                return $false
            }
        }
        $eagerCommandAvailable =
            $allowedEagerCommands.Contains($commandName)
        if (-not $eagerCommandAvailable -and
            $topLevelDefinitionEndOffsets.ContainsKey($commandName) -and
            $topLevelDefinitionEndOffsets[$commandName] -gt 0 -and
            $topLevelDefinitionEndOffsets[$commandName] -le
                $command.Extent.StartOffset) {
            $eagerCommandAvailable = $true
        }
        if (-not $eagerCommandAvailable) {
            # first-call契約より前のbuiltin/external commandをpositive setへ
            # 固定し、未知cmdletのScriptBlock parameterへambient値を渡せない。
            return $false
        }
    }

    $eagerTargetCalls = @(
        $sourceAst.FindAll(
            {
                param($node)
                return $node -is
                        [System.Management.Automation.Language.CommandAst] -and
                    (ConvertTo-PrivateMarkerCallableName `
                        $node.GetCommandName()) -ceq
                        $targetCommandName
            },
            $true
        ) | Where-Object {
            -not (Test-PrivateMarkerAstIsDeferredDefinition -Node $_)
        } | Sort-Object { $_.Extent.StartOffset }
    )
    return $eagerTargetCalls.Count -gt 0 -and
        [object]::ReferenceEquals($eagerTargetCalls[0], $rawOuterCommand)
}

function Test-FirstProcessInvocationIsRawTransport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    return Test-FirstProcessInvocationPolicy -Source $Source
}

function Assert-FirstProcessInvocationValidatorRegressions {
    $cases = @(
        [pscustomobject]@{
            Name = 'direct-before'
            Expected = $false
            Source = @'
Invoke-PrivateMarkerProcess
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'function-before'
            Expected = $true
            Source = @'
function Invoke-Deferred {
    Invoke-PrivateMarkerProcess
}
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'uninvoked-scriptblock'
            Expected = $true
            Source = @'
$unused = { Invoke-PrivateMarkerProcess }
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'nested-inner'
            Expected = $false
            Source = @'
$rawTransportResult = Invoke-PrivateMarkerProcess -Value $(Invoke-PrivateMarkerProcess)
'@
        },
        [pscustomobject]@{
            Name = 'invoked-scriptblock-member'
            Expected = $false
            Source = @'
({ Invoke-PrivateMarkerProcess }).Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'invoked-scriptblock-return-as-is'
            Expected = $false
            Source = @'
({ Invoke-PrivateMarkerProcess }).InvokeReturnAsIs()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'safe-application-get-command'
            Expected = $true
            Source = @'
Get-Command git -CommandType Application
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'scoped-function-wrapper'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
global:Invoke-Early
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'transitive-function-wrapper'
            Expected = $false
            Source = @'
function Invoke-Later {
    Invoke-PrivateMarkerProcess
}
function Invoke-Early {
    Invoke-Later
}
Invoke-Early
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'target-function-shadow'
            Expected = $false
            Source = @'
function Invoke-PrivateMarkerProcess {
    'shadow'
}
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'target-alias-shadow'
            Expected = $false
            Source = @'
function Invoke-Early {
    'shadow'
}
Set-Alias Invoke-PrivateMarkerProcess Invoke-Early
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'risky-alias-wrapper'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
Set-Alias EarlyAlias Invoke-Early
EarlyAlias
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'set-item-alias-wrapper'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
Set-Item Alias:EarlyAlias Invoke-Early
EarlyAlias
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'set-content-alias-wrapper'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
Set-Content Alias:EarlyAlias Invoke-Early
EarlyAlias
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'get-command-scriptblock'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
(Get-Command Invoke-Early).ScriptBlock.Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'builtin-get-command-alias'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
(gcm Invoke-Early).ScriptBlock.Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'module-qualified-get-command'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
(Microsoft.PowerShell.Core\Get-Command Invoke-Early).ScriptBlock.Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'dynamic-get-command'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
$name = 'Invoke-Early'
(Get-Command $name).ScriptBlock.Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'get-item-function-scriptblock'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
(Get-Item Function:Invoke-Early).ScriptBlock.Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'function-provider-invoke'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
${function:Invoke-Early}.Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'invoke-command-function-provider'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
Invoke-Command -ScriptBlock ${function:Invoke-Early}
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'invoke-expression-helper'
            Expected = $false
            Source = @'
Invoke-Expression 'Invoke-PrivateMarkerProcess'
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'pipeline-function-provider'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-PrivateMarkerProcess
}
1 | ForEach-Object ${function:Invoke-Early}
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'stored-scriptblock-foreach'
            Expected = $false
            Source = @'
$stored = { Invoke-PrivateMarkerProcess }
ForEach-Object -InputObject 1 -Process $stored
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'stored-scriptblock-where'
            Expected = $false
            Source = @'
$stored = { Invoke-PrivateMarkerProcess }
1 | Where-Object $stored
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'dynamic-scriptblock-get-variable-foreach'
            Expected = $false
            Source = @'
$stored = [scriptblock]::Create('Invoke-PrivateMarkerProcess')
1 | ForEach-Object (Get-Variable stored -ValueOnly)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-scriptblock-get-variable-foreach'
            Expected = $false
            Source = @'
1 | ForEach-Object (Get-Variable ambientBlock -ValueOnly)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-scriptblock-variable-foreach'
            Expected = $false
            Source = @'
1 | ForEach-Object $ambientBlock
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'dynamic-scriptblock-direct-foreach'
            Expected = $false
            Source = @'
1 | ForEach-Object ([scriptblock]::Create('Invoke-PrivateMarkerProcess'))
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-scriptblock-member-name'
            Expected = $false
            Source = @'
$ambientBlock | ForEach-Object -MemberName Invoke
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-scriptblock-sort-property'
            Expected = $false
            Source = @'
1 | Sort-Object -Property $ambientBlock
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-scriptblock-select-expression'
            Expected = $false
            Source = @'
1 | Select-Object -Property @{ Name = 'x'; Expression = $ambientBlock }
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-scriptblock-wrapper-invoke'
            Expected = $false
            Source = @'
function Invoke-Early {
    (Get-Variable ambientBlock -ValueOnly).Invoke()
}
Invoke-Early
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-scriptblock-wrapper-foreach'
            Expected = $false
            Source = @'
function Invoke-Early {
    1 | ForEach-Object $ambientBlock
}
Invoke-Early
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-scriptblock-member-foreach'
            Expected = $false
            Source = @'
$items = @(1)
$items.ForEach($ambientBlock)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'unknown-scriptblock-consumer'
            Expected = $false
            Source = @'
Invoke-AmbientConsumer $ambientBlock
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'unknown-scriptblock-consumer-wrapper'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-AmbientConsumer $ambientBlock
}
Invoke-Early
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'unknown-scriptblock-member-execute'
            Expected = $false
            Source = @'
$ambient.Execute($ambientBlock)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-allowlisted-member-add'
            Expected = $false
            Source = @'
$ambient.Add($ambientBlock)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-allowlisted-member-find-all'
            Expected = $false
            Source = @'
$ambient.FindAll($ambientBlock, $true)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'assigned-ambient-allowlisted-receiver'
            Expected = $false
            Source = @'
$localReceiver = $ambient
$localReceiver.Add($null)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'ambient-foreach-allowlisted-receiver'
            Expected = $false
            Source = @'
foreach ($item in $ambientItems) {
    $item.Add($null)
}
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'source-bound-foreach-allowlisted-receiver'
            Expected = $true
            Source = @'
$localItems = @(@())
foreach ($item in $localItems) {
    $item.Add($null)
}
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'conditional-assignment-allowlisted-receiver'
            Expected = $false
            Source = @'
if ($false) {
    $ambient = @()
}
$ambient.Add($null)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'conditional-assignment-find-all-receiver'
            Expected = $false
            Source = @'
if ($false) {
    $ambient = @()
}
$ambient.FindAll({ $true }, $true)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'zero-iteration-assignment-allowlisted-receiver'
            Expected = $false
            Source = @'
foreach ($unused in @()) {
    $ambient = @()
}
$ambient.Add($null)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'conditional-reassignment-after-safe-binding'
            Expected = $false
            Source = @'
$localReceiver = @()
if ($true) {
    $localReceiver = $ambient
}
$localReceiver.Add($null)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'compound-assignment-receiver'
            Expected = $false
            Source = @'
$localReceiver += @()
$localReceiver.Add($null)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'untyped-parameter-allowlisted-receiver'
            Expected = $false
            Source = @'
function Invoke-Early($ambient) {
    $ambient.Add($null)
}
Invoke-Early $ambient
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'module-qualified-safe-primitive'
            Expected = $false
            Source = @'
Synthetic.Autoload\Join-Path '.' 'safe'
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'module-qualified-raw-target'
            Expected = $false
            Source = @'
$rawTransportResult = Synthetic.Autoload\Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'global-qualified-safe-primitive'
            Expected = $false
            Source = @'
global:Join-Path '.' 'safe'
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'global-qualified-raw-target'
            Expected = $false
            Source = @'
$rawTransportResult = global:Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'local-function-call-before-definition'
            Expected = $false
            Source = @'
Invoke-Later
function Invoke-Later {
    Join-Path '.' 'safe'
}
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'conditional-local-function-definition'
            Expected = $false
            Source = @'
if ($false) {
    function Invoke-Conditional {
        Join-Path '.' 'safe'
    }
}
Invoke-Conditional
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'wrapper-calls-later-definition'
            Expected = $false
            Source = @'
function Invoke-Early {
    Invoke-Later
}
Invoke-Early
function Invoke-Later {
    Join-Path '.' 'safe'
}
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'literal-scriptblock-invoke-expression'
            Expected = $false
            Source = @'
$stored = { Invoke-Expression 'Invoke-PrivateMarkerProcess' }
1 | ForEach-Object (Get-Variable stored -ValueOnly)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'safe-known-prefix-command'
            Expected = $true
            Source = @'
Join-Path '.' 'safe'
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'safe-defined-before-call'
            Expected = $true
            Source = @'
function Invoke-Safe {
    Join-Path '.' 'safe'
}
Invoke-Safe
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'safe-direct-receiver-binding'
            Expected = $true
            Source = @'
$localReceiver = @()
$localReceiver.Add($null)
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'safe-literal-foreach'
            Expected = $true
            Source = @'
1 | ForEach-Object { $_.ToString() }
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'receiver-partial-safe-variable'
            Expected = $false
            Source = @'
$x = { Invoke-PrivateMarkerProcess }
$safe = $true
(Write-Output (Get-Variable x -ValueOnly) -Verbose:$safe).Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'class-constructor'
            Expected = $false
            Source = @'
class EarlyClass {
    EarlyClass() {
        Invoke-PrivateMarkerProcess
    }
}
[EarlyClass]::new()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'class-method-invoke'
            Expected = $false
            Source = @'
class EarlyClass {
    [scriptblock] Invoke() {
        return { Invoke-PrivateMarkerProcess }
    }
}
[EarlyClass]::new().Invoke()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'class-as-constructor'
            Expected = $false
            Source = @'
class EarlyClass {
    EarlyClass() {
        Invoke-PrivateMarkerProcess
    }
}
$instance = @{} -as [EarlyClass]
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'class-static-instance'
            Expected = $false
            Source = @'
class EarlyClass {
    static [EarlyClass] $Instance = [EarlyClass]::new()
    EarlyClass() {
        Invoke-PrivateMarkerProcess
    }
    [void] Run() {}
}
$instance = [EarlyClass]::Instance
$instance.Run()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'class-inheritance-constructor'
            Expected = $false
            Source = @'
class EarlyBase {
    EarlyBase() {
        Invoke-PrivateMarkerProcess
    }
}
class EarlyDerived : EarlyBase {}
[EarlyDerived]::new()
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'set-item-function-provider'
            Expected = $false
            Source = @'
Set-Item Function:Invoke-PrivateMarkerProcess { 'shadow' }
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'dynamic-new-item-provider'
            Expected = $false
            Source = @'
$providerPath = 'Function:Invoke-PrivateMarkerProcess'
New-Item -Path $providerPath -ItemType Directory -Value { 'shadow' }
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'bootstrap-set-variable'
            Expected = $false
            Source = @'
$root = '.'
$processBoundary = Join-Path $root 'scripts/private-marker-process.ps1'
Set-Variable processBoundary './synthetic.ps1'
. $processBoundary
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        },
        [pscustomobject]@{
            Name = 'bootstrap-scope-wrapper'
            Expected = $false
            Source = @'
$root = '.'
$processBoundary = Join-Path $root 'scripts/private-marker-process.ps1'
function Set-Boundary {
    Set-Variable -Scope 1 -Name processBoundary -Value './synthetic.ps1'
}
Set-Boundary
. $processBoundary
$rawTransportResult = Invoke-PrivateMarkerProcess
'@
        }
    )
    foreach ($case in $cases) {
        $actual = Test-FirstProcessInvocationIsRawTransport `
            -Source $case.Source
        if ($actual -ne $case.Expected) {
            Add-Failure "First-invocation validator regression failed: $($case.Name)."
        }
    }
}

function Assert-FirstProcessInvocationIsRawTransport {
    # 実 self-test も synthetic cases と同じ純粋 validator で、最初の
    # eager bounded call が raw binary fixture であることを実行前に確認する。
    $source = [System.IO.File]::ReadAllText(
        $selfTestScriptPath,
        (New-Object System.Text.UTF8Encoding($false, $true))
    )
    if (-not (Test-FirstProcessInvocationIsRawTransport -Source $source)) {
        Add-Failure 'Expected raw binary transport to be the first executable bounded helper invocation.'
    }
}

function Test-ByteArrayContainsSequence {
    param(
        [byte[]]$Haystack,
        [byte[]]$Needle
    )

    if ($Needle.Length -eq 0) {
        return $true
    }
    if ($Haystack.Length -lt $Needle.Length) {
        return $false
    }
    for ($offset = 0;
        $offset -le ($Haystack.Length - $Needle.Length);
        $offset++) {
        $matched = $true
        for ($needleIndex = 0;
            $needleIndex -lt $Needle.Length;
            $needleIndex++) {
            if ($Haystack[$offset + $needleIndex] -ne $Needle[$needleIndex]) {
                $matched = $false
                break
            }
        }
        if ($matched) {
            return $true
        }
    }
    return $false
}

function Test-ByteArraysEqual {
    param(
        [byte[]]$Expected,
        [byte[]]$Actual
    )

    if ($Expected.Length -ne $Actual.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Expected.Length; $index++) {
        if ($Expected[$index] -ne $Actual[$index]) {
            return $false
        }
    }
    return $true
}

function Get-ProcessEnvironmentSnapshot {
    $snapshot = @{}
    $environment = [Environment]::GetEnvironmentVariables('Process')
    foreach ($name in $environment.Keys) {
        $snapshot["$name"] = [string]$environment[$name]
    }
    return $snapshot
}

function Assert-ProcessEnvironmentUnchanged {
    param(
        [hashtable]$Expected,
        [string]$Context
    )

    $actual = Get-ProcessEnvironmentSnapshot
    $differentNames = New-Object System.Collections.Generic.List[string]
    foreach ($name in @($Expected.Keys + $actual.Keys) | Sort-Object -Unique) {
        if ($Expected.ContainsKey($name) -ne $actual.ContainsKey($name) -or
            ($Expected.ContainsKey($name) -and $Expected[$name] -cne $actual[$name])) {
            # 周辺環境には秘密値があり得るため、差分は変数名だけを報告する。
            $differentNames.Add("$name") | Out-Null
        }
    }
    if ($differentNames.Count -gt 0) {
        Add-Failure "$Context changed parent environment variables: $($differentNames -join ', ')."
    }
}

function Invoke-Scanner {
    param(
        [string]$ScanPath,
        [hashtable]$EnvironmentOverrides = @{},
        [string[]]$AdditionalArguments = @(),
        [string]$ScannerPath = $scanner
    )

    $arguments = @('-NoProfile')
    if ($PSVersionTable.PSVersion.Major -le 5 -and
        (Test-PrivateMarkerWindowsHost)) {
        $arguments += @('-ExecutionPolicy', 'Bypass')
    }
    $arguments += @('-File', $ScannerPath, '-Path', $ScanPath)
    $arguments += $AdditionalArguments
    # scanner childごとにsuite-owned temp namespaceを継承させる。system tempの
    # 共通prefixを監視すると、別の正当な並列runをこのrunのleakと誤認する。
    $scannerEnvironmentOverrides = @{}
    foreach ($name in $EnvironmentOverrides.Keys) {
        $scannerEnvironmentOverrides["$name"] =
            $EnvironmentOverrides[$name]
    }
    foreach ($tempVariable in @('TEMP', 'TMP', 'TMPDIR')) {
        if (-not $scannerEnvironmentOverrides.ContainsKey($tempVariable)) {
            $scannerEnvironmentOverrides[$tempVariable] = $scannerTempRoot
        }
    }
    $result = Invoke-PrivateMarkerProcess `
        -FileName $currentPowerShellExecutable `
        -Arguments $arguments `
        -WorkingDirectory $root `
        -EnvironmentOverrides $scannerEnvironmentOverrides `
        -MaximumStandardOutputBytes 4194304 `
        -TimeoutMilliseconds 30000
    return ConvertTo-TestProcessResult -Result $result
}

function Invoke-HermeticGit {
    param(
        [string]$WorkingDirectory,
        [string[]]$Arguments,
        [string]$IsolationRoot
    )

    $gitCommand = Get-Command git -ErrorAction Stop
    $result = Invoke-PrivateMarkerProcess `
        -FileName $gitCommand.Source `
        -Arguments $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -SanitizeGitEnvironment `
        -IsolationRoot $IsolationRoot `
        -TimeoutMilliseconds 20000
    return ConvertTo-TestProcessResult -Result $result
}

function Set-SyntheticGitConfiguration {
    param(
        [string]$Path,
        [hashtable]$Values
    )

    # scanner の Git 子は unknown environment を全破棄するため、Windows
    # race fixture は executable 隣接の bounded UTF-8 設定だけを読む。
    $lines = @(
        foreach ($name in @($Values.Keys | Sort-Object)) {
            $encodedValue = [Convert]::ToBase64String(
                [System.Text.Encoding]::UTF8.GetBytes(
                    [string]$Values[$name]
                )
            )
            "$name`:$encodedValue"
        }
    )
    [System.IO.File]::WriteAllLines(
        $Path,
        $lines,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function ConvertTo-TestProcessResult {
    param([pscustomobject]$Result)

    $stdout = [System.Text.UTF8Encoding]::new($false).GetString(
        $Result.StandardOutputBytes
    )
    $stderr = [System.Text.UTF8Encoding]::new($false).GetString(
        $Result.StandardErrorBytes
    )
    $healthyBoundary = $Result.StreamsCompleted -and
        $Result.TreeStopped -and
        -not $Result.TimedOut -and
        -not $Result.OutputLimitExceeded -and
        -not $Result.InputWriteFailed -and
        -not $Result.PipeLeakDetected
    $exitCode = if ($healthyBoundary) { $Result.ExitCode } else { -1 }
    $diagnostics = New-Object System.Collections.Generic.List[string]
    if (-not $Result.StreamsCompleted) { $diagnostics.Add('streams-incomplete') }
    if (-not $Result.TreeStopped) { $diagnostics.Add('tree-cleanup-failed') }
    if ($Result.TimedOut) { $diagnostics.Add('timed-out') }
    if ($Result.OutputLimitExceeded) { $diagnostics.Add('output-limit') }
    if ($Result.InputWriteFailed) { $diagnostics.Add('input-write') }
    if ($Result.PipeLeakDetected) { $diagnostics.Add('pipe-leak') }
    $output = (@($stdout, $stderr) -join [Environment]::NewLine).TrimEnd()
    if ($diagnostics.Count -gt 0) {
        $output += [Environment]::NewLine + (
            'bounded-process-failure: ' + ($diagnostics -join ',')
        )
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        RawExitCode = $Result.ExitCode
        Output = $output
        TimedOut = $Result.TimedOut
        OutputLimitExceeded = $Result.OutputLimitExceeded
        InputWriteFailed = $Result.InputWriteFailed
        PipeLeakDetected = $Result.PipeLeakDetected
        StreamsCompleted = $Result.StreamsCompleted
        TreeStopped = $Result.TreeStopped
    }
}

function Test-FixedScannerBoundaryFailure {
    param([pscustomobject]$Result)

    return $Result.ExitCode -eq 2 -and
        $Result.Output.Trim() -ceq
            'Private marker scan failed closed (integrity: scanner-boundary).'
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("codex-windows-sandbox-troubleshooting-scan-test-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$scannerTempRoot = Join-Path $tempRoot 'scanner-temp'
New-Item -ItemType Directory -Path $scannerTempRoot | Out-Null
$emptyCommandPath = Join-Path $tempRoot 'empty-command-path'
New-Item -ItemType Directory -Path $emptyCommandPath | Out-Null
$foreignScannerIsolationRoot = $null
$directoryLinkItemType = if (Test-PrivateMarkerWindowsHost) {
    'Junction'
} else {
    'SymbolicLink'
}

try {
    Assert-FirstProcessInvocationValidatorRegressions
    Assert-FirstProcessInvocationIsRawTransport

    # macOS evidence modeはexternal setsidが無いnative gateを実測する。
    # cold pwsh/Add-Typeだけtest-onlyで30秒まで許容し、他hostの既定値は守る。
    $availableSetSidPath = @('/usr/bin/setsid', '/bin/setsid') |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    $usesNativePosixSessionGate =
        -not (Test-PrivateMarkerWindowsHost) -and
        [string]::IsNullOrWhiteSpace([string]$availableSetSidPath)
    $processTestTimeoutMilliseconds =
        if ($RequireMacOSNativePosixContainment) { 30000 } else { 10000 }
    $rawTransportTestTimeoutMilliseconds =
        if ($RequireMacOSNativePosixContainment) { 30000 } else { 5000 }

    # 最初の eager bounded call で binary stdin、partial stdout/stderr、
    # EOF、非 0 exit code を framing や UTF-8 preamble なしで固定する。
    $rawTransportScript = @'
$stdin = [Console]::OpenStandardInput()
$readBuffer = New-Object byte[] 3
$stdout = [Console]::OpenStandardOutput()
$readCount = $stdin.Read($readBuffer, 0, $readBuffer.Length)
while ($readCount -gt 0) {
    $stdout.Write($readBuffer, 0, $readCount)
    $stdout.Flush()
    $readCount = $stdin.Read($readBuffer, 0, $readBuffer.Length)
}
$stderrBytes = [byte[]]@(255, 254, 128, 127, 13, 10, 1, 0)
$stderr = [Console]::OpenStandardError()
$stderr.Write($stderrBytes, 0, 3)
$stderr.Flush()
$stderr.Write($stderrBytes, 3, $stderrBytes.Length - 3)
$stderr.Flush()
exit 37
'@
    $rawTransportChildPath = Join-Path `
        $tempRoot `
        'raw-transport-child.ps1'
    [System.IO.File]::WriteAllText(
        $rawTransportChildPath,
        $rawTransportScript,
        [System.Text.UTF8Encoding]::new($false)
    )
    $rawTransportArguments = @('-NoProfile')
    if ($PSVersionTable.PSVersion.Major -le 5 -and
        (Test-PrivateMarkerWindowsHost)) {
        $rawTransportArguments += @('-ExecutionPolicy', 'Bypass')
    }
    $rawTransportArguments += @('-File', $rawTransportChildPath)
    [byte[]]$rawTransportInput = @(
        0, 128, 255, 1, 10, 13, 127, 254, 2, 129, 253, 3
    )
    $rawTransportResult = Invoke-PrivateMarkerProcess `
        -FileName $currentPowerShellExecutable `
        -Arguments $rawTransportArguments `
        -WorkingDirectory $tempRoot `
        -StandardInputBytes $rawTransportInput `
        -TimeoutMilliseconds $rawTransportTestTimeoutMilliseconds `
        -MaximumStandardOutputBytes 64 `
        -MaximumStandardErrorBytes 64
    [byte[]]$expectedRawStderr = @(
        255, 254, 128, 127, 13, 10, 1, 0
    )
    if ($rawTransportResult.ExitCode -ne 37 -or
        $rawTransportResult.TimedOut -or
        $rawTransportResult.OutputLimitExceeded -or
        $rawTransportResult.InputWriteFailed -or
        $rawTransportResult.PipeLeakDetected -or
        -not $rawTransportResult.StreamsCompleted -or
        -not $rawTransportResult.TreeStopped -or
        -not (Test-ByteArraysEqual `
            -Expected $rawTransportInput `
            -Actual $rawTransportResult.StandardOutputBytes) -or
        -not (Test-ByteArraysEqual `
            -Expected $expectedRawStderr `
            -Actual $rawTransportResult.StandardErrorBytes)) {
        Add-Failure 'Expected the process boundary to preserve binary stdin/stdout/stderr, EOF, and exit code exactly.'
    }
    if ((Test-PrivateMarkerWindowsHost) -and
        [PrivateMarker.ContainedProcess]::LastDisposedStandardStreamCount -ne
            3) {
        Add-Failure 'Expected the successful Windows process boundary to dispose all three standard FileStreams explicitly.'
    }

    # native gateのcold startupはsub-second deadlineより前に起きるため、
    # post-exit seamはdirect/external gate hostだけで決定的に検証する。
    # native gate自身のdeadline cleanupは後段の専用1ms fixtureが所有する。
    if (-not $usesNativePosixSessionGate) {
        # child 自体は 0 で即時終了させ、終了確認後だけ self-test seam で
        # deadline を消費する。旧「未終了かつ期限超過」条件なら TimedOut=false
        # になり、host負荷に依存せず終了済み成功の誤受理を検出できる。
        $instantExitExecutable = if (Test-PrivateMarkerWindowsHost) {
            [Environment]::GetEnvironmentVariable('ComSpec', 'Process')
        } else {
            '/bin/sh'
        }
        if ([string]::IsNullOrWhiteSpace($instantExitExecutable) -or
            -not (Test-Path -LiteralPath $instantExitExecutable -PathType Leaf)) {
            Add-Failure 'Expected an absolute native shell for the post-exit deadline regression.'
        } else {
            $instantExitArguments = if (Test-PrivateMarkerWindowsHost) {
                @('/d', '/c', 'exit 0')
            } else {
                @('-c', 'exit 0')
            }
            $expiredCompletedProcessResult = Invoke-PrivateMarkerProcess `
                -FileName $instantExitExecutable `
                -Arguments $instantExitArguments `
                -WorkingDirectory $tempRoot `
                -TimeoutMilliseconds 25 `
                -TestOnlyPostExitDelayMilliseconds 100
            if (-not $expiredCompletedProcessResult.TimedOut -or
                $expiredCompletedProcessResult.ExitCode -ne 0 -or
                $expiredCompletedProcessResult.OutputLimitExceeded -or
                $expiredCompletedProcessResult.InputWriteFailed -or
                $expiredCompletedProcessResult.PipeLeakDetected -or
                -not $expiredCompletedProcessResult.StreamsCompleted -or
                -not $expiredCompletedProcessResult.TreeStopped) {
                Add-Failure 'Expected the post-exit delay deadline to reject an already exited zero-code child.'
            }

            # 初回期限検査は5秒以内に通過させ、stream回収後のtest-only seamだけで
            # 残時間を消費する。cleanup後の再検査が無ければ TimedOut=false の
            # ままなので、result受理直前のtotal deadlineを独立に固定する。
            $expiredAfterInitialCheckResult = Invoke-PrivateMarkerProcess `
                -FileName $instantExitExecutable `
                -Arguments $instantExitArguments `
                -WorkingDirectory $tempRoot `
                -TimeoutMilliseconds 5000 `
                -TestOnlyExpireDeadlineAfterInitialCheck
            if (-not $expiredAfterInitialCheckResult.TimedOut -or
                $expiredAfterInitialCheckResult.ExitCode -ne 0 -or
                $expiredAfterInitialCheckResult.OutputLimitExceeded -or
                $expiredAfterInitialCheckResult.InputWriteFailed -or
                $expiredAfterInitialCheckResult.PipeLeakDetected -or
                -not $expiredAfterInitialCheckResult.StreamsCompleted -or
                -not $expiredAfterInitialCheckResult.TreeStopped) {
                Add-Failure 'Expected the post-stream cleanup deadline to reject a zero-code child.'
            }
        }
    }

    # timeout clockはWindows/POSIXいずれのlaunchより前に開始し、native
    # session gateと成功受理も同じdeadlineへ含める。source順序を固定する。
    $processBoundarySource = [System.IO.File]::ReadAllText(
        $processBoundary,
        (New-Object System.Text.UTF8Encoding($false, $true))
    )
    $clockStartOffset = $processBoundarySource.IndexOf(
        '$clock = [System.Diagnostics.Stopwatch]::StartNew()',
        [StringComparison]::Ordinal
    )
    $windowsLaunchOffset = $processBoundarySource.IndexOf(
        '$containedProcess = [PrivateMarker.ContainedProcess]::Start(',
        [StringComparison]::Ordinal
    )
    $posixLaunchOffset = $processBoundarySource.IndexOf(
        '$processStarted = $process.Start()',
        [StringComparison]::Ordinal
    )
    $gateDeadlineOffset = $processBoundarySource.IndexOf(
        '$clock.ElapsedMilliseconds -lt $TimeoutMilliseconds;',
        [StringComparison]::Ordinal
    )
    $successDeadlineOffset = $processBoundarySource.IndexOf(
        'if ($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {',
        [StringComparison]::Ordinal
    )
    $resultDeadlineOffset = $processBoundarySource.LastIndexOf(
        'if ($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {',
        [StringComparison]::Ordinal
    )
    $streamsCompletedOffset = $processBoundarySource.IndexOf(
        '$streamsCompleted = $null -ne $stdoutTask',
        [StringComparison]::Ordinal
    )
    if ($clockStartOffset -lt 0 -or
        $windowsLaunchOffset -lt 0 -or
        $posixLaunchOffset -lt 0 -or
        $gateDeadlineOffset -lt 0 -or
        $successDeadlineOffset -lt 0 -or
        $resultDeadlineOffset -le $successDeadlineOffset -or
        $streamsCompletedOffset -lt 0 -or
        $clockStartOffset -ge $windowsLaunchOffset -or
        $clockStartOffset -ge $posixLaunchOffset -or
        $clockStartOffset -ge $successDeadlineOffset -or
        $resultDeadlineOffset -ge $streamsCompletedOffset) {
        Add-Failure 'Expected the process timeout clock to own launch, POSIX gate setup, stream cleanup, and success acceptance.'
    }

    # PowerShell childは自身のinput boundaryでBOMを許容し得るため、native
    # Git batch protocolでもraw stdinとcomplete binary stdoutを比較する。
    $rawGitCommands = @(
        Get-Command git `
            -CommandType Application `
            -ErrorAction SilentlyContinue
    )
    if ($rawGitCommands.Count -eq 0) {
        Add-Failure 'Expected native Git to be available for the raw process-boundary regression.'
    } else {
        $rawGitPath = $rawGitCommands[0].Source
        $rawGitRoot = Join-Path $tempRoot 'raw-git-transport'
        $rawGitIsolationRoot = Join-Path $tempRoot 'raw-git-isolation'
        New-Item -ItemType Directory -Path $rawGitRoot | Out-Null
        New-Item `
            -ItemType Directory `
            -Path $rawGitIsolationRoot | Out-Null

        $rawGitInitResult = Invoke-PrivateMarkerProcess `
            -FileName $rawGitPath `
            -Arguments @('init', '-q') `
            -WorkingDirectory $rawGitRoot `
            -SanitizeGitEnvironment `
            -IsolationRoot $rawGitIsolationRoot `
            -TimeoutMilliseconds $processTestTimeoutMilliseconds
        if ($rawGitInitResult.ExitCode -ne 0 -or
            $rawGitInitResult.TimedOut -or
            $rawGitInitResult.OutputLimitExceeded -or
            -not $rawGitInitResult.StreamsCompleted -or
            -not $rawGitInitResult.TreeStopped) {
            Add-Failure 'Expected the raw native Git transport fixture to initialize.'
        } else {
            [byte[]]$rawGitBlobBytes = @(0, 128, 255, 10, 13, 1, 2)
            [System.IO.File]::WriteAllBytes(
                (Join-Path $rawGitRoot 'blob.bin'),
                $rawGitBlobBytes
            )
            $rawGitHashResult = Invoke-PrivateMarkerProcess `
                -FileName $rawGitPath `
                -Arguments @('hash-object', '-w', '--', 'blob.bin') `
                -WorkingDirectory $rawGitRoot `
                -SanitizeGitEnvironment `
                -IsolationRoot $rawGitIsolationRoot `
                -TimeoutMilliseconds $processTestTimeoutMilliseconds
            $rawGitObjectId = [System.Text.Encoding]::ASCII.GetString(
                $rawGitHashResult.StandardOutputBytes
            ).Trim()
            if ($rawGitHashResult.ExitCode -ne 0 -or
                $rawGitHashResult.TimedOut -or
                $rawGitHashResult.OutputLimitExceeded -or
                -not $rawGitHashResult.StreamsCompleted -or
                -not $rawGitHashResult.TreeStopped -or
                $rawGitObjectId -notmatch
                    '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
                Add-Failure 'Expected the raw native Git transport fixture to create a blob object.'
            } else {
                # helper は caller の console encoding を変更しない。PS5.1
                # でも呼出し前後のcode page/preambleを完全一致で固定する。
                $inputCodePageBefore = [Console]::InputEncoding.CodePage
                $inputPreambleBefore = [Convert]::ToBase64String(
                    [Console]::InputEncoding.GetPreamble()
                )
                $rawGitBatchInput = [System.Text.Encoding]::ASCII.GetBytes(
                    "$rawGitObjectId`n"
                )
                $rawGitBatchResult = Invoke-PrivateMarkerProcess `
                    -FileName $rawGitPath `
                    -Arguments @('cat-file', '--batch') `
                    -WorkingDirectory $rawGitRoot `
                    -SanitizeGitEnvironment `
                    -IsolationRoot $rawGitIsolationRoot `
                    -StandardInputBytes $rawGitBatchInput `
                    -TimeoutMilliseconds $processTestTimeoutMilliseconds
                $rawGitHeaderBytes =
                    [System.Text.Encoding]::ASCII.GetBytes(
                        "$rawGitObjectId blob $($rawGitBlobBytes.Length)`n"
                    )
                [byte[]]$expectedRawGitOutput = @(
                    @($rawGitHeaderBytes) +
                    @($rawGitBlobBytes) +
                    @(10)
                )
                if ($rawGitBatchResult.ExitCode -ne 0 -or
                    $rawGitBatchResult.TimedOut -or
                    $rawGitBatchResult.OutputLimitExceeded -or
                    $rawGitBatchResult.InputWriteFailed -or
                    $rawGitBatchResult.PipeLeakDetected -or
                    -not $rawGitBatchResult.StreamsCompleted -or
                    -not $rawGitBatchResult.TreeStopped -or
                    $rawGitBatchResult.StandardErrorBytes.Length -ne 0 -or
                    -not (Test-ByteArraysEqual `
                        -Expected $expectedRawGitOutput `
                        -Actual $rawGitBatchResult.StandardOutputBytes)) {
                    Add-Failure 'Expected native git cat-file batch transport to remain byte-exact without a UTF-8 preamble.'
                }
                if ([Console]::InputEncoding.CodePage -ne
                        $inputCodePageBefore -or
                    [Convert]::ToBase64String(
                        [Console]::InputEncoding.GetPreamble()
                    ) -ne $inputPreambleBefore) {
                    Add-Failure 'Expected the raw input transport to restore the caller console input encoding exactly.'
                }
            }
        }
    }

    # caller override を最後に全破棄し、実 executable directory と固定
    # allowlist だけから child 環境を再構築する。未知の secret 風変数も残さない。
    $hermeticEnvironmentScript = @'
param(
    [string]$ExpectedExecutableDirectory,
    [string]$ExpectedIsolationRoot
)
$comparison = if (
    [Environment]::OSVersion.Platform -eq
        [PlatformID]::Win32NT
) {
    [StringComparison]::OrdinalIgnoreCase
} else {
    [StringComparison]::Ordinal
}
$pathEntries = @(
    $env:PATH.Split([IO.Path]::PathSeparator) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)
if ($pathEntries.Count -eq 0 -or
    -not [string]::Equals(
        [IO.Path]::GetFullPath($pathEntries[0]),
        [IO.Path]::GetFullPath($ExpectedExecutableDirectory),
        $comparison
    )) {
    exit 41
}
if (-not [string]::IsNullOrEmpty($env:SYNTHETIC_SECRET) -or
    -not [string]::IsNullOrEmpty($env:GIT_HOSTILE_SENTINEL) -or
    $env:PATH -match 'hostile-path') {
    exit 42
}
if ($env:GIT_CONFIG_NOSYSTEM -cne '1' -or
    $env:GIT_ATTR_NOSYSTEM -cne '1' -or
    $env:GIT_TERMINAL_PROMPT -cne '0' -or
    $env:GIT_NO_LAZY_FETCH -cne '1' -or
    $env:GIT_NO_REPLACE_OBJECTS -cne '1' -or
    $env:GIT_CONFIG_COUNT -cne '5') {
    exit 43
}
if (-not $env:TEMP.StartsWith($ExpectedIsolationRoot, $comparison) -or
    -not $env:HOME.StartsWith($ExpectedIsolationRoot, $comparison) -or
    -not $env:GIT_CONFIG_GLOBAL.StartsWith(
        $ExpectedIsolationRoot,
        $comparison
    )) {
    exit 44
}
exit 0
'@
    $hermeticEnvironmentScriptPath =
        Join-Path $tempRoot 'hermetic-environment-child.ps1'
    [System.IO.File]::WriteAllText(
        $hermeticEnvironmentScriptPath,
        $hermeticEnvironmentScript,
        [System.Text.UTF8Encoding]::new($true)
    )
    $hermeticEnvironmentIsolationRoot =
        Join-Path $tempRoot 'hermetic-environment-isolation'
    New-Item `
        -ItemType Directory `
        -Path $hermeticEnvironmentIsolationRoot | Out-Null
    $hermeticEnvironmentArguments = @('-NoProfile')
    if ($PSVersionTable.PSVersion.Major -le 5 -and
        (Test-PrivateMarkerWindowsHost)) {
        $hermeticEnvironmentArguments += @('-ExecutionPolicy', 'Bypass')
    }
    $hermeticEnvironmentArguments += @(
        '-File',
        $hermeticEnvironmentScriptPath,
        (Split-Path -Parent $currentPowerShellExecutable),
        $hermeticEnvironmentIsolationRoot
    )
    $hermeticEnvironmentResult = Invoke-PrivateMarkerProcess `
        -FileName $currentPowerShellExecutable `
        -Arguments $hermeticEnvironmentArguments `
        -WorkingDirectory $tempRoot `
        -EnvironmentOverrides @{
            SYNTHETIC_SECRET = 'synthetic-private-value'
            GIT_HOSTILE_SENTINEL = 'present'
            PATH = 'hostile-path'
            GIT_CONFIG_NOSYSTEM = '0'
            GIT_CONFIG_COUNT = '99'
        } `
        -SanitizeGitEnvironment `
        -IsolationRoot $hermeticEnvironmentIsolationRoot `
        -TimeoutMilliseconds $processTestTimeoutMilliseconds
    if ($hermeticEnvironmentResult.ExitCode -ne 0 -or
        $hermeticEnvironmentResult.TimedOut -or
        $hermeticEnvironmentResult.OutputLimitExceeded -or
        $hermeticEnvironmentResult.InputWriteFailed -or
        $hermeticEnvironmentResult.PipeLeakDetected -or
        -not $hermeticEnvironmentResult.StreamsCompleted -or
        -not $hermeticEnvironmentResult.TreeStopped) {
        Add-Failure "Expected sanitized children to receive only the fixed hermetic environment allowlist. Exit: $($hermeticEnvironmentResult.ExitCode)"
    }

    # Prefix・UTF-8 multibyte・実platform改行をすべて含めたraw byte数で、
    # exact limitは成功し、1 byte超過だけがbounded failureになることを確認する。
    $boundaryEmitterPath = Join-Path $tempRoot 'RawBoundaryEmitter.ps1'
    $boundaryEmitterSource = @'
param([int]$TotalBytes)
$prefixText = ([char]0x5883).ToString() + [char]0x754C + ':'
$prefixBytes = [System.Text.Encoding]::UTF8.GetBytes($prefixText)
$newlineBytes = [System.Text.Encoding]::UTF8.GetBytes(
    [Environment]::NewLine
)
if ($TotalBytes -lt ($prefixBytes.Length + $newlineBytes.Length)) {
    throw 'Requested payload is too small.'
}
$payload = New-Object byte[] $TotalBytes
[Array]::Copy($prefixBytes, 0, $payload, 0, $prefixBytes.Length)
for ($index = $prefixBytes.Length;
    $index -lt ($payload.Length - $newlineBytes.Length);
    $index++) {
    $payload[$index] = [byte][char]'x'
}
[Array]::Copy(
    $newlineBytes,
    0,
    $payload,
    $payload.Length - $newlineBytes.Length,
    $newlineBytes.Length
)
$stream = [Console]::OpenStandardOutput()
$stream.Write($payload, 0, $payload.Length)
$stream.Flush()
'@
    [System.IO.File]::WriteAllText(
        $boundaryEmitterPath,
        $boundaryEmitterSource,
        [System.Text.UTF8Encoding]::new($true)
    )
    $boundaryHostArguments = @('-NoProfile')
    if ($PSVersionTable.PSVersion.Major -le 5 -and
        (Test-PrivateMarkerWindowsHost)) {
        $boundaryHostArguments += @('-ExecutionPolicy', 'Bypass')
    }
    $boundaryLimit = 65536
    $withinBoundaryResult = Invoke-PrivateMarkerProcess `
        -FileName $currentPowerShellExecutable `
        -Arguments (
            $boundaryHostArguments +
            @('-File', $boundaryEmitterPath, $boundaryLimit)
        ) `
        -WorkingDirectory $tempRoot `
        -MaximumStandardOutputBytes $boundaryLimit `
        -MaximumStandardErrorBytes 8192 `
        -TimeoutMilliseconds $processTestTimeoutMilliseconds
    $expectedBoundaryPrefix = [System.Text.Encoding]::UTF8.GetBytes(
        ([char]0x5883).ToString() + [char]0x754C + ':'
    )
    $expectedBoundaryNewline = [System.Text.Encoding]::UTF8.GetBytes(
        [Environment]::NewLine
    )
    $boundaryPrefixMatches =
        $withinBoundaryResult.StandardOutputBytes.Length -ge
            $expectedBoundaryPrefix.Length
    if ($boundaryPrefixMatches) {
        for ($index = 0;
            $index -lt $expectedBoundaryPrefix.Length;
            $index++) {
            if ($withinBoundaryResult.StandardOutputBytes[$index] -ne
                $expectedBoundaryPrefix[$index]) {
                $boundaryPrefixMatches = $false
                break
            }
        }
    }
    $boundaryNewlineMatches =
        $withinBoundaryResult.StandardOutputBytes.Length -ge
            $expectedBoundaryNewline.Length
    if ($boundaryNewlineMatches) {
        $newlineOffset =
            $withinBoundaryResult.StandardOutputBytes.Length -
            $expectedBoundaryNewline.Length
        for ($index = 0;
            $index -lt $expectedBoundaryNewline.Length;
            $index++) {
            if ($withinBoundaryResult.StandardOutputBytes[
                    $newlineOffset + $index
                ] -ne $expectedBoundaryNewline[$index]) {
                $boundaryNewlineMatches = $false
                break
            }
        }
    }
    if ($withinBoundaryResult.ExitCode -ne 0 -or
        $withinBoundaryResult.OutputLimitExceeded -or
        -not $withinBoundaryResult.StreamsCompleted -or
        -not $withinBoundaryResult.TreeStopped -or
        $withinBoundaryResult.StandardOutputBytes.Length -ne $boundaryLimit -or
        -not $boundaryPrefixMatches -or
        -not $boundaryNewlineMatches) {
        Add-Failure 'Expected the exact raw UTF-8 output boundary, including prefix and platform newline, to pass.'
    }

    $overBoundaryResult = Invoke-PrivateMarkerProcess `
        -FileName $currentPowerShellExecutable `
        -Arguments (
            $boundaryHostArguments +
            @('-File', $boundaryEmitterPath, ($boundaryLimit + 1))
        ) `
        -WorkingDirectory $tempRoot `
        -MaximumStandardOutputBytes $boundaryLimit `
        -MaximumStandardErrorBytes 8192 `
        -TimeoutMilliseconds $processTestTimeoutMilliseconds
    if (-not $overBoundaryResult.OutputLimitExceeded -or
        -not $overBoundaryResult.TreeStopped -or
        $overBoundaryResult.StandardOutputBytes.Length -gt $boundaryLimit) {
        Add-Failure 'Expected one raw UTF-8 byte beyond the output boundary to stop fail-closed.'
    }

    # Hostile user pathはResolve-Path前後のprovider例外からもraw出力しない。
    $hostilePathPrefix =
        'hostile-nonexistent-' + [System.Guid]::NewGuid().ToString('N')
    $hostilePathCharacters = @(
        [char]0x202E,
        [char]0x2028,
        [char]0x2029
    )
    $hostileMissingPath = Join-Path $tempRoot (
        $hostilePathPrefix +
        ($hostilePathCharacters -join '-') +
        '-spoof'
    )
    $hostileArguments = @('-NoProfile')
    if ($PSVersionTable.PSVersion.Major -le 5 -and
        (Test-PrivateMarkerWindowsHost)) {
        $hostileArguments += @('-ExecutionPolicy', 'Bypass')
    }
    $hostileArguments += @(
        '-File',
        $scanner,
        '-Path',
        $hostileMissingPath
    )
    $hostilePathResult = Invoke-PrivateMarkerProcess `
        -FileName $currentPowerShellExecutable `
        -Arguments $hostileArguments `
        -WorkingDirectory $root `
        -MaximumStandardOutputBytes 256 `
        -MaximumStandardErrorBytes 512 `
        -TimeoutMilliseconds $processTestTimeoutMilliseconds
    $hostileCombinedBytes = New-Object byte[] (
        $hostilePathResult.StandardOutputBytes.Length +
        $hostilePathResult.StandardErrorBytes.Length
    )
    [Array]::Copy(
        $hostilePathResult.StandardOutputBytes,
        0,
        $hostileCombinedBytes,
        0,
        $hostilePathResult.StandardOutputBytes.Length
    )
    [Array]::Copy(
        $hostilePathResult.StandardErrorBytes,
        0,
        $hostileCombinedBytes,
        $hostilePathResult.StandardOutputBytes.Length,
        $hostilePathResult.StandardErrorBytes.Length
    )
    $hostileFixedDiagnostic =
        'Private marker scan failed closed (integrity: scan-root-missing).'
    $expectedHostileStdout = New-Object byte[] 0
    $expectedHostileStderr = [System.Text.Encoding]::UTF8.GetBytes(
        $hostileFixedDiagnostic + [Environment]::NewLine
    )
    $hostileLeakDetected = $false
    # exact bytesだけでframing混入は検出できるが、絶対pathとUnicode制御の
    # 非出力契約も個別に残し、regressionの原因を一意にする。
    foreach ($sensitiveText in @(
        $scanner,
        $hostileMissingPath,
        $hostilePathPrefix
    )) {
        foreach ($encoding in @(
            [System.Text.Encoding]::UTF8,
            [System.Text.Encoding]::Unicode,
            [System.Text.Encoding]::BigEndianUnicode
        )) {
            if (Test-ByteArrayContainsSequence `
                    -Haystack $hostileCombinedBytes `
                    -Needle $encoding.GetBytes($sensitiveText)) {
                $hostileLeakDetected = $true
            }
        }
    }
    foreach ($hostileCharacter in $hostilePathCharacters) {
        if (Test-ByteArrayContainsSequence `
                -Haystack $hostileCombinedBytes `
                -Needle (
                    [System.Text.Encoding]::UTF8.GetBytes(
                        [string]$hostileCharacter
                    )
                )) {
            $hostileLeakDetected = $true
        }
    }
    if ($hostilePathResult.ExitCode -ne 2 -or
        $hostilePathResult.OutputLimitExceeded -or
        -not $hostilePathResult.StreamsCompleted -or
        -not $hostilePathResult.TreeStopped -or
        $hostilePathResult.StandardOutputBytes.Length -gt 256 -or
        $hostilePathResult.StandardErrorBytes.Length -gt 512 -or
        -not (Test-ByteArraysEqual `
            -Expected $expectedHostileStdout `
            -Actual $hostilePathResult.StandardOutputBytes) -or
        -not (Test-ByteArraysEqual `
            -Expected $expectedHostileStderr `
            -Actual $hostilePathResult.StandardErrorBytes) -or
        $hostileLeakDetected) {
        Add-Failure 'Expected hostile nonexistent scan paths to emit exactly one fixed stderr code plus the platform newline.'
    }

    # OS非依存の合成resultでも、同じcontainment shapeのexit 23だけを
    # evidence predicateが拒否することをPS7/PS5.1の両方で固定する。
    $syntheticPosixEvidenceResult = [pscustomobject]@{
        PosixSessionGate = 'native-setsid'
        PipeLeakDetected = $true
        StreamsCompleted = $false
        TreeStopped = $true
        TimedOut = $false
        OutputLimitExceeded = $false
        InputWriteFailed = $false
        ExitCode = 0
    }
    $syntheticPosixNonzeroResult = [pscustomobject]@{
        PosixSessionGate = 'native-setsid'
        PipeLeakDetected = $true
        StreamsCompleted = $false
        TreeStopped = $true
        TimedOut = $false
        OutputLimitExceeded = $false
        InputWriteFailed = $false
        ExitCode = 23
    }
    if (-not (Test-PrivateMarkerPosixContainmentEvidence `
            -Result $syntheticPosixEvidenceResult `
            -ExpectedSessionGate 'native-setsid' `
            -DescendantStarted $true) -or
        (Test-PrivateMarkerPosixContainmentEvidence `
            -Result $syntheticPosixNonzeroResult `
            -ExpectedSessionGate 'native-setsid' `
            -DescendantStarted $true)) {
        Add-Failure 'Expected POSIX evidence to require target exit zero.'
    }

    # child statusは固定allowlistだけを親例外へ変換し、任意文字列やpathを
    # CI logへ反射しない。errnoも有限桁のdecimalだけを許可する。
    $posixGateFailureReasonCases = @(
        [pscustomobject]@{
            Status = 'native-library'
            Expected = 'native-library'
        },
        [pscustomobject]@{
            Status = 'native-entrypoint'
            Expected = 'native-entrypoint'
        },
        [pscustomobject]@{
            Status = 'native-type-definition'
            Expected = 'native-type-definition'
        },
        [pscustomobject]@{
            Status = 'native-platform-detection'
            Expected = 'native-platform-detection'
        },
        [pscustomobject]@{
            Status = 'native-invocation'
            Expected = 'native-invocation'
        },
        [pscustomobject]@{
            Status = 'setsid-error-1'
            Expected = 'setsid-error-1'
        },
        [pscustomobject]@{
            Status = 'ready-write'
            Expected = 'ready-write'
        },
        [pscustomobject]@{
            Status = 'setsid-error-123456'
            Expected = 'unknown'
        },
        [pscustomobject]@{
            Status = 'synthetic-sensitive-value'
            Expected = 'unknown'
        }
    )
    foreach ($reasonCase in $posixGateFailureReasonCases) {
        $actualReason = ConvertTo-PrivateMarkerPosixGateFailureReason `
            -Status $reasonCase.Status
        if ($actualReason -cne $reasonCase.Expected) {
            Add-Failure "Expected fixed POSIX gate failure reason '$($reasonCase.Expected)'; observed '$actualReason'."
        }
    }

    # status無しの実timeoutだけをtimeoutにし、早期exitとmalformed statusは
    # unknownへ畳むclosed classificationをtable-drivenで固定する。
    foreach ($resolutionCase in @(
        [pscustomobject]@{
            Label = 'live-child-deadline'
            Status = ''
            DeadlineReached = $true
            ChildHasExited = $false
            Expected = 'timeout'
        },
        [pscustomobject]@{
            Label = 'early-exit-no-status'
            Status = ''
            DeadlineReached = $false
            ChildHasExited = $true
            Expected = 'unknown'
        },
        [pscustomobject]@{
            Label = 'deadline-after-early-exit'
            Status = ''
            DeadlineReached = $true
            ChildHasExited = $true
            Expected = 'unknown'
        },
        [pscustomobject]@{
            Label = 'malformed-status'
            Status = 'synthetic-malformed-status'
            DeadlineReached = $true
            ChildHasExited = $false
            Expected = 'unknown'
        }
    )) {
        $resolvedReason =
            Resolve-PrivateMarkerPosixGateFailureReason `
                -Status $resolutionCase.Status `
                -DeadlineReached $resolutionCase.DeadlineReached `
                -ChildHasExited $resolutionCase.ChildHasExited
        if ($resolvedReason -cne $resolutionCase.Expected) {
            Add-Failure "Expected POSIX gate resolution '$($resolutionCase.Label)' to remain '$($resolutionCase.Expected)'."
        }
    }

    $posixStatusReadFixture =
        Join-Path $tempRoot 'synthetic-posix-gate-status'
    $posixStatusReadCases = @(
        [pscustomobject]@{
            Label = 'known'
            Bytes = [Text.Encoding]::UTF8.GetBytes('native-library')
            ExpectedText = 'native-library'
            ExpectedReason = 'native-library'
        },
        [pscustomobject]@{
            Label = '64-byte-boundary'
            Bytes = [Text.Encoding]::UTF8.GetBytes(('x' * 64))
            ExpectedText = 'x' * 64
            ExpectedReason = 'unknown'
        },
        [pscustomobject]@{
            Label = '65-byte-rejection'
            Bytes = [Text.Encoding]::UTF8.GetBytes(('x' * 65))
            ExpectedText = ''
            ExpectedReason = 'unknown'
        },
        [pscustomobject]@{
            Label = 'invalid-utf8'
            Bytes = [byte[]]@(0xC3, 0x28)
            ExpectedText = ''
            ExpectedReason = 'unknown'
        },
        [pscustomobject]@{
            Label = 'synthetic-sensitive-content'
            Bytes = [Text.Encoding]::UTF8.GetBytes(
                '<local-path>/synthetic-sensitive-value'
            )
            ExpectedText = '<local-path>/synthetic-sensitive-value'
            ExpectedReason = 'unknown'
        }
    )
    foreach ($statusReadCase in $posixStatusReadCases) {
        try {
            [IO.File]::WriteAllBytes(
                $posixStatusReadFixture,
                [byte[]]$statusReadCase.Bytes
            )
            $actualStatusText =
                Read-PrivateMarkerPosixGateStatus `
                    -Path $posixStatusReadFixture
            $actualStatusReason =
                ConvertTo-PrivateMarkerPosixGateFailureReason `
                    -Status $actualStatusText
            if ($actualStatusText -cne $statusReadCase.ExpectedText -or
                $actualStatusReason -cne $statusReadCase.ExpectedReason) {
                Add-Failure "Expected bounded POSIX status case '$($statusReadCase.Label)' to produce only its fixed result."
            }
        }
        finally {
            if ([IO.File]::Exists($posixStatusReadFixture)) {
                [IO.File]::Delete($posixStatusReadFixture)
            }
        }
    }

    if (-not (Test-PrivateMarkerWindowsHost)) {
        # native wrapperはPowerShell 7のread-only `$IsMacOS` と
        # case-insensitiveに衝突する名前へ代入してはならない。
        $nativeWrapperSource = [IO.File]::ReadAllText($processBoundary)
        if ($nativeWrapperSource -cmatch '(?im)^\s*\$isMacOS\s*=') {
            Add-Failure 'Expected the native POSIX wrapper to avoid the read-only IsMacOS automatic variable.'
        }
        if ($nativeWrapperSource -notmatch
            '\[IO\.File\]::Move\(\$statusStagingPath, \$statusPath\)' -or
            $nativeWrapperSource -notmatch
            '\$posixGateStatusStagingPath') {
            Add-Failure 'Expected the native POSIX status channel to publish only a closed staging file.'
        }

        # 各phaseを実childで失敗させ、atomic公開されたfixed statusを親が
        # 読み取れることと、final/stagingをfinallyが残さないことを同時に測る。
        foreach ($nativeGateFailureCase in @(
            [pscustomobject]@{
                Phase = 'type-definition'
                ExpectedReason = 'native-type-definition'
            },
            [pscustomobject]@{
                Phase = 'platform-detection'
                ExpectedReason = 'native-platform-detection'
            },
            [pscustomobject]@{
                Phase = 'native-invocation'
                ExpectedReason = 'native-invocation'
            }
        )) {
            $nativeGateFailurePhase =
                [string]$nativeGateFailureCase.Phase
            $nativeGateFailureIsolation =
                Join-Path $tempRoot "native-gate-$nativeGateFailurePhase"
            $observedNativeGateFailure = ''
            try {
                [void](Invoke-PrivateMarkerProcess `
                        -FileName $currentPowerShellExecutable `
                        -Arguments @('-NoProfile', '-Command', 'exit 0') `
                        -WorkingDirectory $tempRoot `
                        -IsolationRoot $nativeGateFailureIsolation `
                        -TimeoutMilliseconds $processTestTimeoutMilliseconds `
                        -ForceNativePosixSessionGate `
                        -TestOnlyNativePosixGateFailurePhase (
                            $nativeGateFailurePhase
                        ))
                Add-Failure "Expected native POSIX gate phase '$nativeGateFailurePhase' to fail closed."
            }
            catch {
                $observedNativeGateFailure = $_.Exception.Message
            }
            $expectedNativeGateFailure = (
                'Failed to establish the bounded POSIX session gate (' +
                "$($nativeGateFailureCase.ExpectedReason))."
            )
            if ($observedNativeGateFailure -cne
                $expectedNativeGateFailure) {
                Add-Failure "Expected native POSIX gate phase '$nativeGateFailurePhase' to publish only its fixed parent reason."
            }

            $nativeGateFailureResidue = @()
            if (Test-Path -LiteralPath $nativeGateFailureIsolation) {
                $nativeGateFailureResidue = @(
                    Get-ChildItem `
                        -LiteralPath $nativeGateFailureIsolation `
                        -Force |
                        Where-Object {
                            $_.Name -like 'private-marker-posix-*'
                        }
                )
            }
            if ($nativeGateFailureResidue.Count -ne 0) {
                Add-Failure "Expected native POSIX gate phase '$nativeGateFailurePhase' to remove final and staging status files."
            }
        }

        # 1ms total deadlineでchildがreadyを公開する前に必ず停止させ、
        # fixed timeout分類とlate-ready/final/staging cleanupを実processで測る。
        $nativeGateDeadlineIsolation =
            Join-Path $tempRoot 'native-gate-deadline'
        $observedNativeGateDeadlineFailure = ''
        try {
            [void](Invoke-PrivateMarkerProcess `
                    -FileName $currentPowerShellExecutable `
                    -Arguments @('-NoProfile', '-Command', 'exit 0') `
                    -WorkingDirectory $tempRoot `
                    -IsolationRoot $nativeGateDeadlineIsolation `
                    -TimeoutMilliseconds 1 `
                    -ForceNativePosixSessionGate)
            Add-Failure 'Expected native POSIX gate deadline to fail closed.'
        }
        catch {
            $observedNativeGateDeadlineFailure = $_.Exception.Message
        }
        if ($observedNativeGateDeadlineFailure -cne
            'Failed to establish the bounded POSIX session gate (timeout).') {
            Add-Failure 'Expected a live native POSIX gate deadline to report only fixed timeout.'
        }
        $nativeGateDeadlineResidue = @()
        if (Test-Path -LiteralPath $nativeGateDeadlineIsolation) {
            $nativeGateDeadlineResidue = @(
                Get-ChildItem `
                    -LiteralPath $nativeGateDeadlineIsolation `
                    -Force |
                    Where-Object {
                        $_.Name -like 'private-marker-posix-*'
                    }
            )
        }
        if ($nativeGateDeadlineResidue.Count -ne 0) {
            Add-Failure 'Expected native POSIX gate deadline cleanup to remove late-ready/final/staging files.'
        }

        # direct parentが終了済みでも、同じprocess groupの孫をsignalして
        # inherited pipeと遅延sentinelの両方を確実に閉じる。
        if ($RequireMacOSNativePosixContainment) {
            $macOSRuntimeCanaryPassed =
                [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                    [System.Runtime.InteropServices.OSPlatform]::OSX
                )
            if (-not $macOSRuntimeCanaryPassed) {
                Add-Failure 'Expected -RequireMacOSNativePosixContainment to run on Darwin.'
            }
        }
        $posixSurvivedSentinels =
            New-Object System.Collections.Generic.List[string]
        $posixContainmentCases = @(
            [pscustomobject]@{
                Label = 'auto'
                ForceNativeGate = $false
                ExpectedExitCode = 0
                MustProduceEvidence = $true
            },
            [pscustomobject]@{
                Label = 'forced-native'
                ForceNativeGate = $true
                ExpectedExitCode = 0
                MustProduceEvidence = $true
            },
            [pscustomobject]@{
                Label = 'forced-native-nonzero'
                ForceNativeGate = $true
                ExpectedExitCode = 23
                MustProduceEvidence = $false
            }
        )
        foreach ($posixContainmentCase in $posixContainmentCases) {
            $gateLabel = [string]$posixContainmentCase.Label
            $forceNativeGate =
                [bool]$posixContainmentCase.ForceNativeGate
            $expectedSessionGate = if ($forceNativeGate -or
                [string]::IsNullOrWhiteSpace($availableSetSidPath)) {
                'native-setsid'
            } else {
                'external-setsid'
            }
            $startedSentinel =
                Join-Path $tempRoot "posix-$gateLabel-started.txt"
            $survivedSentinel =
                Join-Path $tempRoot "posix-$gateLabel-survived.txt"
            $posixSurvivedSentinels.Add($survivedSentinel) | Out-Null
            $escapedStartedSentinel = $startedSentinel.Replace("'", "''")
            $escapedSurvivedSentinel = $survivedSentinel.Replace("'", "''")
            $posixGrandchildTemplate = @'
[System.IO.File]::WriteAllText(
    '__STARTED__',
    'started',
    [System.Text.UTF8Encoding]::new($false)
)
Start-Sleep -Milliseconds 1500
[System.IO.File]::WriteAllText(
    '__SURVIVED__',
    'survived',
    [System.Text.UTF8Encoding]::new($false)
)
[Console]::Out.Write('late-output')
'@
            $posixGrandchildScript = $posixGrandchildTemplate.Replace(
                '__STARTED__',
                $escapedStartedSentinel
            ).Replace(
                '__SURVIVED__',
                $escapedSurvivedSentinel
            )
            $posixGrandchildEncoded = [Convert]::ToBase64String(
                [System.Text.Encoding]::Unicode.GetBytes(
                    $posixGrandchildScript
                )
            )
            $escapedPowerShellExecutable =
                $currentPowerShellExecutable.Replace("'", "''")
            $posixParentTemplate = @'
$ErrorActionPreference = 'Stop'
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = '__HOST__'
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.ArgumentList.Add('-NoProfile')
$startInfo.ArgumentList.Add('-EncodedCommand')
$startInfo.ArgumentList.Add('__PAYLOAD__')
$child = [System.Diagnostics.Process]::Start($startInfo)
try {
    $started = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ([System.IO.File]::Exists('__STARTED__')) {
            $started = $true
            break
        }
        Start-Sleep -Milliseconds 10
    }
    if (-not $started) {
        exit 125
    }
}
finally {
    $child.Dispose()
}
exit __EXIT_CODE__
'@
            $posixParentScript = $posixParentTemplate.Replace(
                '__HOST__',
                $escapedPowerShellExecutable
            ).Replace(
                '__PAYLOAD__',
                $posixGrandchildEncoded
            ).Replace(
                '__STARTED__',
                $escapedStartedSentinel
            ).Replace(
                '__EXIT_CODE__',
                [string]$posixContainmentCase.ExpectedExitCode
            )
            $posixParentEncoded = [Convert]::ToBase64String(
                [System.Text.Encoding]::Unicode.GetBytes($posixParentScript)
            )
            $posixPipeResult = Invoke-PrivateMarkerProcess `
                -FileName $currentPowerShellExecutable `
                -Arguments @(
                    '-NoProfile',
                    '-EncodedCommand',
                    $posixParentEncoded
                ) `
                -WorkingDirectory $tempRoot `
                -IsolationRoot (
                    Join-Path $tempRoot "posix-$gateLabel-isolation"
                ) `
                -TimeoutMilliseconds $processTestTimeoutMilliseconds `
                -StreamCompletionWaitMilliseconds 250 `
                -StreamCleanupWaitMilliseconds 2000 `
                -ForceNativePosixSessionGate:$forceNativeGate
            $actualSessionGate = [string]$posixPipeResult.PosixSessionGate
            $sessionGateMatches =
                $actualSessionGate -ceq $expectedSessionGate
            if (-not $sessionGateMatches) {
                Add-Failure "Expected POSIX $gateLabel containment gate '$expectedSessionGate'; observed '$actualSessionGate'."
            }
            $containmentShapePassed =
                $posixPipeResult.PipeLeakDetected -and
                -not $posixPipeResult.StreamsCompleted -and
                $posixPipeResult.TreeStopped -and
                -not $posixPipeResult.TimedOut -and
                -not $posixPipeResult.OutputLimitExceeded -and
                -not $posixPipeResult.InputWriteFailed
            if (-not $containmentShapePassed) {
                Add-Failure "Expected POSIX $gateLabel containment to detect the child-held pipe and stop the process group."
            }
            $descendantStarted =
                Test-Path -LiteralPath $startedSentinel -PathType Leaf
            if (-not $descendantStarted) {
                Add-Failure "Expected POSIX $gateLabel containment fixture to prove that its descendant started."
            }
            $exitCodeMatches =
                $posixPipeResult.ExitCode -eq
                [int]$posixContainmentCase.ExpectedExitCode
            if (-not $exitCodeMatches) {
                Add-Failure "Expected POSIX $gateLabel target exit code $($posixContainmentCase.ExpectedExitCode); observed $($posixPipeResult.ExitCode)."
            }
            # macOS evidenceはcontainment shapeだけでなくtarget成功も必須。
            # 同じshapeでexit 23を返すfixtureがfalse-greenを直接拒否する。
            $eligibleForContainmentEvidence =
                Test-PrivateMarkerPosixContainmentEvidence `
                    -Result $posixPipeResult `
                    -ExpectedSessionGate $expectedSessionGate `
                    -DescendantStarted $descendantStarted
            if ($posixContainmentCase.MustProduceEvidence) {
                if ($eligibleForContainmentEvidence) {
                    $posixGateEvidence[$gateLabel] = $actualSessionGate
                } else {
                    Add-Failure "Expected POSIX $gateLabel containment with target exit 0 to produce evidence."
                }
            } elseif ($eligibleForContainmentEvidence) {
                Add-Failure 'Expected the synthetic nonzero POSIX target to be rejected as containment evidence.'
            } elseif ($sessionGateMatches -and
                $containmentShapePassed -and
                $descendantStarted -and
                $exitCodeMatches) {
                # 非ゼロfixture自身の前提も満たした場合だけ、拒否の実測証跡へ昇格する。
                $posixNonzeroEvidenceRejected = $true
            }
        }
        Start-Sleep -Milliseconds 1750
        $posixDescendantsStopped = $true
        foreach ($survivedSentinel in $posixSurvivedSentinels) {
            if (Test-Path -LiteralPath $survivedSentinel) {
                $posixDescendantsStopped = $false
                Add-Failure 'Expected POSIX process-group cleanup to stop every delayed descendant sentinel.'
                break
            }
        }
        if ($RequireMacOSNativePosixContainment -and
            $macOSRuntimeCanaryPassed -and
            $posixDescendantsStopped -and
            $posixNonzeroEvidenceRejected -and
            $posixGateEvidence['forced-native'] -ceq 'native-setsid') {
            $macOSNativeContainmentVerified = $true
        }

        # kill(2)の戻り値-1は同じでも、ESRCHだけを「既に停止済み」と
        # みなし、EPERM/EACCESをTreeStopped成功へ昇格させない。
        if (-not [PrivateMarker.PosixSignal]::IsSuccessfulResult(0, 0) -or
            -not [PrivateMarker.PosixSignal]::IsSuccessfulResult(-1, 3) -or
            [PrivateMarker.PosixSignal]::IsSuccessfulResult(-1, 1) -or
            [PrivateMarker.PosixSignal]::IsSuccessfulResult(-1, 13)) {
            Add-Failure 'Expected POSIX cleanup to accept success/ESRCH and reject EPERM/EACCES.'
        }
    }

    if (Test-PrivateMarkerWindowsHost) {
        # Job 割当前と resume 前の合成失敗は target を一度も実行せず、
        # native cleanup 結果を確認してから PID を有限時間で除去する。
        foreach ($launchFailureMode in @('assign', 'resume', 'close')) {
            $launchFailureSentinel = Join-Path `
                $tempRoot `
                "windows-launch-failure-$launchFailureMode"
            $escapedLaunchFailureSentinel =
                $launchFailureSentinel.Replace("'", "''")
            $launchFailureScript = @"
[System.IO.File]::WriteAllText('$escapedLaunchFailureSentinel', 'ran')
"@
            $launchFailureEncoded = [Convert]::ToBase64String(
                [System.Text.Encoding]::Unicode.GetBytes(
                    $launchFailureScript
                )
            )
            $launchFailureStopwatch =
                [System.Diagnostics.Stopwatch]::StartNew()
            $launchFailureObserved = $false
            try {
                [void](Invoke-PrivateMarkerProcess `
                    -FileName $currentPowerShellExecutable `
                    -Arguments @(
                        '-NoProfile',
                        '-ExecutionPolicy',
                        'Bypass',
                        '-EncodedCommand',
                        $launchFailureEncoded
                    ) `
                    -WorkingDirectory $tempRoot `
                    -TimeoutMilliseconds 10000 `
                    -ForceWindowsLaunchFailure $launchFailureMode)
            }
            catch {
                $launchFailureObserved = $true
            }
            $launchFailureStopwatch.Stop()
            $expectedLaunchFailureStreamDisposals =
                if ($launchFailureMode -eq 'assign') { 0 } else { 3 }
            if ([PrivateMarker.ContainedProcess]::LastDisposedStandardStreamCount -ne
                    $expectedLaunchFailureStreamDisposals) {
                Add-Failure "Expected $launchFailureMode launch cleanup to continue through every created standard FileStream."
            }
            if ($launchFailureMode -eq 'close' -and
                [PrivateMarker.ContainedProcess]::LastLaunchCleanupFailureCount -lt
                    2) {
                Add-Failure 'Expected consecutive Job close failures to be aggregated before the final cleanup retry.'
            }
            $launchFailureProcessId =
                [PrivateMarker.ContainedProcess]::
                    LastSyntheticFailureProcessId
            $launchFailureProcessGone = $false
            if ($launchFailureProcessId -gt 0) {
                # API 戻り値に加え、process table からの消失を最大 1 秒だけ
                # 再確認し、handle だけ閉じた誤実装を検出する。
                for ($pidCheckAttempt = 0;
                    $pidCheckAttempt -lt 20;
                    $pidCheckAttempt++) {
                    if ($null -eq (Get-Process `
                        -Id $launchFailureProcessId `
                        -ErrorAction SilentlyContinue)) {
                        $launchFailureProcessGone = $true
                        break
                    }
                    Start-Sleep -Milliseconds 50
                }
            }
            Start-Sleep -Milliseconds 100
            if (-not $launchFailureObserved -or
                $launchFailureProcessId -le 0 -or
                -not $launchFailureProcessGone -or
                $launchFailureStopwatch.ElapsedMilliseconds -ge 6000 -or
                (Test-Path -LiteralPath $launchFailureSentinel)) {
                Add-Failure "Expected $launchFailureMode launch failure to remove its PID without resuming the suspended target."
            }
        }

        # Git が存在して timeout した場合は working-tree fallback へ降格しない。
        $syntheticGitDirectory = Join-Path $tempRoot 'synthetic-git'
        $syntheticGitPath = Join-Path $syntheticGitDirectory 'git.exe'
        $syntheticGitConfigurationPath =
            Join-Path $syntheticGitDirectory 'synthetic-git-config.txt'
        $slowGitSentinel = Join-Path $tempRoot 'slow-git-survived.txt'
        New-Item -ItemType Directory -Path $syntheticGitDirectory | Out-Null
        $syntheticGitSourcePath = Join-Path $syntheticGitDirectory 'SyntheticGit.cs'
        $syntheticGitCompilerPath = Join-Path $syntheticGitDirectory 'compile-synthetic-git.ps1'
        $syntheticGitSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class SyntheticGitProgram
{
    private static Dictionary<string, string> ReadConfiguration()
    {
        var values = new Dictionary<string, string>(
            StringComparer.Ordinal);
        var executableDirectory = Path.GetDirectoryName(
            Assembly.GetExecutingAssembly().Location);
        var configurationPath = Path.Combine(
            executableDirectory,
            "synthetic-git-config.txt");
        if (!File.Exists(configurationPath))
        {
            return values;
        }
        var configurationInfo = new FileInfo(configurationPath);
        if (configurationInfo.Length > 16384)
        {
            throw new InvalidDataException(
                "Synthetic Git configuration is too large.");
        }
        foreach (var line in File.ReadAllLines(
            configurationPath,
            new UTF8Encoding(false, true)))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                throw new InvalidDataException(
                    "Synthetic Git configuration is invalid.");
            }
            var name = line.Substring(0, separator);
            var encodedValue = line.Substring(separator + 1);
            values[name] = Encoding.UTF8.GetString(
                Convert.FromBase64String(encodedValue));
        }
        return values;
    }

    private static string GetConfiguration(
        Dictionary<string, string> values,
        string name)
    {
        string value;
        return values.TryGetValue(name, out value) ? value : null;
    }

    private static string QuoteArgument(string argument)
    {
        if (String.IsNullOrEmpty(argument))
        {
            return "\"\"";
        }
        if (argument.IndexOfAny(new[] { ' ', '\t', '"' }) < 0)
        {
            return argument;
        }

        var output = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                output.Append('\\', (backslashes * 2) + 1);
                output.Append('"');
                backslashes = 0;
                continue;
            }
            output.Append('\\', backslashes);
            backslashes = 0;
            output.Append(character);
        }
        output.Append('\\', backslashes * 2);
        output.Append('"');
        return output.ToString();
    }

    private static int Run(string fileName, string[] arguments, int timeoutMilliseconds)
    {
        var forwardsInput = Array.IndexOf(arguments, "cat-file") >= 0 &&
            Array.IndexOf(arguments, "--batch") >= 0;
        var startInfo = new ProcessStartInfo {
            FileName = fileName,
            Arguments = String.Join(" ", Array.ConvertAll(arguments, QuoteArgument)),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = forwardsInput,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using (var process = Process.Start(startInfo))
        {
            var stdoutTask = process.StandardOutput.BaseStream.CopyToAsync(
                Console.OpenStandardOutput());
            var stderrTask = process.StandardError.BaseStream.CopyToAsync(
                Console.OpenStandardError());
            if (forwardsInput)
            {
                var inputTask = Console.OpenStandardInput().CopyToAsync(
                    process.StandardInput.BaseStream);
                if (!inputTask.Wait(5000))
                {
                    process.Kill();
                    process.WaitForExit(5000);
                    return 123;
                }
                process.StandardInput.Close();
            }
            if (!process.WaitForExit(timeoutMilliseconds))
            {
                process.Kill();
                process.WaitForExit(5000);
                return 124;
            }
            if (!Task.WaitAll(new[] { stdoutTask, stderrTask }, 5000))
            {
                return 125;
            }
            Console.Out.Flush();
            Console.Error.Flush();
            return process.ExitCode;
        }
    }

    private static bool IsStageListing(string[] arguments)
    {
        return Array.IndexOf(arguments, "ls-files") >= 0 &&
            Array.IndexOf(arguments, "--stage") >= 0 &&
            Array.IndexOf(arguments, "-z") >= 0 &&
            Array.IndexOf(arguments, "--debug") < 0;
    }

    private static bool IsDebugStageListing(string[] arguments)
    {
        return Array.IndexOf(arguments, "ls-files") >= 0 &&
            Array.IndexOf(arguments, "--stage") >= 0 &&
            Array.IndexOf(arguments, "-z") >= 0 &&
            Array.IndexOf(arguments, "--debug") >= 0;
    }

    private static int NextStageListingCount(string counterPath)
    {
        using (var stream = new FileStream(
            counterPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None))
        {
            if (stream.Length > 32)
            {
                throw new InvalidDataException("Synthetic Git counter is invalid.");
            }
            var bytes = new byte[(int)stream.Length];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = stream.Read(bytes, offset, bytes.Length - offset);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }
                offset += read;
            }

            var count = 0;
            if (bytes.Length > 0 &&
                !Int32.TryParse(Encoding.ASCII.GetString(bytes), out count))
            {
                throw new InvalidDataException("Synthetic Git counter is invalid.");
            }
            count++;
            var nextBytes = Encoding.ASCII.GetBytes(count.ToString());
            stream.Position = 0;
            stream.SetLength(0);
            stream.Write(nextBytes, 0, nextBytes.Length);
            stream.Flush(true);
            return count;
        }
    }

    public static int Main(string[] args)
    {
        var configuration = ReadConfiguration();
        if (String.Equals(
            GetConfiguration(configuration, "mode"),
            "worktree-mutation",
            StringComparison.Ordinal))
        {
            var realGit = GetConfiguration(configuration, "real-git");
            var counterPath = GetConfiguration(configuration, "counter");
            if (IsStageListing(args) && NextStageListingCount(counterPath) == 2)
            {
                File.WriteAllText(
                    Path.Combine(
                        GetConfiguration(configuration, "repository"),
                        GetConfiguration(configuration, "replacement")),
                    "synthetic worktree mutation after scan",
                    new UTF8Encoding(false));
                File.WriteAllText(
                    GetConfiguration(configuration, "sentinel"),
                    "worktree-mutated",
                    new UTF8Encoding(false));
            }
            return Run(realGit, args, 20000);
        }

        if (String.Equals(
            GetConfiguration(configuration, "mode"),
            "local-marker-mutation",
            StringComparison.Ordinal))
        {
            var realGit = GetConfiguration(configuration, "real-git");
            var counterPath = GetConfiguration(configuration, "counter");
            if (IsStageListing(args) && NextStageListingCount(counterPath) == 2)
            {
                var markerPath = Path.Combine(
                    GetConfiguration(configuration, "repository"),
                    ".private-markers.local");
                var action = GetConfiguration(configuration, "action");
                if (String.Equals(action, "delete", StringComparison.Ordinal))
                {
                    File.Delete(markerPath);
                }
                else if (String.Equals(
                    action,
                    "dangling",
                    StringComparison.Ordinal))
                {
                    Directory.Move(
                        GetConfiguration(configuration, "prepared-link"),
                        markerPath);
                }
                else
                {
                    File.WriteAllText(
                        markerPath,
                        GetConfiguration(configuration, "content"),
                        new UTF8Encoding(false));
                }
                File.WriteAllText(
                    GetConfiguration(configuration, "sentinel"),
                    action,
                    new UTF8Encoding(false));
            }
            return Run(realGit, args, 20000);
        }

        if (String.Equals(
            GetConfiguration(configuration, "mode"),
            "index-mutation",
            StringComparison.Ordinal))
        {
            var realGit = GetConfiguration(configuration, "real-git");
            var counterPath = GetConfiguration(configuration, "counter");
            if (IsStageListing(args) && NextStageListingCount(counterPath) == 3)
            {
                var mutationExit = Run(
                    realGit,
                    new[] {
                        "-C",
                        GetConfiguration(configuration, "repository"),
                        "add",
                        "--",
                        GetConfiguration(configuration, "replacement"),
                        GetConfiguration(configuration, "addition")
                    },
                    5000);
                if (mutationExit != 0)
                {
                    return 90;
                }
                File.WriteAllText(
                    GetConfiguration(configuration, "sentinel"),
                    "mutated",
                    new UTF8Encoding(false));
            }
            return Run(realGit, args, 20000);
        }

        if (String.Equals(
            GetConfiguration(configuration, "mode"),
            "flags-mutation",
            StringComparison.Ordinal))
        {
            var realGit = GetConfiguration(configuration, "real-git");
            var counterPath = GetConfiguration(configuration, "counter");
            if (IsDebugStageListing(args) && NextStageListingCount(counterPath) == 3)
            {
                var repository =
                    GetConfiguration(configuration, "repository");
                var relativePath =
                    GetConfiguration(configuration, "replacement");
                var removeExit = Run(
                    realGit,
                    new[] {
                        "-C",
                        repository,
                        "update-index",
                        "--force-remove",
                        "--",
                        relativePath
                    },
                    5000);
                var intentExit = removeExit == 0
                    ? Run(
                        realGit,
                        new[] {
                            "-C",
                            repository,
                            "add",
                            "-N",
                            "--",
                            relativePath
                        },
                        5000)
                    : removeExit;
                if (removeExit != 0 || intentExit != 0)
                {
                    return 91;
                }
                File.WriteAllText(
                    GetConfiguration(configuration, "sentinel"),
                    "flags-mutated",
                    new UTF8Encoding(false));
            }
            return Run(realGit, args, 20000);
        }

        Thread.Sleep(5000);
        File.WriteAllText(
            GetConfiguration(configuration, "sentinel"),
            "survived");
        return 0;
    }
}
'@
        $immediateSpawnerPath = Join-Path $syntheticGitDirectory 'ImmediateSpawner.exe'
        $immediateSpawnerSourcePath = Join-Path $syntheticGitDirectory 'ImmediateSpawner.cs'
        $immediateSpawnerSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

public static class ImmediateSpawnerProgram
{
    public static int Main(string[] args)
    {
        if (args.Length == 1 &&
            String.Equals(args[0], "--child", StringComparison.Ordinal))
        {
            File.WriteAllText(
                Environment.GetEnvironmentVariable("PRIVATE_MARKER_PIPE_STARTED_SENTINEL"),
                "started",
                new UTF8Encoding(false));
            Thread.Sleep(1000);
            File.WriteAllText(
                Environment.GetEnvironmentVariable("PRIVATE_MARKER_PIPE_SURVIVED_SENTINEL"),
                "survived",
                new UTF8Encoding(false));
            return 0;
        }

        // root process は意図的な猶予を置かず、最初の処理で pipe 継承 child を起動する。
        var startInfo = new ProcessStartInfo {
            FileName = Assembly.GetExecutingAssembly().Location,
            Arguments = "--child",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using (var child = Process.Start(startInfo))
        {
            if (child == null)
            {
                return 20;
            }
        }
        Console.Out.WriteLine("parent-exit");
        return 0;
    }
}
'@
        $syntheticGitCompiler = @'
param(
    [string]$SourcePath,
    [string]$OutputPath
)
Add-Type `
    -Path $SourcePath `
    -OutputAssembly $OutputPath `
    -OutputType ConsoleApplication
'@
        [System.IO.File]::WriteAllText(
            $syntheticGitSourcePath,
            $syntheticGitSource,
            [System.Text.UTF8Encoding]::new($false)
        )
        [System.IO.File]::WriteAllText(
            $immediateSpawnerSourcePath,
            $immediateSpawnerSource,
            [System.Text.UTF8Encoding]::new($false)
        )
        [System.IO.File]::WriteAllText(
            $syntheticGitCompilerPath,
            $syntheticGitCompiler,
            [System.Text.UTF8Encoding]::new($true)
        )
        $windowsPowerShell = Get-Command powershell -ErrorAction Stop
        $compileResult = Invoke-PrivateMarkerProcess `
            -FileName $windowsPowerShell.Source `
            -Arguments @(
                '-NoProfile',
                '-ExecutionPolicy',
                'Bypass',
                '-File',
                $syntheticGitCompilerPath,
                '-SourcePath',
                $syntheticGitSourcePath,
                '-OutputPath',
                $syntheticGitPath
            ) `
            -WorkingDirectory $syntheticGitDirectory `
            -TimeoutMilliseconds 30000
        if ($compileResult.ExitCode -ne 0 -or
            -not $compileResult.StreamsCompleted -or
            -not $compileResult.TreeStopped -or
            -not (Test-Path -LiteralPath $syntheticGitPath -PathType Leaf)) {
            Add-Failure 'Expected bounded synthetic Git compilation to succeed.'
        }
        $spawnerCompileResult = Invoke-PrivateMarkerProcess `
            -FileName $windowsPowerShell.Source `
            -Arguments @(
                '-NoProfile',
                '-ExecutionPolicy',
                'Bypass',
                '-File',
                $syntheticGitCompilerPath,
                '-SourcePath',
                $immediateSpawnerSourcePath,
                '-OutputPath',
                $immediateSpawnerPath
            ) `
            -WorkingDirectory $syntheticGitDirectory `
            -TimeoutMilliseconds 30000
        if ($spawnerCompileResult.ExitCode -ne 0 -or
            -not $spawnerCompileResult.StreamsCompleted -or
            -not $spawnerCompileResult.TreeStopped -or
            -not (Test-Path -LiteralPath $immediateSpawnerPath -PathType Leaf)) {
            Add-Failure 'Expected bounded immediate-spawner compilation to succeed.'
        } else {
            # 目的 process が最初の処理で child を起動しても、direct target は
            # suspended 中にJob所属済みなのでkill-on-close境界から逃げられない。
            $pipeSurvivedSentinels = New-Object System.Collections.Generic.List[string]
            for ($attempt = 1; $attempt -le 10; $attempt++) {
                $pipeStartedSentinel = Join-Path `
                    $tempRoot `
                    "pipe-grandchild-started-$attempt.txt"
                $pipeSurvivedSentinel = Join-Path `
                    $tempRoot `
                    "pipe-grandchild-survived-$attempt.txt"
                $pipeSurvivedSentinels.Add($pipeSurvivedSentinel) | Out-Null
                $pipeResult = Invoke-PrivateMarkerProcess `
                    -FileName $immediateSpawnerPath `
                    -WorkingDirectory $tempRoot `
                    -EnvironmentOverrides @{
                        PRIVATE_MARKER_PIPE_STARTED_SENTINEL = $pipeStartedSentinel
                        PRIVATE_MARKER_PIPE_SURVIVED_SENTINEL = $pipeSurvivedSentinel
                    } `
                    -TimeoutMilliseconds 10000 `
                    -StreamCompletionWaitMilliseconds 500 `
                    -StreamCleanupWaitMilliseconds 1000
                if (-not $pipeResult.PipeLeakDetected -or
                    $pipeResult.StreamsCompleted -or
                    -not $pipeResult.TreeStopped) {
                    Add-Failure "Expected immediate-spawner attempt $attempt to detect and stop a child-held pipe."
                }
                if (-not (Test-Path -LiteralPath $pipeStartedSentinel)) {
                    Add-Failure "Expected immediate-spawner attempt $attempt to prove that its child started."
                }
            }

            # 全 attempt の child が artifact を書く期限を一度だけ bounded に待つ。
            Start-Sleep -Milliseconds 1250
            foreach ($pipeSurvivedSentinel in $pipeSurvivedSentinels) {
                if (Test-Path -LiteralPath $pipeSurvivedSentinel) {
                    Add-Failure 'Expected atomic Job assignment to stop every immediate child before artifact creation.'
                    break
                }
            }
        }

        $timeoutRoot = Join-Path $tempRoot 'timeout-root'
        New-Item -ItemType Directory -Path $timeoutRoot | Out-Null
        Set-Content -LiteralPath (Join-Path $timeoutRoot 'README.md') -Value 'synthetic clean timeout fixture' -Encoding UTF8
        Set-SyntheticGitConfiguration `
            -Path $syntheticGitConfigurationPath `
            -Values @{
                mode = 'slow'
                sentinel = $slowGitSentinel
            }
        $timeoutResult = Invoke-Scanner `
            -ScanPath $timeoutRoot `
            -EnvironmentOverrides @{
                PATH = $syntheticGitDirectory
            } `
            -AdditionalArguments @('-GitCommandTimeoutMilliseconds', '750')
        if ($timeoutResult.ExitCode -ne 2 -or
            $timeoutResult.Output.Trim() -cne
                'Private marker scan failed closed (integrity: scanner-boundary).') {
            Add-Failure "Expected a timed-out Git probe to fail closed. Output: $($timeoutResult.Output.Trim())"
        }
        if (Test-Path -LiteralPath $slowGitSentinel) {
            Add-Failure 'Expected the timed-out synthetic Git process tree to be stopped before artifact creation.'
        }
    }

    # success 側の規約例を 1 fixture へ集約し、各例を個別 process で再走査しない。
    $cleanRoot = Join-Path $tempRoot 'clean accepted examples'
    New-Item -ItemType Directory -Path $cleanRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $cleanRoot 'README.md') -Value @(
        '# Clean synthetic fixture'
        'A completion notice is a claim, not evidence. Verify artifacts first.'
        'Use a placeholder path such as C:\path\to\repo in examples.'
        'You can also write C:\Users\<name>\project to describe a user directory.'
        'Running C:\Program Files\Git\bin\bash.exe is a documented system example.'
        'Running C:\Program Files\Git\usr\bin\bash.exe is also documented.'
        'Plain bash may resolve to C:\Windows\System32\bash.exe.'
        ('Own repo: ' + (('https://github' + '.com/') + 'h8nc4y/codex-windows-sandbox-troubleshooting'))
        ('Upstream: ' + (('https://github' + '.com/') + 'openai/codex/issues/7031'))
    ) -Encoding UTF8

    $cleanResult = Invoke-Scanner -ScanPath $cleanRoot
    if ($cleanResult.ExitCode -ne 0) {
        Add-Failure "Expected clean fixture to pass, but scanner exited $($cleanResult.ExitCode): $($cleanResult.Output.Trim())"
    }
    $noGitFallbackResult = Invoke-Scanner `
        -ScanPath $cleanRoot `
        -EnvironmentOverrides @{ PATH = $emptyCommandPath }
    if ($noGitFallbackResult.ExitCode -ne 0 -or
        $noGitFallbackResult.Output -notmatch 'working-tree') {
        Add-Failure "Expected a true non-Git directory to retain fallback when Git is unavailable. Output: $($noGitFallbackResult.Output.Trim())"
    }

    # scan-wide 期限は実運用の 120 秒を延長できず、self-test だけが
    # lower-only 値で最終 success write 前の固定 fail-closed を再現する。
    $expectedScannerBoundaryDiagnostic =
        'Private marker scan failed closed (integrity: scanner-boundary).'
    $scanDeadlineResult = Invoke-Scanner `
        -ScanPath $cleanRoot `
        -EnvironmentOverrides @{ PATH = $emptyCommandPath } `
        -AdditionalArguments @('-ScanDeadlineMilliseconds', '1')
    if ($scanDeadlineResult.ExitCode -ne 2 -or
        $scanDeadlineResult.TimedOut -or
        $scanDeadlineResult.Output.Trim() -cne
            $expectedScannerBoundaryDiagnostic -or
        $scanDeadlineResult.Output -match 'Private marker scan passed') {
        Add-Failure "Expected the lower-only scan-wide deadline to fail before final success output. Output: $($scanDeadlineResult.Output.Trim())"
    }

    # PowerShell binder の型/範囲 error は absolute script path を出すため、
    # 全公開引数を raw token として検証し、どの invalid 形も同じ固定診断へ畳む。
    $expectedInvocationContractDiagnostic =
        'Private marker scan failed closed (integrity: invocation-contract).'
    $invalidInvocationCases = @(
        @{
            Label = 'invalid-type'
            Arguments = @('-ScanDeadlineMilliseconds', 'not-an-int')
        },
        @{
            Label = 'out-of-range'
            Arguments = @('-ScanDeadlineMilliseconds', '120001')
        },
        @{
            Label = 'unknown-argument'
            Arguments = @('-UnknownArgument', 'synthetic')
        },
        @{
            Label = 'invalid-common-parameter'
            Arguments = @('-ErrorAction', 'definitely-invalid')
        },
        @{
            Label = 'missing-value'
            Arguments = @('-ScanDeadlineMilliseconds')
        },
        @{
            Label = 'duplicate-path'
            Arguments = @('-Path', $cleanRoot)
        }
    )
    foreach ($invalidInvocationCase in $invalidInvocationCases) {
        $invalidInvocationResult = Invoke-Scanner `
            -ScanPath $cleanRoot `
            -AdditionalArguments $invalidInvocationCase.Arguments
        if ($invalidInvocationResult.ExitCode -ne 2 -or
            $invalidInvocationResult.Output.Trim() -cne
                $expectedInvocationContractDiagnostic -or
            $invalidInvocationResult.Output.Contains($scanner) -or
            $invalidInvocationResult.Output.Contains($cleanRoot) -or
            $invalidInvocationResult.Output.Contains($tempRoot)) {
            Add-Failure "Expected $($invalidInvocationCase.Label) public invocation to fail with one fixed redacted diagnostic. Output: $($invalidInvocationResult.Output.Trim())"
        }
    }

    # helper load と temp isolation 作成も最外 scanner boundary の内側に置き、
    # provider/exception 本文や absolute path を stderr へ通さない。
    $isolatedScannerDirectory = Join-Path $tempRoot 'isolated-scanner'
    New-Item -ItemType Directory -Path $isolatedScannerDirectory | Out-Null
    $isolatedScannerPath =
        Join-Path $isolatedScannerDirectory 'scan-private-markers.ps1'
    [System.IO.File]::WriteAllBytes(
        $isolatedScannerPath,
        [System.IO.File]::ReadAllBytes($scanner)
    )
    $missingHelperResult = Invoke-Scanner `
        -ScanPath $cleanRoot `
        -ScannerPath $isolatedScannerPath
    if ($missingHelperResult.ExitCode -ne 2 -or
        $missingHelperResult.Output.Trim() -cne
            $expectedScannerBoundaryDiagnostic -or
        $missingHelperResult.Output.Contains($isolatedScannerDirectory) -or
        $missingHelperResult.Output.Contains($tempRoot)) {
        Add-Failure "Expected a missing process helper to fail with one fixed redacted scanner-boundary diagnostic. Output: $($missingHelperResult.Output.Trim())"
    }

    $isolatedHelperPath =
        Join-Path $isolatedScannerDirectory 'private-marker-process.ps1'
    $helperFailureSentinel = Join-Path $tempRoot 'helper-failure-sentinel'
    $escapedHelperFailureSentinel =
        $helperFailureSentinel.Replace("'", "''")
    [System.IO.File]::WriteAllText(
        $isolatedHelperPath,
        "throw '$escapedHelperFailureSentinel'",
        [System.Text.UTF8Encoding]::new($true)
    )
    $throwingHelperResult = Invoke-Scanner `
        -ScanPath $cleanRoot `
        -ScannerPath $isolatedScannerPath
    if ($throwingHelperResult.ExitCode -ne 2 -or
        $throwingHelperResult.Output.Trim() -cne
            $expectedScannerBoundaryDiagnostic -or
        $throwingHelperResult.Output.Contains($helperFailureSentinel) -or
        $throwingHelperResult.Output.Contains($tempRoot)) {
        Add-Failure "Expected a throwing process helper to fail with one fixed redacted scanner-boundary diagnostic. Output: $($throwingHelperResult.Output.Trim())"
    }

    $tempProviderBlocker = Join-Path $tempRoot 'temp-provider-blocker'
    [System.IO.File]::WriteAllText(
        $tempProviderBlocker,
        'synthetic blocker',
        [System.Text.UTF8Encoding]::new($false)
    )
    $invalidTempRoot = Join-Path $tempProviderBlocker 'nested'
    $isolationWrapperPath =
        Join-Path $tempRoot 'invoke-scanner-with-invalid-temp.ps1'
    $isolationWrapperSource = @'
param(
    [string]$ScannerPath,
    [string]$ScanPath,
    [string]$InvalidTempRoot
)
$env:TEMP = $InvalidTempRoot
$env:TMP = $InvalidTempRoot
$env:TMPDIR = $InvalidTempRoot
& $ScannerPath -Path $ScanPath
exit $LASTEXITCODE
'@
    [System.IO.File]::WriteAllText(
        $isolationWrapperPath,
        $isolationWrapperSource,
        [System.Text.UTF8Encoding]::new($true)
    )
    $isolationWrapperArguments = @('-NoProfile')
    if ($PSVersionTable.PSVersion.Major -le 5 -and
        (Test-PrivateMarkerWindowsHost)) {
        $isolationWrapperArguments += @('-ExecutionPolicy', 'Bypass')
    }
    $isolationWrapperArguments += @(
        '-File',
        $isolationWrapperPath,
        $scanner,
        $cleanRoot,
        $invalidTempRoot
    )
    $isolationCreateRawResult = Invoke-PrivateMarkerProcess `
        -FileName $currentPowerShellExecutable `
        -Arguments $isolationWrapperArguments `
        -WorkingDirectory $root `
        -TimeoutMilliseconds 30000
    $isolationCreateResult =
        ConvertTo-TestProcessResult -Result $isolationCreateRawResult
    # exact fixed equality は absolute fixture path の混入も同時に拒否する。
    if (-not (Test-FixedScannerBoundaryFailure `
        $isolationCreateResult)) {
        Add-Failure "Expected isolation-root creation failure to use one fixed redacted scanner-boundary diagnostic. Output: $($isolationCreateResult.Output.Trim())"
    }

    # non-Git fallback は nested `.git` directory だけでなく leaf gitfile も読まない。
    $nestedGitLeafRoot = Join-Path $cleanRoot 'nested-git-leaf'
    New-Item -ItemType Directory -Path $nestedGitLeafRoot | Out-Null
    $nestedGitLeafPath = Join-Path $nestedGitLeafRoot '.git'
    $nestedGitLeafMarker = ('g' + 'hp_') + 'synthetic_gitfile_marker'
    Set-Content `
        -LiteralPath $nestedGitLeafPath `
        -Value $nestedGitLeafMarker `
        -Encoding UTF8
    $nestedGitLeafResult = Invoke-Scanner `
        -ScanPath $cleanRoot `
        -EnvironmentOverrides @{ PATH = $emptyCommandPath }
    if ($nestedGitLeafResult.ExitCode -ne 0 -or
        $nestedGitLeafResult.Output -notmatch 'working-tree' -or
        $nestedGitLeafResult.Output.Contains($nestedGitLeafMarker)) {
        Add-Failure "Expected a nested .git leaf to remain excluded from fallback scanning. Output: $($nestedGitLeafResult.Output.Trim())"
    }
    [System.IO.File]::Delete($nestedGitLeafPath)
    [System.IO.Directory]::Delete($nestedGitLeafRoot)

    # nested control metadata directory も fallback の列挙対象外に保つ。
    $nestedGitDirectoryRoot = Join-Path $cleanRoot 'nested-git-directory'
    $nestedGitDirectoryPath = Join-Path $nestedGitDirectoryRoot '.git'
    $nestedGitDirectoryMarker = ('g' + 'hp_') +
        'synthetic_nested_git_directory_marker'
    New-Item `
        -ItemType Directory `
        -Path $nestedGitDirectoryPath `
        -Force | Out-Null
    Set-Content `
        -LiteralPath (Join-Path $nestedGitDirectoryPath 'ignored.md') `
        -Value $nestedGitDirectoryMarker `
        -Encoding UTF8
    $nestedGitDirectoryResult = Invoke-Scanner `
        -ScanPath $cleanRoot `
        -EnvironmentOverrides @{ PATH = $emptyCommandPath }
    if ($nestedGitDirectoryResult.ExitCode -ne 0 -or
        $nestedGitDirectoryResult.Output -notmatch 'working-tree' -or
        $nestedGitDirectoryResult.Output.Contains(
            $nestedGitDirectoryMarker
        )) {
        Add-Failure "Expected a nested .git directory to remain excluded from fallback scanning. Output: $($nestedGitDirectoryResult.Output.Trim())"
    }
    [System.IO.Directory]::Delete($nestedGitDirectoryRoot, $true)

    # scan root と ancestor の `.git` は fallback 除外ではない。Git probe が
    # repository を確立できなければ file/directory の両形を固定診断で拒否する。
    $expectedGitMetadataDiagnostic =
        'Private marker scan failed closed (integrity: git-probe).'
    foreach ($metadataScope in @('root', 'ancestor')) {
        foreach ($metadataKind in @('directory', 'file')) {
            $metadataParent = Join-Path `
                $tempRoot `
                "invalid-$metadataScope-git-metadata-$metadataKind"
            $metadataScanRoot = if ($metadataScope -eq 'ancestor') {
                Join-Path $metadataParent 'scan-root'
            } else {
                $metadataParent
            }
            New-Item `
                -ItemType Directory `
                -Path $metadataScanRoot `
                -Force | Out-Null
            $metadataPath = Join-Path $metadataParent '.git'
            if ($metadataKind -eq 'directory') {
                New-Item `
                    -ItemType Directory `
                    -Path $metadataPath `
                    -Force | Out-Null
            } else {
                [System.IO.File]::WriteAllText(
                    $metadataPath,
                    'gitdir: ../synthetic-missing-git-directory',
                    [System.Text.UTF8Encoding]::new($false)
                )
            }
            Set-Content `
                -LiteralPath (Join-Path $metadataScanRoot 'README.md') `
                -Value 'synthetic clean content' `
                -Encoding UTF8

            $metadataResult = Invoke-Scanner `
                -ScanPath $metadataScanRoot
            if ($metadataResult.ExitCode -ne 2 -or
                $metadataResult.Output.Trim() -cne
                    $expectedGitMetadataDiagnostic) {
                Add-Failure "Expected invalid $metadataScope .git $metadataKind metadata to fail closed with the fixed diagnostic. Output: $($metadataResult.Output.Trim())"
            }
        }
    }

    # linked worktree の `.git` leaf は、Git 自身が exact checkout root と
    # common metadata を証明した場合だけ正規 repository として許可する。
    $linkedSourceRoot = Join-Path $tempRoot 'linked-worktree-source'
    $linkedCheckoutRoot = Join-Path $tempRoot 'linked-worktree-checkout'
    $linkedIsolationRoot = Join-Path $tempRoot 'linked-worktree-isolation'
    foreach ($linkedDirectory in @(
        $linkedSourceRoot,
        $linkedIsolationRoot
    )) {
        New-Item -ItemType Directory -Path $linkedDirectory | Out-Null
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $linkedSourceRoot 'README.md'),
        'synthetic clean linked-worktree content',
        [System.Text.UTF8Encoding]::new($false)
    )
    $linkedInit = Invoke-HermeticGit `
        -WorkingDirectory $linkedSourceRoot `
        -Arguments @('init', '--quiet') `
        -IsolationRoot $linkedIsolationRoot
    $linkedAdd = Invoke-HermeticGit `
        -WorkingDirectory $linkedSourceRoot `
        -Arguments @('add', '--', 'README.md') `
        -IsolationRoot $linkedIsolationRoot
    $linkedFixtureEmail = 'linked-fixture' + '@example.invalid'
    $linkedCommit = Invoke-HermeticGit `
        -WorkingDirectory $linkedSourceRoot `
        -Arguments @(
            '-c',
            'user.name=Linked Worktree Fixture',
            '-c',
            "user.email=$linkedFixtureEmail",
            '-c',
            'commit.gpgSign=false',
            'commit',
            '--quiet',
            '-m',
            'synthetic linked worktree base'
        ) `
        -IsolationRoot $linkedIsolationRoot
    $linkedAddWorktree = Invoke-HermeticGit `
        -WorkingDirectory $linkedSourceRoot `
        -Arguments @(
            'worktree',
            'add',
            '--quiet',
            '--detach',
            $linkedCheckoutRoot,
            'HEAD'
        ) `
        -IsolationRoot $linkedIsolationRoot
    if (@(
        $linkedInit,
        $linkedAdd,
        $linkedCommit,
        $linkedAddWorktree
    ) | Where-Object {
        $_.ExitCode -ne 0 -or
        -not $_.StreamsCompleted -or
        -not $_.TreeStopped
    }) {
        Add-Failure 'Expected the linked-worktree fixture setup to succeed through bounded hermetic Git.'
    } elseif (-not (Test-Path `
        -LiteralPath (Join-Path $linkedCheckoutRoot '.git') `
        -PathType Leaf)) {
        Add-Failure 'Expected the linked checkout to expose a .git control file.'
    } else {
        $linkedScannerResult = Invoke-Scanner -ScanPath $linkedCheckoutRoot
        if ($linkedScannerResult.ExitCode -ne 0 -or
            $linkedScannerResult.Output -notmatch 'git-tracked') {
            Add-Failure "Expected a Git-proven linked worktree control file to scan in git-tracked mode. Output: $($linkedScannerResult.Output.Trim())"
        }
    }
    if (Test-Path -LiteralPath $linkedCheckoutRoot) {
        $linkedRemoveWorktree = Invoke-HermeticGit `
            -WorkingDirectory $linkedSourceRoot `
            -Arguments @(
                'worktree',
                'remove',
                '--force',
                $linkedCheckoutRoot
            ) `
            -IsolationRoot $linkedIsolationRoot
        if ($linkedRemoveWorktree.ExitCode -ne 0 -or
            -not $linkedRemoveWorktree.TreeStopped) {
            Add-Failure "Expected linked-worktree fixture cleanup to succeed. Output: $($linkedRemoveWorktree.Output.Trim())"
        }
    }

    # `.git` は Windows では case-insensitive control metadata、POSIX では
    # ordinary case-sensitive content である。ambient `OS` 変数には委ねない。
    $uppercaseGitRoot = Join-Path $tempRoot 'uppercase-git-entry'
    $uppercaseGitDirectory = Join-Path $uppercaseGitRoot '.GIT'
    New-Item `
        -ItemType Directory `
        -Path $uppercaseGitDirectory `
        -Force | Out-Null
    $uppercaseGitMarker = ('g' + 'hp_') + 'synthetic_uppercase_git'
    [System.IO.File]::WriteAllText(
        (Join-Path $uppercaseGitRoot 'README.md'),
        'synthetic clean uppercase Git entry fixture',
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        (Join-Path $uppercaseGitDirectory 'visible.md'),
        $uppercaseGitMarker,
        [System.Text.UTF8Encoding]::new($false)
    )
    $uppercaseGitResult = Invoke-Scanner -ScanPath $uppercaseGitRoot
    if (Test-PrivateMarkerWindowsHost) {
        if ($uppercaseGitResult.ExitCode -ne 2 -or
            $uppercaseGitResult.Output.Trim() -cne
                $expectedGitMetadataDiagnostic) {
            Add-Failure "Expected Windows .GIT to be treated as case-insensitive Git control metadata. Output: $($uppercaseGitResult.Output.Trim())"
        }
    } elseif ($uppercaseGitResult.ExitCode -eq 0 -or
        $uppercaseGitResult.Output -notmatch
            '\.GIT[\\/]visible\.md' -or
        $uppercaseGitResult.Output.Contains($uppercaseGitMarker)) {
        Add-Failure "Expected POSIX .GIT to remain ordinary case-sensitive scanned content with redacted findings. Output: $($uppercaseGitResult.Output.Trim())"
    }

    # OS は ambient 変数ではなく runtime API で判定する。unset/empty/forgedでも挙動を固定する。
    foreach ($osCase in @(
        @{ Label = 'unset'; Value = $null },
        @{ Label = 'present-empty'; Value = '' },
        @{ Label = 'forged-posix'; Value = 'forged-posix' },
        @{ Label = 'forged-windows'; Value = 'Windows_NT' }
    )) {
        $osEnvironment = @{
            PATH = $emptyCommandPath
            OS = $osCase.Value
        }
        $osResult = Invoke-Scanner `
            -ScanPath $cleanRoot `
            -EnvironmentOverrides $osEnvironment
        if ($osResult.ExitCode -ne 0 -or
            $osResult.Output -notmatch 'working-tree') {
            Add-Failure "Expected ambient OS case '$($osCase.Label)' not to change runtime detection. Output: $($osResult.Output.Trim())"
        }
    }

    # content byte数が0でも entry数で必ず停止し、空file群を無制限に保持しない。
    $zeroByteRoot = Join-Path $tempRoot 'zero-byte-entry-limit'
    New-Item -ItemType Directory -Path $zeroByteRoot | Out-Null
    for ($zeroIndex = 0; $zeroIndex -le 10000; $zeroIndex++) {
        $zeroPath = Join-Path $zeroByteRoot (
            'zero-{0:D5}' -f $zeroIndex
        )
        $zeroStream = [System.IO.File]::Create($zeroPath)
        $zeroStream.Dispose()
    }
    $zeroByteResult = Invoke-Scanner `
        -ScanPath $zeroByteRoot `
        -EnvironmentOverrides @{ PATH = $emptyCommandPath }
    if (-not (Test-FixedScannerBoundaryFailure $zeroByteResult) -or
        $zeroByteResult.Output.Length -gt 16384) {
        Add-Failure "Expected zero-byte file amplification to hit the bounded entry limit. Output: $($zeroByteResult.Output.Trim())"
    }

    # Higher-recall cloud / PEM prefixes, with one redaction regression each.
    # finding 側も 1 directory へ集約するが、rule と固有 file 名を全件確認して
    # どれか 1 件だけの成功を matrix 全体の成功と誤認しない。
    $findingRoot = Join-Path $tempRoot 'combined findings'
    New-Item -ItemType Directory -Path $findingRoot | Out-Null
    $syntheticMarker = ('g' + 'hp_') + 'synthetic_placeholder_only'

    # finding 件数の上限内でも serialized payload が 64 KiB を超える場合、
    # partial table を出さず固定 code だけへ縮退する。
    $findingOutputCapRoot = Join-Path $tempRoot 'finding-output-cap'
    New-Item -ItemType Directory -Path $findingOutputCapRoot | Out-Null
    for ($fileIndex = 0; $fileIndex -lt 8; $fileIndex++) {
        $longFileName = (
            'finding-output-{0}-' -f $fileIndex
        ) + ('x' * 96) + '.txt'
        Set-Content `
            -LiteralPath (Join-Path $findingOutputCapRoot $longFileName) `
            -Value @(
                for ($lineIndex = 0; $lineIndex -lt 64; $lineIndex++) {
                    $syntheticMarker
                }
            ) `
            -Encoding UTF8
    }
    $findingOutputCapResult = Invoke-Scanner `
        -ScanPath $findingOutputCapRoot `
        -EnvironmentOverrides @{ PATH = $emptyCommandPath }
    if ($findingOutputCapResult.ExitCode -eq 0 -or
        $findingOutputCapResult.Output -notmatch
            'scan-diagnostic-output-limit' -or
        $findingOutputCapResult.Output -match '<redacted>' -or
        $findingOutputCapResult.Output.Length -gt 16384) {
        Add-Failure 'Expected over-limit finding output to collapse to one bounded diagnostic without a partial table.'
    }

    $adjacentContent = 'synthetic marker after UTF-8: ' + [char]0x30C8 + $syntheticMarker
    [System.IO.File]::WriteAllText(
        (Join-Path $findingRoot 'utf8-adjacent.md'),
        $adjacentContent,
        [System.Text.UTF8Encoding]::new($false)
    )
    $prefixCases = @(
        @{ Rule = 'openai-api-key-prefix';            Marker = ('s' + 'k-') + 'SyntheticOpenAI000000000000' }
        @{ Rule = 'aws-access-key-id';                Marker = ('A' + 'KIA') + 'EXAMPLE0000000000000' }
        @{ Rule = 'gcp-api-key-prefix';               Marker = ('AIza') + 'Synthetic0000000000000000000000000000' }
        @{ Rule = 'slack-user-token-prefix';          Marker = ('xo' + 'xp-') + 'synthetic-placeholder' }
        @{ Rule = 'slack-legacy-app-token-prefix';    Marker = ('xo' + 'xa-') + 'synthetic-placeholder' }
        @{ Rule = 'slack-app-level-token-prefix';     Marker = ('xa' + 'pp-') + 'synthetic-placeholder' }
        @{ Rule = 'stripe-live-secret-key';           Marker = ('s' + 'k') + '_live_SyntheticPlaceholder0000' }
        @{ Rule = 'pem-private-key-block';            Marker = '-----' + ('BEGIN ' + 'OPENSSH PRIVATE KEY') + '-----' }
    )

    foreach ($case in $prefixCases) {
        Set-Content `
            -LiteralPath (Join-Path $findingRoot ("$($case.Rule).txt")) `
            -Value "synthetic marker: $($case.Marker)" `
            -Encoding UTF8
    }

    # windows-absolute-path: private-looking paths should be findings.
    # Split the literal so this test file does not make the scanner flag itself.
    $realWinPath = 'C' + ':\Users\realperson\Secrets\config'
    Set-Content `
        -LiteralPath (Join-Path $findingRoot 'windows-path.md') `
        -Value "See $realWinPath for details." `
        -Encoding UTF8
    # System path 自体を許可しても、同じ行の後続 marker path は必ず再探索する。
    Set-Content `
        -LiteralPath (Join-Path $findingRoot 'windows-path-after-system.md') `
        -Value "Run C:\Program Files\Git\bin\bash.exe, then inspect $realWinPath." `
        -Encoding UTF8

    # non-allowlisted GitHub URL も同一 finding scan で検査する。
    # URLs are split so this test file does not make the scanner flag itself.
    $foreignUrl = ('https://github' + '.com/') +
        'h8nc4y/synthetic-other-repository'
    Set-Content `
        -LiteralPath (Join-Path $findingRoot 'github-url.md') `
        -Value "See $foreignUrl for details." `
        -Encoding UTF8

    # Cf/bidi と Unicode line/paragraph separator は terminal 上で必ず escape する。
    $diagnosticControlCharacters = @(
        [char]0x202E,
        [char]0x2028,
        [char]0x2029
    )
    $diagnosticControlName =
        'diagnostic-' +
        ($diagnosticControlCharacters -join '-') +
        '-spoof.md'
    Set-Content `
        -LiteralPath (Join-Path $findingRoot $diagnosticControlName) `
        -Value "synthetic marker: $syntheticMarker" `
        -Encoding UTF8

    $findingResult = Invoke-Scanner -ScanPath $findingRoot
    if ($findingResult.ExitCode -eq 0) {
        Add-Failure 'Expected the combined synthetic finding fixture to fail.'
    }
    $expectedRules = @(
        'github-classic-token-prefix'
        $prefixCases.Rule
        'windows-absolute-path'
        'non-allowlisted-github-repo-url'
    )
    foreach ($rule in $expectedRules) {
        if ($findingResult.Output -notmatch [regex]::Escape($rule)) {
            Add-Failure "Expected combined finding output to name $rule. Output: $($findingResult.Output.Trim())"
        }
    }
    if ($findingResult.Output -notmatch 'utf8-adjacent\.md') {
        Add-Failure 'Expected the BOM-less UTF-8 adjacent marker file to appear in findings.'
    }
    if ($findingResult.Output -notmatch 'windows-path-after-system\.md') {
        Add-Failure 'Expected a path after an allowlisted system path to remain visible in findings.'
    }
    foreach ($rawValue in @(
        $syntheticMarker
        $prefixCases.Marker
        $realWinPath
        $foreignUrl
    )) {
        if ($findingResult.Output.Contains($rawValue)) {
            Add-Failure 'Expected every combined finding value to stay redacted.'
        }
    }
    if ($findingResult.Output -notmatch '<redacted>') {
        Add-Failure "Expected combined findings to report '<redacted>'. Output: $($findingResult.Output.Trim())"
    }
    foreach ($diagnosticCharacter in $diagnosticControlCharacters) {
        if ($findingResult.Output.Contains([string]$diagnosticCharacter)) {
            Add-Failure 'Expected diagnostic control characters not to appear raw in scanner output.'
        }
    }
    foreach ($escapedDiagnostic in @('\u202E', '\u2028', '\u2029')) {
        if (-not $findingResult.Output.Contains($escapedDiagnostic)) {
            Add-Failure "Expected scanner output to contain escaped diagnostic text $escapedDiagnostic."
        }
    }

    # 同一行のURL列挙は finding を1件へ畳み、出力サイズを URL 数で増幅させない。
    $urlAmplificationRoot = Join-Path $tempRoot 'url-amplification'
    New-Item -ItemType Directory -Path $urlAmplificationRoot | Out-Null
    $foreignUrls = (
        1..200 |
            ForEach-Object { "${foreignUrl}?fixture=$_" }
    ) -join ' '
    Set-Content `
        -LiteralPath (Join-Path $urlAmplificationRoot 'many-urls.md') `
        -Value $foreignUrls `
        -Encoding UTF8
    $urlAmplificationResult = Invoke-Scanner -ScanPath $urlAmplificationRoot
    $urlRuleCount = [regex]::Matches(
        $urlAmplificationResult.Output,
        'non-allowlisted-github-repo-url'
    ).Count
    if ($urlAmplificationResult.ExitCode -eq 0 -or
        $urlRuleCount -ne 1 -or
        $urlAmplificationResult.Output.Length -gt 16384) {
        Add-Failure "Expected same-line URL findings to stay deduplicated and bounded. Output length: $($urlAmplificationResult.Output.Length)"
    }

    # allowlisted URL だけでも NextMatch 回数を固定し、巨大な match 列挙を fail-closed にする。
    $allowedUrl = ('https://github' + '.com/') +
        'h8nc4y/codex-windows-sandbox-troubleshooting'
    $allowedUrlAmplificationRoot =
        Join-Path $tempRoot 'allowed-url-amplification'
    New-Item -ItemType Directory -Path $allowedUrlAmplificationRoot | Out-Null
    Set-Content `
        -LiteralPath (
            Join-Path $allowedUrlAmplificationRoot 'many-allowed-urls.md'
        ) `
        -Value ((1..300 | ForEach-Object { $allowedUrl }) -join ' ') `
        -Encoding UTF8
    $allowedUrlAmplificationResult =
        Invoke-Scanner -ScanPath $allowedUrlAmplificationRoot
    if (-not (Test-FixedScannerBoundaryFailure `
        $allowedUrlAmplificationResult) -or
        $allowedUrlAmplificationResult.Output.Length -gt 16384) {
        Add-Failure "Expected allowed-URL amplification to fail inside a bounded diagnostic. Output: $($allowedUrlAmplificationResult.Output.Trim())"
    }

    # 1行全体を split 配列へ複製せず、bounded substring の前に行長で拒否する。
    $overlongLineRoot = Join-Path $tempRoot 'overlong-line-limit'
    New-Item -ItemType Directory -Path $overlongLineRoot | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $overlongLineRoot 'overlong.txt'),
        [string]::new([char]'a', (1MB + 1)),
        [System.Text.UTF8Encoding]::new($false)
    )
    $overlongLineResult = Invoke-Scanner -ScanPath $overlongLineRoot
    if (-not (Test-FixedScannerBoundaryFailure $overlongLineResult) -or
        $overlongLineResult.Output.Length -gt 16384) {
        Add-Failure "Expected an overlong line to fail before unbounded line scanning. Output: $($overlongLineResult.Output.Trim())"
    }

    # finding は file 単位と scan 全体の双方で上限を持つ。
    $perFileFindingRoot = Join-Path $tempRoot 'per-file-finding-limit'
    New-Item -ItemType Directory -Path $perFileFindingRoot | Out-Null
    $perFileMarkerLines = (
        1..65 |
            ForEach-Object { "synthetic line $_ $syntheticMarker" }
    )
    Set-Content `
        -LiteralPath (Join-Path $perFileFindingRoot 'many-findings.md') `
        -Value $perFileMarkerLines `
        -Encoding UTF8
    $perFileFindingResult = Invoke-Scanner -ScanPath $perFileFindingRoot
    if (-not (Test-FixedScannerBoundaryFailure $perFileFindingResult) -or
        $perFileFindingResult.Output.Length -gt 16384 -or
        $perFileFindingResult.Output.Contains($syntheticMarker)) {
        Add-Failure "Expected per-file finding amplification to fail closed without exposing values. Output: $($perFileFindingResult.Output.Trim())"
    }

    $totalFindingRoot = Join-Path $tempRoot 'total-finding-limit'
    New-Item -ItemType Directory -Path $totalFindingRoot | Out-Null
    foreach ($fileIndex in 1..9) {
        $totalMarkerLines = (
            1..60 |
                ForEach-Object {
                    "synthetic file $fileIndex line $_ $syntheticMarker"
                }
        )
        Set-Content `
            -LiteralPath (
                Join-Path $totalFindingRoot ("findings-{0:D2}.md" -f $fileIndex)
            ) `
            -Value $totalMarkerLines `
            -Encoding UTF8
    }
    $totalFindingResult = Invoke-Scanner -ScanPath $totalFindingRoot
    if (-not (Test-FixedScannerBoundaryFailure $totalFindingResult) -or
        $totalFindingResult.Output.Length -gt 16384 -or
        $totalFindingResult.Output.Contains($syntheticMarker)) {
        Add-Failure "Expected total finding amplification to fail closed without exposing values. Output: $($totalFindingResult.Output.Trim())"
    }

    $localMarkerRoot = Join-Path $tempRoot 'local-marker'
    New-Item -ItemType Directory -Path $localMarkerRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $localMarkerRoot '.private-markers.local') -Value 'local-only-marker' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $localMarkerRoot 'leak.txt') -Value 'synthetic local-only-marker fixture' -Encoding UTF8

    $localMarkerResult = Invoke-Scanner -ScanPath $localMarkerRoot
    if ($localMarkerResult.ExitCode -eq 0) {
        Add-Failure 'Expected local marker fixture to fail, but scanner exited 0.'
    }
    if ($localMarkerResult.Output -notmatch 'local-private-marker-1') {
        Add-Failure "Expected local marker output to name local-private-marker-1. Output: $($localMarkerResult.Output.Trim())"
    }

    # 036 固有の環境変数名を child process だけへ渡し、port 時の名称 drift を固定する。
    $environmentMarkerRoot = Join-Path $tempRoot 'environment-marker'
    New-Item -ItemType Directory -Path $environmentMarkerRoot | Out-Null
    $environmentMarker = 'synthetic-environment-only-marker'
    Set-Content `
        -LiteralPath (Join-Path $environmentMarkerRoot 'leak.txt') `
        -Value "fixture contains $environmentMarker" `
        -Encoding UTF8
    $environmentMarkerResult = Invoke-Scanner `
        -ScanPath $environmentMarkerRoot `
        -EnvironmentOverrides @{
            CODEX_WINDOWS_SANDBOX_TROUBLESHOOTING_PRIVATE_MARKERS =
                $environmentMarker
        }
    if ($environmentMarkerResult.ExitCode -eq 0 -or
        $environmentMarkerResult.Output -notmatch 'local-private-marker-1' -or
        $environmentMarkerResult.Output.Contains($environmentMarker)) {
        Add-Failure "Expected the 036 environment marker contract to fail redacted. Output: $($environmentMarkerResult.Output.Trim())"
    }

    if (Test-PrivateMarkerWindowsHost) {
        # Explicit scan root 自体が junction の場合も、外部 target を列挙する前に拒否する。
        $rootJunctionPath = Join-Path $tempRoot 'root junction'
        $rootJunctionTarget = Join-Path $tempRoot 'root junction external target'
        New-Item -ItemType Directory -Path $rootJunctionTarget | Out-Null
        Set-Content `
            -LiteralPath (Join-Path $rootJunctionTarget 'clean.md') `
            -Value 'synthetic clean root-junction content' `
            -Encoding UTF8
        try {
            New-Item `
                -ItemType Junction `
                -Path $rootJunctionPath `
                -Target $rootJunctionTarget |
                Out-Null
            $rootJunctionResult = Invoke-Scanner -ScanPath $rootJunctionPath
            if (-not (Test-FixedScannerBoundaryFailure `
                $rootJunctionResult)) {
                Add-Failure "Expected an explicit root junction to fail closed. Output: $($rootJunctionResult.Output.Trim())"
            }
        }
        finally {
            if (Test-Path -LiteralPath $rootJunctionPath) {
                [System.IO.Directory]::Delete($rootJunctionPath)
            }
        }

        # Dangling .git junction は target 解決で消えたように見えても Git 境界として fail-closed にする。
        $danglingGitRoot = Join-Path $tempRoot 'dangling git marker'
        $danglingGitTarget = Join-Path $tempRoot 'deleted git marker target'
        $danglingGitMarker = Join-Path $danglingGitRoot '.git'
        New-Item -ItemType Directory -Path $danglingGitRoot | Out-Null
        New-Item -ItemType Directory -Path $danglingGitTarget | Out-Null
        try {
            New-Item -ItemType Junction -Path $danglingGitMarker -Target $danglingGitTarget | Out-Null
            [System.IO.Directory]::Delete($danglingGitTarget)
            $danglingGitResult = Invoke-Scanner -ScanPath $danglingGitRoot
            if ($danglingGitResult.ExitCode -ne 2 -or
                $danglingGitResult.Output.Trim() -cne
                    $expectedGitMetadataDiagnostic) {
                Add-Failure "Expected a dangling .git junction to block fallback scanning. Output: $($danglingGitResult.Output.Trim())"
            }
            $danglingNoGitResult = Invoke-Scanner `
                -ScanPath $danglingGitRoot `
                -EnvironmentOverrides @{ PATH = $emptyCommandPath }
            if ($danglingNoGitResult.ExitCode -ne 2 -or
                $danglingNoGitResult.Output.Trim() -cne
                    $expectedGitMetadataDiagnostic) {
                Add-Failure "Expected a dangling .git junction to block no-Git fallback. Output: $($danglingNoGitResult.Output.Trim())"
            }
        }
        finally {
            $danglingGitEntry = Get-ChildItem `
                -LiteralPath $danglingGitRoot `
                -Force `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ceq '.git' } |
                Select-Object -First 1
            if ($null -ne $danglingGitEntry) {
                $danglingGitEntry.Delete()
            }
        }
    }

    # 敵対的な Git 環境は scanner の子だけへ渡す。親の absent / present-empty は変更しない。
    $trackedRoot = Join-Path $tempRoot 'git tracked target'
    $decoyRoot = Join-Path $tempRoot 'git decoy'
    $fixtureIsolationRoot = Join-Path $tempRoot 'fixture-git-isolation'
    $ambientRoot = Join-Path $tempRoot 'ambient-git'
    foreach ($directory in @($trackedRoot, $decoyRoot, $fixtureIsolationRoot, $ambientRoot)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }

    $targetInit = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('init', '--quiet') `
        -IsolationRoot $fixtureIsolationRoot
    if ($targetInit.ExitCode -ne 0 -or $targetInit.TimedOut -or -not $targetInit.TreeStopped) {
        Add-Failure "Expected bounded target git init to succeed. Output: $($targetInit.Output.Trim())"
    } else {
        # Git-backed列挙はuntracked local markerを返さない。dangling leafを
        # Test-Pathで不存在扱いせず、root entryの段階でfail closedにする。
        $danglingLocalMarkerPath =
            Join-Path $trackedRoot '.private-markers.local'
        $danglingLocalMarkerTarget =
            Join-Path $tempRoot 'dangling local marker target'
        New-Item `
            -ItemType Directory `
            -Path $danglingLocalMarkerTarget |
            Out-Null
        try {
            New-Item `
                -ItemType $directoryLinkItemType `
                -Path $danglingLocalMarkerPath `
                -Target $danglingLocalMarkerTarget |
                Out-Null
            [System.IO.Directory]::Delete($danglingLocalMarkerTarget)
            $danglingLocalMarkerResult = Invoke-Scanner `
                -ScanPath $trackedRoot
            if (-not (Test-FixedScannerBoundaryFailure `
                    $danglingLocalMarkerResult)) {
                Add-Failure "Expected an initial dangling local-marker leaf to fail closed. Output: $($danglingLocalMarkerResult.Output.Trim())"
            }
        }
        finally {
            $danglingLocalMarkerEntry =
                Get-ChildItem `
                    -LiteralPath $trackedRoot `
                    -Force `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.Name -ceq '.private-markers.local'
                    } |
                    Select-Object -First 1
            if ($null -ne $danglingLocalMarkerEntry) {
                $danglingLocalMarkerEntry.Delete()
            }
        }
    }

    if ((Test-PrivateMarkerWindowsHost) -and
        (Test-Path -LiteralPath $syntheticGitPath -PathType Leaf)) {
        # worktree/local再検証後の3回目raw stage listing直前に、実indexへ
        # replacementとadditionを同時適用し、最終windowをfail-closedで閉じる。
        $indexMutationRoot = Join-Path $tempRoot 'index mutation target'
        $indexMutationIsolationRoot = Join-Path `
            $tempRoot `
            'index-mutation-git-isolation'
        foreach ($directory in @(
            $indexMutationRoot,
            $indexMutationIsolationRoot
        )) {
            New-Item -ItemType Directory -Path $directory | Out-Null
        }
        $replacementRelative = 'race-replaced.env'
        $additionRelative = 'race-added.env'
        $replacementPath = Join-Path $indexMutationRoot $replacementRelative
        $additionPath = Join-Path $indexMutationRoot $additionRelative
        Set-Content `
            -LiteralPath $replacementPath `
            -Value 'synthetic baseline replacement' `
            -Encoding UTF8
        $mutationInit = Invoke-HermeticGit `
            -WorkingDirectory $indexMutationRoot `
            -Arguments @('init', '--quiet') `
            -IsolationRoot $indexMutationIsolationRoot
        $mutationBaselineAdd = Invoke-HermeticGit `
            -WorkingDirectory $indexMutationRoot `
            -Arguments @('add', '--', $replacementRelative) `
            -IsolationRoot $indexMutationIsolationRoot
        $oldReplacementOid = Invoke-HermeticGit `
            -WorkingDirectory $indexMutationRoot `
            -Arguments @('rev-parse', ":$replacementRelative") `
            -IsolationRoot $indexMutationIsolationRoot

        Set-Content `
            -LiteralPath $replacementPath `
            -Value 'synthetic changed replacement' `
            -Encoding UTF8
        Set-Content `
            -LiteralPath $additionPath `
            -Value 'synthetic added during scan' `
            -Encoding UTF8
        $expectedReplacementOid = Invoke-HermeticGit `
            -WorkingDirectory $indexMutationRoot `
            -Arguments @('hash-object', '--', $replacementRelative) `
            -IsolationRoot $indexMutationIsolationRoot

        if (@(
            $mutationInit,
            $mutationBaselineAdd,
            $oldReplacementOid,
            $expectedReplacementOid
        ) | Where-Object {
            $_.ExitCode -ne 0 -or
            -not $_.StreamsCompleted -or
            -not $_.TreeStopped
        }) {
            Add-Failure 'Expected index-mutation fixture setup to succeed.'
        } else {
            $indexMutationCounter = Join-Path $tempRoot 'index-mutation-counter.txt'
            $indexMutationSentinel = Join-Path $tempRoot 'index-mutation-complete.txt'
            $realGitPath = (Get-Command git -ErrorAction Stop).Source
            Set-SyntheticGitConfiguration `
                -Path $syntheticGitConfigurationPath `
                -Values @{
                    mode = 'index-mutation'
                    'real-git' = $realGitPath
                    counter = $indexMutationCounter
                    repository = $indexMutationRoot
                    replacement = $replacementRelative
                    addition = $additionRelative
                    sentinel = $indexMutationSentinel
                }
            $indexMutationResult = Invoke-Scanner `
                -ScanPath $indexMutationRoot `
                -EnvironmentOverrides @{
                    PATH = $syntheticGitDirectory
                }
            if ($indexMutationResult.ExitCode -ne 2 -or
                -not $indexMutationResult.StreamsCompleted -or
                -not $indexMutationResult.TreeStopped -or
                $indexMutationResult.TimedOut -or
                $indexMutationResult.OutputLimitExceeded -or
                $indexMutationResult.PipeLeakDetected -or
                $indexMutationResult.Output.Trim() -cne
                    $expectedScannerBoundaryDiagnostic) {
                Add-Failure "Expected raw index drift to fail through a healthy boundary. Output: $($indexMutationResult.Output.Trim())"
            }
            if (-not (Test-Path -LiteralPath $indexMutationCounter) -or
                (Get-Content -LiteralPath $indexMutationCounter -Raw).Trim() -cne '3') {
                Add-Failure 'Expected exactly three raw stage listings in the index-mutation fixture.'
            }
            if (-not (Test-Path -LiteralPath $indexMutationSentinel)) {
                Add-Failure 'Expected the real staged mutation after content revalidation and before final index verification.'
            }

            $addedIndexEntry = Invoke-HermeticGit `
                -WorkingDirectory $indexMutationRoot `
                -Arguments @(
                    'ls-files',
                    '--error-unmatch',
                    '--',
                    $additionRelative
                ) `
                -IsolationRoot $indexMutationIsolationRoot
            $newReplacementOid = Invoke-HermeticGit `
                -WorkingDirectory $indexMutationRoot `
                -Arguments @('rev-parse', ":$replacementRelative") `
                -IsolationRoot $indexMutationIsolationRoot
            if ($addedIndexEntry.ExitCode -ne 0) {
                Add-Failure 'Expected the mutation proxy to add a real index entry.'
            }
            if ($newReplacementOid.ExitCode -ne 0 -or
                $newReplacementOid.Output.Trim() -ceq $oldReplacementOid.Output.Trim() -or
                $newReplacementOid.Output.Trim() -cne $expectedReplacementOid.Output.Trim()) {
                Add-Failure 'Expected the mutation proxy to replace the staged blob with the changed worktree blob.'
            }
        }

        # index snapshotが不変でも、second raw stage listingでworktreeだけを
        # 変更するproxyを使い、final byte/presence revalidationを実測する。
        $worktreeMutationRoot = Join-Path `
            $tempRoot `
            'worktree mutation target'
        $worktreeMutationIsolationRoot = Join-Path `
            $tempRoot `
            'worktree-mutation-git-isolation'
        New-Item -ItemType Directory -Path $worktreeMutationRoot | Out-Null
        New-Item `
            -ItemType Directory `
            -Path $worktreeMutationIsolationRoot |
            Out-Null
        $worktreeMutationRelative = 'worktree-race.md'
        $worktreeMutationPath =
            Join-Path $worktreeMutationRoot $worktreeMutationRelative
        Set-Content `
            -LiteralPath $worktreeMutationPath `
            -Value 'synthetic worktree baseline' `
            -Encoding UTF8
        $worktreeMutationInit = Invoke-HermeticGit `
            -WorkingDirectory $worktreeMutationRoot `
            -Arguments @('init', '--quiet') `
            -IsolationRoot $worktreeMutationIsolationRoot
        $worktreeMutationAdd = Invoke-HermeticGit `
            -WorkingDirectory $worktreeMutationRoot `
            -Arguments @('add', '--', $worktreeMutationRelative) `
            -IsolationRoot $worktreeMutationIsolationRoot
        $worktreeMutationCounter =
            Join-Path $tempRoot 'worktree-mutation-counter.txt'
        $worktreeMutationSentinel =
            Join-Path $tempRoot 'worktree-mutation-complete.txt'
        if ($worktreeMutationInit.ExitCode -ne 0 -or
            $worktreeMutationAdd.ExitCode -ne 0) {
            Add-Failure 'Expected worktree-mutation fixture setup to succeed.'
        } else {
            $realGitPath = (Get-Command git -ErrorAction Stop).Source
            Set-SyntheticGitConfiguration `
                -Path $syntheticGitConfigurationPath `
                -Values @{
                    mode = 'worktree-mutation'
                    'real-git' = $realGitPath
                    counter = $worktreeMutationCounter
                    repository = $worktreeMutationRoot
                    replacement = $worktreeMutationRelative
                    sentinel = $worktreeMutationSentinel
                }
            $worktreeMutationResult = Invoke-Scanner `
                -ScanPath $worktreeMutationRoot `
                -EnvironmentOverrides @{
                    PATH = $syntheticGitDirectory
                }
            if (-not (Test-FixedScannerBoundaryFailure `
                    $worktreeMutationResult)) {
                Add-Failure "Expected worktree byte drift to fail closed. Output: $($worktreeMutationResult.Output.Trim())"
            }
            if (-not (Test-Path -LiteralPath $worktreeMutationSentinel) -or
                -not (Test-Path -LiteralPath $worktreeMutationCounter) -or
                (Get-Content `
                    -LiteralPath $worktreeMutationCounter `
                    -Raw).Trim() -cne '2') {
                Add-Failure 'Expected worktree mutation after exactly two raw stage listings.'
            }
        }

        # local markerはrule入力そのもの。second raw stage listing直前に
        # create/change/delete/dangling leaf化し、final entry/byte snapshotが
        # すべて拒否する。
        foreach ($localMarkerMutationAction in @(
                'create',
                'change',
                'delete',
                'dangling'
            )) {
            $localMarkerMutationRoot = Join-Path `
                $tempRoot `
                "local marker $localMarkerMutationAction target"
            $localMarkerMutationIsolationRoot = Join-Path `
                $tempRoot `
                "local-marker-$localMarkerMutationAction-git-isolation"
            New-Item `
                -ItemType Directory `
                -Path $localMarkerMutationRoot |
                Out-Null
            New-Item `
                -ItemType Directory `
                -Path $localMarkerMutationIsolationRoot |
                Out-Null
            $localMarkerTrackedRelative = 'tracked.md'
            $localMarkerTrackedPath = Join-Path `
                $localMarkerMutationRoot `
                $localMarkerTrackedRelative
            [System.IO.File]::WriteAllText(
                $localMarkerTrackedPath,
                'synthetic local marker race target',
                [System.Text.UTF8Encoding]::new($false)
            )
            $localMarkerMutationInit = Invoke-HermeticGit `
                -WorkingDirectory $localMarkerMutationRoot `
                -Arguments @('init', '--quiet') `
                -IsolationRoot $localMarkerMutationIsolationRoot
            $localMarkerMutationAdd = Invoke-HermeticGit `
                -WorkingDirectory $localMarkerMutationRoot `
                -Arguments @('add', '--', $localMarkerTrackedRelative) `
                -IsolationRoot $localMarkerMutationIsolationRoot
            $localMarkerPath = Join-Path `
                $localMarkerMutationRoot `
                '.private-markers.local'
            $localMarkerPreparedLink = ''
            if ($localMarkerMutationAction -eq 'dangling') {
                $localMarkerPreparedTarget = Join-Path `
                    $tempRoot `
                    'prepared dangling local marker target'
                $localMarkerPreparedLink = Join-Path `
                    $tempRoot `
                    'prepared dangling local marker link'
                New-Item `
                    -ItemType Directory `
                    -Path $localMarkerPreparedTarget |
                    Out-Null
                New-Item `
                    -ItemType Junction `
                    -Path $localMarkerPreparedLink `
                    -Target $localMarkerPreparedTarget |
                    Out-Null
                [System.IO.Directory]::Delete($localMarkerPreparedTarget)
            } elseif ($localMarkerMutationAction -ne 'create') {
                [System.IO.File]::WriteAllText(
                    $localMarkerPath,
                    'synthetic-local-marker-before',
                    [System.Text.UTF8Encoding]::new($false)
                )
            }
            $localMarkerMutationCounter = Join-Path `
                $tempRoot `
                "local-marker-$localMarkerMutationAction-counter.txt"
            $localMarkerMutationSentinel = Join-Path `
                $tempRoot `
                "local-marker-$localMarkerMutationAction-complete.txt"
            $localMarkerMutationContent =
                "synthetic-local-marker-after-$localMarkerMutationAction"
            if ($localMarkerMutationInit.ExitCode -ne 0 -or
                $localMarkerMutationAdd.ExitCode -ne 0) {
                Add-Failure "Expected local-marker-$localMarkerMutationAction fixture setup to succeed."
                continue
            }

            $realGitPath = (Get-Command git -ErrorAction Stop).Source
            Set-SyntheticGitConfiguration `
                -Path $syntheticGitConfigurationPath `
                -Values @{
                    mode = 'local-marker-mutation'
                    'real-git' = $realGitPath
                    counter = $localMarkerMutationCounter
                    repository = $localMarkerMutationRoot
                    action = $localMarkerMutationAction
                    content = $localMarkerMutationContent
                    sentinel = $localMarkerMutationSentinel
                    'prepared-link' = $localMarkerPreparedLink
                }
            $localMarkerMutationResult = Invoke-Scanner `
                -ScanPath $localMarkerMutationRoot `
                -EnvironmentOverrides @{
                    PATH = $syntheticGitDirectory
                }
            if (-not (Test-FixedScannerBoundaryFailure `
                    $localMarkerMutationResult)) {
                Add-Failure "Expected local marker $localMarkerMutationAction drift to fail closed. Output: $($localMarkerMutationResult.Output.Trim())"
            }
            if (-not (Test-Path -LiteralPath $localMarkerMutationSentinel) -or
                -not (Test-Path -LiteralPath $localMarkerMutationCounter) -or
                (Get-Content `
                    -LiteralPath $localMarkerMutationCounter `
                    -Raw).Trim() -cne '2') {
                Add-Failure "Expected local marker $localMarkerMutationAction after exactly two raw stage listings."
            }
            if ($localMarkerMutationAction -eq 'delete') {
                if (Test-Path -LiteralPath $localMarkerPath) {
                    Add-Failure 'Expected local marker delete proxy to remove the file.'
                }
            } elseif ($localMarkerMutationAction -eq 'dangling') {
                $localMarkerDanglingEntry =
                    Get-ChildItem `
                        -LiteralPath $localMarkerMutationRoot `
                        -Force `
                        -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.Name -ceq '.private-markers.local'
                        } |
                        Select-Object -First 1
                if ($null -eq $localMarkerDanglingEntry -or
                    ($localMarkerDanglingEntry.Attributes -band
                        [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                    Add-Failure 'Expected local marker dangling proxy to leave an unsafe leaf.'
                }
                if ($null -ne $localMarkerDanglingEntry) {
                    $localMarkerDanglingEntry.Delete()
                }
            } elseif (-not (Test-Path -LiteralPath $localMarkerPath) -or
                [System.IO.File]::ReadAllText($localMarkerPath) -cne
                    $localMarkerMutationContent) {
                Add-Failure "Expected local marker $localMarkerMutationAction proxy to write the changed content."
            }
        }

        # mode/OID/pathが同一のまま、content再検証後にCE_INTENT_TO_ADD
        # flagだけ変わるraceも、3回目raw debug snapshotで検出する。
        $flagsMutationRoot = Join-Path $tempRoot 'flags mutation target'
        $flagsMutationIsolationRoot =
            Join-Path $tempRoot 'flags-mutation-git-isolation'
        New-Item -ItemType Directory -Path $flagsMutationRoot | Out-Null
        New-Item `
            -ItemType Directory `
            -Path $flagsMutationIsolationRoot |
            Out-Null
        $flagsRelative = 'flags-only-empty.md'
        $flagsPath = Join-Path $flagsMutationRoot $flagsRelative
        [System.IO.File]::WriteAllBytes($flagsPath, [byte[]]@())
        $flagsInit = Invoke-HermeticGit `
            -WorkingDirectory $flagsMutationRoot `
            -Arguments @('init', '--quiet') `
            -IsolationRoot $flagsMutationIsolationRoot
        $flagsAdd = Invoke-HermeticGit `
            -WorkingDirectory $flagsMutationRoot `
            -Arguments @('add', '--', $flagsRelative) `
            -IsolationRoot $flagsMutationIsolationRoot
        $flagsStageArguments = @(
            '-c',
            'core.quotepath=false',
            'ls-files',
            '-z',
            '--stage',
            '--',
            $flagsRelative
        )
        $flagsDebugArguments = @(
            '-c',
            'core.quotepath=false',
            'ls-files',
            '-z',
            '--stage',
            '--debug',
            '--',
            $flagsRelative
        )
        $flagsStageBefore = Invoke-HermeticGit `
            -WorkingDirectory $flagsMutationRoot `
            -Arguments $flagsStageArguments `
            -IsolationRoot $flagsMutationIsolationRoot
        $flagsDebugBefore = Invoke-HermeticGit `
            -WorkingDirectory $flagsMutationRoot `
            -Arguments $flagsDebugArguments `
            -IsolationRoot $flagsMutationIsolationRoot
        if (@(
            $flagsInit,
            $flagsAdd,
            $flagsStageBefore,
            $flagsDebugBefore
        ) | Where-Object {
            $_.ExitCode -ne 0 -or
            -not $_.StreamsCompleted -or
            -not $_.TreeStopped
        }) {
            Add-Failure 'Expected flags-only mutation fixture setup to succeed.'
        } else {
            $flagsMutationCounter =
                Join-Path $tempRoot 'flags-mutation-counter.txt'
            $flagsMutationSentinel =
                Join-Path $tempRoot 'flags-mutation-complete.txt'
            $realGitPath = (Get-Command git -ErrorAction Stop).Source
            Set-SyntheticGitConfiguration `
                -Path $syntheticGitConfigurationPath `
                -Values @{
                    mode = 'flags-mutation'
                    'real-git' = $realGitPath
                    counter = $flagsMutationCounter
                    repository = $flagsMutationRoot
                    replacement = $flagsRelative
                    sentinel = $flagsMutationSentinel
                }
            $flagsMutationResult = Invoke-Scanner `
                -ScanPath $flagsMutationRoot `
                -EnvironmentOverrides @{
                    PATH = $syntheticGitDirectory
                }
            if ($flagsMutationResult.ExitCode -ne 2 -or
                -not $flagsMutationResult.StreamsCompleted -or
                -not $flagsMutationResult.TreeStopped -or
                $flagsMutationResult.TimedOut -or
                $flagsMutationResult.OutputLimitExceeded -or
                $flagsMutationResult.PipeLeakDetected -or
                $flagsMutationResult.Output.Trim() -cne
                    $expectedScannerBoundaryDiagnostic) {
                Add-Failure "Expected flags-only index drift to fail through a healthy boundary. Output: $($flagsMutationResult.Output.Trim())"
            }
            if (-not (Test-Path -LiteralPath $flagsMutationCounter) -or
                (Get-Content -LiteralPath $flagsMutationCounter -Raw).Trim() -cne
                    '3') {
                Add-Failure 'Expected exactly three raw debug listings in the flags-only mutation fixture.'
            }
            if (-not (Test-Path -LiteralPath $flagsMutationSentinel)) {
                Add-Failure 'Expected the real flags-only mutation after content revalidation and before final metadata verification.'
            }

            $flagsStageAfter = Invoke-HermeticGit `
                -WorkingDirectory $flagsMutationRoot `
                -Arguments $flagsStageArguments `
                -IsolationRoot $flagsMutationIsolationRoot
            $flagsDebugAfter = Invoke-HermeticGit `
                -WorkingDirectory $flagsMutationRoot `
                -Arguments $flagsDebugArguments `
                -IsolationRoot $flagsMutationIsolationRoot
            if ($flagsStageAfter.ExitCode -ne 0 -or
                $flagsStageAfter.Output -cne $flagsStageBefore.Output) {
                Add-Failure 'Expected flags-only mutation to preserve exact stage listing bytes.'
            }
            if ($flagsDebugAfter.ExitCode -ne 0 -or
                $flagsDebugAfter.Output -ceq $flagsDebugBefore.Output -or
                $flagsDebugAfter.Output -notmatch 'flags: 2000[0-9a-fA-F]{4}') {
                Add-Failure 'Expected flags-only mutation to change only the raw debug metadata snapshot.'
            }
        }
    }

    $trackedMarker = ('g' + 'hp_') + 'synthetic_tracked_placeholder'
    $untrackedMarker = ('xo' + 'xb-') + 'synthetic_untracked_placeholder'
    $trackedDirectory = Join-Path $trackedRoot 'nested'
    New-Item -ItemType Directory -Path $trackedDirectory | Out-Null
    $trackedLeakPath = Join-Path $trackedDirectory 'leak.md'
    Set-Content -LiteralPath $trackedLeakPath -Value "synthetic marker: $trackedMarker" -Encoding UTF8
    $trackedMarkerBytes = [System.IO.File]::ReadAllBytes($trackedLeakPath)
    Set-Content -LiteralPath (Join-Path $trackedRoot 'untracked.md') -Value "synthetic marker: $untrackedMarker" -Encoding UTF8
    $targetAdd = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('add', 'nested/leak.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($targetAdd.ExitCode -ne 0 -or $targetAdd.TimedOut -or -not $targetAdd.TreeStopped) {
        Add-Failure "Expected bounded target git add to succeed. Output: $($targetAdd.Output.Trim())"
    }
    # index にだけ marker を残し、clean な worktree で上書きして staged blob 検査を証明する。
    Set-Content `
        -LiteralPath (Join-Path $trackedDirectory 'leak.md') `
        -Value 'synthetic clean worktree content' `
        -Encoding UTF8

    $decoyInit = Invoke-HermeticGit `
        -WorkingDirectory $decoyRoot `
        -Arguments @('init', '--quiet') `
        -IsolationRoot $fixtureIsolationRoot
    if ($decoyInit.ExitCode -ne 0 -or $decoyInit.TimedOut -or -not $decoyInit.TreeStopped) {
        Add-Failure "Expected bounded decoy git init to succeed. Output: $($decoyInit.Output.Trim())"
    }

    $ambientHooks = Join-Path $ambientRoot 'hooks'
    $ambientTemplate = Join-Path $ambientRoot 'template'
    $ambientObjects = Join-Path $decoyRoot (Join-Path '.git' 'objects')
    foreach ($directory in @($ambientHooks, $ambientTemplate)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    $traceSentinel = Join-Path $ambientRoot 'git-trace.log'
    $trace2Sentinel = Join-Path $ambientRoot 'git-trace2.json'
    $hookSentinel = Join-Path $ambientRoot 'hook-fired.txt'
    $filterSentinel = Join-Path $ambientRoot 'filter-fired.txt'
    $ambientAttributes = Join-Path $ambientRoot 'attributes'
    $ambientExcludes = Join-Path $ambientRoot 'excludes'
    $ambientConfig = Join-Path $ambientRoot 'hostile.gitconfig'
    [System.IO.File]::WriteAllText($ambientAttributes, "*.md filter=synthetic`n", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($ambientExcludes, "nested/leak.md`n", [System.Text.UTF8Encoding]::new($false))
    $hookScript = @"
#!/bin/sh
printf '%s\n' 'hook-fired' > '$($hookSentinel.Replace([string][char]92, '/'))'
"@
    [System.IO.File]::WriteAllText(
        (Join-Path $ambientHooks 'post-index-change'),
        $hookScript,
        [System.Text.UTF8Encoding]::new($false)
    )
    $hostileConfigContent = @"
[core]
    hooksPath = $($ambientHooks.Replace([string][char]92, '/'))
    attributesFile = $($ambientAttributes.Replace([string][char]92, '/'))
    excludesFile = $($ambientExcludes.Replace([string][char]92, '/'))
[init]
    templateDir = $($ambientTemplate.Replace([string][char]92, '/'))
[filter "synthetic"]
    clean = sh -c "printf filter-fired > '$($filterSentinel.Replace([string][char]92, '/'))'; cat"
    required = true
"@
    [System.IO.File]::WriteAllText($ambientConfig, $hostileConfigContent, [System.Text.UTF8Encoding]::new($false))

    $decoyGitDirectory = Join-Path $decoyRoot '.git'
    $decoyIndex = Join-Path $decoyGitDirectory 'index'
    $adversarialEnvironment = @{
        GIT_DIR = $decoyGitDirectory
        GIT_WORK_TREE = $decoyRoot
        GIT_INDEX_FILE = $decoyIndex
        GIT_OBJECT_DIRECTORY = $ambientObjects
        GIT_ALTERNATE_OBJECT_DIRECTORIES = $ambientObjects
        GIT_CONFIG_GLOBAL = $ambientConfig
        GIT_CONFIG_SYSTEM = $ambientConfig
        GIT_CONFIG_NOSYSTEM = '0'
        GIT_CONFIG_COUNT = '2'
        GIT_CONFIG_KEY_0 = 'core.worktree'
        GIT_CONFIG_VALUE_0 = $decoyRoot
        GIT_CONFIG_KEY_1 = 'core.hooksPath'
        GIT_CONFIG_VALUE_1 = $ambientHooks
        GIT_TRACE = $traceSentinel
        GIT_TRACE2_EVENT = $trace2Sentinel
        GIT_TERMINAL_PROMPT = '1'
        GIT_NO_LAZY_FETCH = '0'
        GIT_NO_REPLACE_OBJECTS = '0'
        GIT_HYGIENE_PRESENT_EMPTY = ''
        HOME = $ambientRoot
        USERPROFILE = $ambientRoot
        XDG_CONFIG_HOME = $ambientRoot
    }

    $repositoryWithoutGitResult = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides @{ PATH = $emptyCommandPath }
    if ($repositoryWithoutGitResult.ExitCode -ne 2 -or
        $repositoryWithoutGitResult.Output.Trim() -cne
            $expectedGitMetadataDiagnostic) {
        Add-Failure "Expected a real .git marker to block no-Git fallback. Output: $($repositoryWithoutGitResult.Output.Trim())"
    }

    $beforeAdversarialScan = Get-ProcessEnvironmentSnapshot
    $adversarialFailure = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides $adversarialEnvironment
    Assert-ProcessEnvironmentUnchanged `
        -Expected $beforeAdversarialScan `
        -Context 'Adversarial failing scanner child'
    if (-not $adversarialEnvironment.ContainsKey('GIT_HYGIENE_PRESENT_EMPTY') -or
        $adversarialEnvironment['GIT_HYGIENE_PRESENT_EMPTY'] -cne '') {
        Add-Failure 'Expected the controlled present-empty Git variable to remain present-empty.'
    }
    if ($adversarialFailure.TimedOut -or -not $adversarialFailure.TreeStopped) {
        Add-Failure "Expected adversarial failing scanner child to finish within bounds. Output: $($adversarialFailure.Output.Trim())"
    }
    if ($adversarialFailure.ExitCode -eq 0) {
        Add-Failure 'Expected hostile Git variables not to empty or redirect the tracked-file scan.'
    }
    if ($adversarialFailure.Output -notmatch 'git-tracked') {
        Add-Failure "Expected adversarial fixture to retain git-tracked mode. Output: $($adversarialFailure.Output.Trim())"
    }
    if ($adversarialFailure.Output -notmatch 'nested/leak\.md') {
        Add-Failure "Expected adversarial fixture to report the target repository marker. Output: $($adversarialFailure.Output.Trim())"
    }
    if ($adversarialFailure.Output -notmatch '\bindex\b') {
        Add-Failure "Expected staged-only marker output to identify the index source. Output: $($adversarialFailure.Output.Trim())"
    }
    if ($adversarialFailure.Output -match 'untracked\.md') {
        Add-Failure 'Expected git-tracked mode not to scan an untracked marker.'
    }
    if ($adversarialFailure.Output.Contains($trackedMarker) -or
        $adversarialFailure.Output.Contains($untrackedMarker)) {
        Add-Failure 'Expected adversarial findings to stay redacted.'
    }

    # refs/replace が staged blob を clean blob へ差し替えても、index の実体を検査する。
    $markerOidResult = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('rev-parse', ':nested/leak.md') `
        -IsolationRoot $fixtureIsolationRoot
    $cleanOidResult = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('hash-object', '-w', '--', 'nested/leak.md') `
        -IsolationRoot $fixtureIsolationRoot
    $markerOid = $markerOidResult.Output.Trim()
    $cleanOid = $cleanOidResult.Output.Trim()
    if ($markerOidResult.ExitCode -ne 0 -or
        $cleanOidResult.ExitCode -ne 0 -or
        $markerOid -notmatch '^[0-9a-f]{40,64}$' -or
        $cleanOid -notmatch '^[0-9a-f]{40,64}$') {
        Add-Failure 'Expected replace-ref fixture object setup to succeed.'
    } else {
        $replaceAdd = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments @('replace', $markerOid, $cleanOid) `
            -IsolationRoot $fixtureIsolationRoot
        if ($replaceAdd.ExitCode -ne 0) {
            Add-Failure "Expected replace-ref fixture setup to succeed. Output: $($replaceAdd.Output.Trim())"
        } else {
            $replaceResult = Invoke-Scanner `
                -ScanPath $trackedRoot `
                -EnvironmentOverrides $adversarialEnvironment
            if ($replaceResult.ExitCode -eq 0 -or
                $replaceResult.Output -notmatch 'nested/leak\.md' -or
                $replaceResult.Output -notmatch '\bindex\b') {
                Add-Failure "Expected replace refs not to hide the staged marker. Output: $($replaceResult.Output.Trim())"
            }
            if ($replaceResult.Output.Contains($trackedMarker)) {
                Add-Failure 'Expected replace-ref finding to keep the staged marker redacted.'
            }
            $replaceDelete = Invoke-HermeticGit `
                -WorkingDirectory $trackedRoot `
                -Arguments @('replace', '-d', $markerOid) `
                -IsolationRoot $fixtureIsolationRoot
            if ($replaceDelete.ExitCode -ne 0) {
                Add-Failure "Expected replace-ref fixture cleanup to succeed. Output: $($replaceDelete.Output.Trim())"
            }
        }
    }

    # Partial clone の不足 blob は remote から補完せず、local-only 境界で即座に拒否する。
    if ($markerOid -match '^[0-9a-f]{40,64}$') {
        $promisorRemoteRoot = Join-Path $tempRoot 'promisor remote'
        $promisorRemoteDirectory = Join-Path $promisorRemoteRoot 'nested'
        New-Item -ItemType Directory -Path $promisorRemoteDirectory | Out-Null
        $promisorInit = Invoke-HermeticGit `
            -WorkingDirectory $promisorRemoteRoot `
            -Arguments @('init', '--quiet') `
            -IsolationRoot $fixtureIsolationRoot
        [System.IO.File]::WriteAllBytes(
            (Join-Path $promisorRemoteDirectory 'leak.md'),
            $trackedMarkerBytes
        )
        $promisorAdd = Invoke-HermeticGit `
            -WorkingDirectory $promisorRemoteRoot `
            -Arguments @('add', '--', 'nested/leak.md') `
            -IsolationRoot $fixtureIsolationRoot
        $fixtureEmail = 'synthetic' + '@example.invalid'
        $promisorCommit = Invoke-HermeticGit `
            -WorkingDirectory $promisorRemoteRoot `
            -Arguments @(
                '-c',
                'user.name=Synthetic Fixture',
                '-c',
                "user.email=$fixtureEmail",
                '-c',
                'commit.gpgSign=false',
                'commit',
                '--quiet',
                '-m',
                'synthetic promisor source'
            ) `
            -IsolationRoot $fixtureIsolationRoot
        $promisorOidResult = Invoke-HermeticGit `
            -WorkingDirectory $promisorRemoteRoot `
            -Arguments @('rev-parse', ':nested/leak.md') `
            -IsolationRoot $fixtureIsolationRoot
        if ($promisorInit.ExitCode -ne 0 -or
            $promisorAdd.ExitCode -ne 0 -or
            $promisorCommit.ExitCode -ne 0 -or
            $promisorOidResult.Output.Trim() -cne $markerOid) {
            Add-Failure 'Expected synthetic promisor remote setup to preserve the staged blob OID.'
        } else {
            $partialCloneConfigResults = @(
                Invoke-HermeticGit `
                    -WorkingDirectory $trackedRoot `
                    -Arguments @('config', 'extensions.partialClone', 'origin') `
                    -IsolationRoot $fixtureIsolationRoot
                Invoke-HermeticGit `
                    -WorkingDirectory $trackedRoot `
                    -Arguments @('config', 'remote.origin.promisor', 'true') `
                    -IsolationRoot $fixtureIsolationRoot
                Invoke-HermeticGit `
                    -WorkingDirectory $trackedRoot `
                    -Arguments @('config', 'remote.origin.partialclonefilter', 'blob:none') `
                    -IsolationRoot $fixtureIsolationRoot
                Invoke-HermeticGit `
                    -WorkingDirectory $trackedRoot `
                    -Arguments @('config', 'remote.origin.url', $promisorRemoteRoot) `
                    -IsolationRoot $fixtureIsolationRoot
            )
            if ($partialCloneConfigResults | Where-Object { $_.ExitCode -ne 0 }) {
                Add-Failure 'Expected synthetic partial-clone configuration to succeed.'
            } else {
                $objectRelativePath = Join-Path `
                    $markerOid.Substring(0, 2) `
                    $markerOid.Substring(2)
                $localMarkerObject = Join-Path `
                    (Join-Path (Join-Path $trackedRoot '.git') 'objects') `
                    $objectRelativePath
                if (-not [System.IO.File]::Exists($localMarkerObject)) {
                    Add-Failure 'Expected the staged marker fixture to use a removable loose object.'
                } else {
                    $localMarkerObjectBytes = [System.IO.File]::ReadAllBytes($localMarkerObject)
                    try {
                        # Git for Windows は loose object を read-only にする場合があるため、
                        # synthetic fixture の退避前だけ通常属性へ戻す。
                        [System.IO.File]::SetAttributes(
                            $localMarkerObject,
                            [System.IO.FileAttributes]::Normal
                        )
                        [System.IO.File]::Delete($localMarkerObject)
                        $partialCloneResult = Invoke-Scanner `
                            -ScanPath $trackedRoot `
                            -EnvironmentOverrides $adversarialEnvironment
                        if ($partialCloneResult.ExitCode -eq 0) {
                            Add-Failure 'Expected a missing promisor blob to fail closed without lazy fetch.'
                        }
                        if ($partialCloneResult.Output.Contains($trackedMarker)) {
                            Add-Failure 'Expected missing-promisor diagnostics not to expose marker content.'
                        }
                        $postScanMissingCheck = Invoke-HermeticGit `
                            -WorkingDirectory $trackedRoot `
                            -Arguments @('cat-file', '-e', "$markerOid`^{blob}") `
                            -IsolationRoot $fixtureIsolationRoot
                        if ($postScanMissingCheck.ExitCode -eq 0) {
                            Add-Failure 'Expected the scanner not to fetch the missing promisor blob.'
                        }
                    }
                    finally {
                        # 回帰で同一 OID が再取得済みなら上書きせず、未取得時だけ退避 bytes を戻す。
                        if (-not [System.IO.File]::Exists($localMarkerObject)) {
                            [System.IO.File]::WriteAllBytes(
                                $localMarkerObject,
                                $localMarkerObjectBytes
                            )
                        }
                    }
                }
            }
            foreach ($configKey in @(
                'extensions.partialClone',
                'remote.origin.promisor',
                'remote.origin.partialclonefilter',
                'remote.origin.url'
            )) {
                $configCleanup = Invoke-HermeticGit `
                    -WorkingDirectory $trackedRoot `
                    -Arguments @('config', '--unset-all', $configKey) `
                    -IsolationRoot $fixtureIsolationRoot
                if ($configCleanup.ExitCode -ne 0) {
                    Add-Failure "Expected partial-clone fixture cleanup to remove $configKey."
                }
            }
        }
    }

    # 同じ敵対環境で成功経路も通し、失敗時だけの cleanup 漏れを見逃さない。
    Set-Content -LiteralPath (Join-Path $trackedDirectory 'leak.md') -Value 'synthetic clean tracked content' -Encoding UTF8
    $targetRestage = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('add', 'nested/leak.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($targetRestage.ExitCode -ne 0 -or $targetRestage.TimedOut -or -not $targetRestage.TreeStopped) {
        Add-Failure "Expected bounded target git restage to succeed. Output: $($targetRestage.Output.Trim())"
    }

    $beforeAdversarialSuccess = Get-ProcessEnvironmentSnapshot
    $adversarialSuccess = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides $adversarialEnvironment
    Assert-ProcessEnvironmentUnchanged `
        -Expected $beforeAdversarialSuccess `
        -Context 'Adversarial successful scanner child'
    if ($adversarialSuccess.ExitCode -ne 0 -or
        $adversarialSuccess.TimedOut -or
        -not $adversarialSuccess.TreeStopped -or
        $adversarialSuccess.Output -notmatch 'git-tracked') {
        Add-Failure "Expected hostile Git variables not to break a clean tracked scan. Output: $($adversarialSuccess.Output.Trim())"
    }

    # Secretを含みやすい名前と拡張子を、index-only / worktree-only の
    # 両方向でまとめて固定する。各path/sourceを確認してmatrixの取りこぼしを防ぐ。
    $textCandidateCases = @(
        @{ Path = '.env';            Marker = ('g' + 'hp_') + 'synthetic_env_root' }
        @{ Path = '.env.local';      Marker = ('g' + 'hp_') + 'synthetic_env_variant' }
        @{ Path = 'production.env';  Marker = ('g' + 'hp_') + 'synthetic_env_suffix' }
        @{ Path = 'certificate.pem'; Marker = ('g' + 'hp_') + 'synthetic_pem' }
        @{ Path = 'private.key';     Marker = ('g' + 'hp_') + 'synthetic_key' }
        @{ Path = 'LICENSE';         Marker = ('g' + 'hp_') + 'synthetic_extensionless' }
        @{ Path = '.npmrc';          Marker = ('g' + 'hp_') + 'synthetic_dotfile' }
    )
    foreach ($case in $textCandidateCases) {
        Set-Content `
            -LiteralPath (Join-Path $trackedRoot $case.Path) `
            -Value "synthetic marker: $($case.Marker)" `
            -Encoding UTF8
    }
    $candidatePaths = @($textCandidateCases.Path)
    $candidateIndexAdd = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments (@('add', '--') + $candidatePaths) `
        -IsolationRoot $fixtureIsolationRoot
    if ($candidateIndexAdd.ExitCode -ne 0) {
        Add-Failure "Expected text-candidate index fixture setup to succeed. Output: $($candidateIndexAdd.Output.Trim())"
    }
    foreach ($case in $textCandidateCases) {
        Set-Content `
            -LiteralPath (Join-Path $trackedRoot $case.Path) `
            -Value "synthetic clean worktree content: $($case.Path)" `
            -Encoding UTF8
    }
    $candidateIndexResult = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides $adversarialEnvironment
    if ($candidateIndexResult.ExitCode -eq 0) {
        Add-Failure 'Expected index-only text-candidate markers to fail the scan.'
    }
    foreach ($case in $textCandidateCases) {
        $escapedPath = [regex]::Escape($case.Path)
        if ($candidateIndexResult.Output -notmatch "(?m)^\s*$escapedPath\s+index\s+") {
            Add-Failure "Expected index-only text candidate $($case.Path) to be reported from index. Output: $($candidateIndexResult.Output.Trim())"
        }
        if ($candidateIndexResult.Output.Contains($case.Marker)) {
            Add-Failure "Expected index-only text candidate $($case.Path) to stay redacted."
        }
    }

    $candidateCleanAdd = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments (@('add', '--') + $candidatePaths) `
        -IsolationRoot $fixtureIsolationRoot
    if ($candidateCleanAdd.ExitCode -ne 0) {
        Add-Failure "Expected clean text-candidate baseline to be staged. Output: $($candidateCleanAdd.Output.Trim())"
    }
    foreach ($case in $textCandidateCases) {
        Set-Content `
            -LiteralPath (Join-Path $trackedRoot $case.Path) `
            -Value "synthetic marker: $($case.Marker)" `
            -Encoding UTF8
    }
    $candidateWorktreeResult = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides $adversarialEnvironment
    if ($candidateWorktreeResult.ExitCode -eq 0) {
        Add-Failure 'Expected worktree-only text-candidate markers to fail the scan.'
    }
    foreach ($case in $textCandidateCases) {
        $escapedPath = [regex]::Escape($case.Path)
        if ($candidateWorktreeResult.Output -notmatch "(?m)^\s*$escapedPath\s+working-tree\s+") {
            Add-Failure "Expected worktree-only text candidate $($case.Path) to be reported from working-tree. Output: $($candidateWorktreeResult.Output.Trim())"
        }
        if ($candidateWorktreeResult.Output.Contains($case.Marker)) {
            Add-Failure "Expected worktree-only text candidate $($case.Path) to stay redacted."
        }
        Set-Content `
            -LiteralPath (Join-Path $trackedRoot $case.Path) `
            -Value "synthetic clean worktree content: $($case.Path)" `
            -Encoding UTF8
    }
    $candidateCleanup = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments (@('add', '--') + $candidatePaths) `
        -IsolationRoot $fixtureIsolationRoot
    if ($candidateCleanup.ExitCode -ne 0) {
        Add-Failure "Expected text-candidate fixture cleanup to succeed. Output: $($candidateCleanup.Output.Trim())"
    }

    $worktreeOnlyMarker = ('xo' + 'xb-') + 'synthetic_worktree_only'
    Set-Content `
        -LiteralPath (Join-Path $trackedDirectory 'leak.md') `
        -Value "synthetic marker: $worktreeOnlyMarker" `
        -Encoding UTF8
    $worktreeOnlyResult = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides $adversarialEnvironment
    if ($worktreeOnlyResult.ExitCode -eq 0 -or
        $worktreeOnlyResult.Output -notmatch '\bworking-tree\b' -or
        $worktreeOnlyResult.Output -notmatch 'nested/leak\.md') {
        Add-Failure "Expected worktree-only marker to be scanned beside the clean index blob. Output: $($worktreeOnlyResult.Output.Trim())"
    }
    if ($worktreeOnlyResult.Output.Contains($worktreeOnlyMarker)) {
        Add-Failure 'Expected the worktree-only marker to stay redacted.'
    }
    Set-Content `
        -LiteralPath (Join-Path $trackedDirectory 'leak.md') `
        -Value 'synthetic clean tracked content' `
        -Encoding UTF8

    $subdirectoryResult = Invoke-Scanner `
        -ScanPath $trackedDirectory `
        -EnvironmentOverrides $adversarialEnvironment
    if (-not (Test-FixedScannerBoundaryFailure $subdirectoryResult)) {
        Add-Failure "Expected a Git subdirectory scan to fail closed instead of falling back. Output: $($subdirectoryResult.Output.Trim())"
    }

    # worktree から消えた tracked file も index blob から検査し、silent skip を防ぐ。
    $missingMarker = ('g' + 'hp_') + 'synthetic_missing_worktree'
    $missingPath = Join-Path $trackedRoot 'missing.md'
    Set-Content -LiteralPath $missingPath -Value "synthetic marker: $missingMarker" -Encoding UTF8
    $missingAdd = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('add', '--', 'missing.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($missingAdd.ExitCode -ne 0) {
        Add-Failure "Expected missing-worktree fixture add to succeed. Output: $($missingAdd.Output.Trim())"
    }
    [System.IO.File]::Delete($missingPath)
    $missingResult = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides $adversarialEnvironment
    if ($missingResult.ExitCode -eq 0 -or
        $missingResult.Output -notmatch 'missing\.md' -or
        $missingResult.Output -notmatch '\bindex\b') {
        Add-Failure "Expected an index-only missing-worktree marker to fail the scan. Output: $($missingResult.Output.Trim())"
    }
    if ($missingResult.Output.Contains($missingMarker)) {
        Add-Failure 'Expected the missing-worktree index marker to stay redacted.'
    }
    $missingRemove = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('update-index', '--force-remove', '--', 'missing.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($missingRemove.ExitCode -ne 0) {
        Add-Failure "Expected missing-worktree fixture cleanup to succeed. Output: $($missingRemove.Output.Trim())"
    }

    # local marker file は untracked 専用であり、index に現れた時点で内容を公開対象にしない。
    $trackedLocalMarkerPath = Join-Path $trackedRoot '.private-markers.local'
    $trackedLocalMarker = 'synthetic-tracked-local-marker'
    Set-Content `
        -LiteralPath $trackedLocalMarkerPath `
        -Value $trackedLocalMarker `
        -Encoding UTF8
    $trackedLocalAdd = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('add', '-f', '--', '.private-markers.local') `
        -IsolationRoot $fixtureIsolationRoot
    if ($trackedLocalAdd.ExitCode -ne 0) {
        Add-Failure "Expected tracked local-marker fixture setup to succeed. Output: $($trackedLocalAdd.Output.Trim())"
    } else {
        $trackedLocalResult = Invoke-Scanner `
            -ScanPath $trackedRoot `
            -EnvironmentOverrides $adversarialEnvironment
        if (-not (Test-FixedScannerBoundaryFailure `
            $trackedLocalResult)) {
            Add-Failure "Expected a tracked .private-markers.local file to fail closed. Output: $($trackedLocalResult.Output.Trim())"
        }
        if ($trackedLocalResult.Output.Contains($trackedLocalMarker)) {
            Add-Failure 'Expected tracked local-marker diagnostics not to expose marker content.'
        }
    }
    $trackedLocalRemove = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('update-index', '--force-remove', '--', '.private-markers.local') `
        -IsolationRoot $fixtureIsolationRoot
    if ($trackedLocalRemove.ExitCode -ne 0) {
        Add-Failure "Expected tracked local-marker fixture cleanup to succeed. Output: $($trackedLocalRemove.Output.Trim())"
    }
    [System.IO.File]::Delete($trackedLocalMarkerPath)

    # `ls-files --stage` では normal empty blob と同じOIDに見えるため、
    # CE_INTENT_TO_ADD flagを直接検査して present/missing worktree の双方を拒否する。
    $intentPath = Join-Path $trackedRoot 'intent.md'
    Set-Content -LiteralPath $intentPath -Value 'synthetic intent-to-add content' -Encoding UTF8
    $intentAdd = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('add', '-N', '--', 'intent.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($intentAdd.ExitCode -ne 0) {
        Add-Failure "Expected intent-to-add fixture setup to succeed. Output: $($intentAdd.Output.Trim())"
    }
    $intentResult = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides $adversarialEnvironment
    if (-not (Test-FixedScannerBoundaryFailure $intentResult)) {
        Add-Failure "Expected present-worktree intent-to-add state to fail closed. Output: $($intentResult.Output.Trim())"
    }
    [System.IO.File]::Delete($intentPath)
    $missingIntentResult = Invoke-Scanner `
        -ScanPath $trackedRoot `
        -EnvironmentOverrides $adversarialEnvironment
    if (-not (Test-FixedScannerBoundaryFailure `
        $missingIntentResult)) {
        Add-Failure "Expected missing-worktree intent-to-add state to fail closed. Output: $($missingIntentResult.Output.Trim())"
    }
    $intentRemove = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('update-index', '--force-remove', '--', 'intent.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($intentRemove.ExitCode -ne 0) {
        Add-Failure "Expected intent-to-add fixture cleanup to succeed. Output: $($intentRemove.Output.Trim())"
    }

    # CE_INTENT_TO_ADDを持たない通常の staged empty blob は正当なtextとして通す。
    $ordinaryEmptyRoot = Join-Path $tempRoot 'ordinary-empty-target'
    $ordinaryEmptyIsolationRoot =
        Join-Path $tempRoot 'ordinary-empty-git-isolation'
    New-Item -ItemType Directory -Path $ordinaryEmptyRoot | Out-Null
    New-Item -ItemType Directory -Path $ordinaryEmptyIsolationRoot | Out-Null
    $ordinaryEmptyRelative = 'ordinary-empty.md'
    $ordinaryEmptyPath = Join-Path $ordinaryEmptyRoot $ordinaryEmptyRelative
    [System.IO.File]::WriteAllBytes($ordinaryEmptyPath, [byte[]]@())
    $ordinaryEmptyInit = Invoke-HermeticGit `
        -WorkingDirectory $ordinaryEmptyRoot `
        -Arguments @('init', '--quiet') `
        -IsolationRoot $ordinaryEmptyIsolationRoot
    $ordinaryEmptyAdd = Invoke-HermeticGit `
        -WorkingDirectory $ordinaryEmptyRoot `
        -Arguments @('add', '--', $ordinaryEmptyRelative) `
        -IsolationRoot $ordinaryEmptyIsolationRoot
    if ($ordinaryEmptyInit.ExitCode -ne 0 -or
        $ordinaryEmptyAdd.ExitCode -ne 0) {
        Add-Failure "Expected ordinary empty-file fixture setup to succeed. Output: $($ordinaryEmptyAdd.Output.Trim())"
    } else {
        $ordinaryEmptyResult = Invoke-Scanner `
            -ScanPath $ordinaryEmptyRoot `
            -EnvironmentOverrides $adversarialEnvironment
        if ($ordinaryEmptyResult.ExitCode -ne 0 -or
            $ordinaryEmptyResult.Output -match 'intent-to-add') {
            Add-Failure "Expected an ordinary staged empty blob to pass without intent-to-add classification. Output: $($ordinaryEmptyResult.Output.Trim())"
        }
    }

    # Index mode 120000 / 160000 は外部参照や別 repository へ進まず拒否する。
    $hashResult = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('hash-object', '-w', '--', 'nested/leak.md') `
        -IsolationRoot $fixtureIsolationRoot
    $fixtureOid = $hashResult.Output.Trim()
    if ($hashResult.ExitCode -ne 0 -or $fixtureOid -notmatch '^[0-9a-f]{40,64}$') {
        Add-Failure "Expected fixture blob hashing to succeed. Output: $($hashResult.Output.Trim())"
    } else {
        foreach ($modeCase in @(
            @{ Mode = '120000'; Path = 'synthetic-link.md'; Label = 'symlink' },
            @{ Mode = '160000'; Path = 'synthetic-gitlink'; Label = 'gitlink' }
        )) {
            $modeAdd = Invoke-HermeticGit `
                -WorkingDirectory $trackedRoot `
                -Arguments @(
                    'update-index',
                    '--add',
                    '--cacheinfo',
                    "$($modeCase.Mode),$fixtureOid,$($modeCase.Path)"
                ) `
                -IsolationRoot $fixtureIsolationRoot
            if ($modeAdd.ExitCode -ne 0) {
                Add-Failure "Expected $($modeCase.Label) index fixture setup to succeed. Output: $($modeAdd.Output.Trim())"
                continue
            }
            $modeResult = Invoke-Scanner `
                -ScanPath $trackedRoot `
                -EnvironmentOverrides $adversarialEnvironment
            if (-not (Test-FixedScannerBoundaryFailure $modeResult)) {
                Add-Failure "Expected $($modeCase.Label) index mode to fail closed. Output: $($modeResult.Output.Trim())"
            }
            $modeRemove = Invoke-HermeticGit `
                -WorkingDirectory $trackedRoot `
                -Arguments @('update-index', '--force-remove', '--', $modeCase.Path) `
                -IsolationRoot $fixtureIsolationRoot
            if ($modeRemove.ExitCode -ne 0) {
                Add-Failure "Expected $($modeCase.Label) fixture cleanup to succeed. Output: $($modeRemove.Output.Trim())"
            }
        }
    }

    # Regular index entryをplatform linkへ差し替え、外部targetをfollowしないことを確認する。
    $reparsePath = Join-Path $trackedRoot 'reparse.md'
    $reparseTarget = Join-Path $tempRoot 'reparse-external-target'
    New-Item -ItemType Directory -Path $reparseTarget | Out-Null
    Set-Content -LiteralPath (Join-Path $reparseTarget 'outside.md') -Value "synthetic marker: $trackedMarker" -Encoding UTF8
    Set-Content -LiteralPath $reparsePath -Value 'synthetic regular index content' -Encoding UTF8
    $reparseAdd = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('add', '--', 'reparse.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($reparseAdd.ExitCode -ne 0) {
        Add-Failure "Expected reparse fixture add to succeed. Output: $($reparseAdd.Output.Trim())"
    }
    [System.IO.File]::Delete($reparsePath)
    try {
        New-Item `
            -ItemType $directoryLinkItemType `
            -Path $reparsePath `
            -Target $reparseTarget |
            Out-Null
        $reparseResult = Invoke-Scanner `
            -ScanPath $trackedRoot `
            -EnvironmentOverrides $adversarialEnvironment
        if (-not (Test-FixedScannerBoundaryFailure $reparseResult)) {
            Add-Failure "Expected a tracked reparse path to fail closed without following it. Output: $($reparseResult.Output.Trim())"
        }
    }
    finally {
        if (Test-Path -LiteralPath $reparsePath) {
            (Get-Item -LiteralPath $reparsePath -Force).Delete()
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $reparseTarget 'outside.md'))) {
        Add-Failure 'Expected reparse cleanup not to alter the external synthetic target.'
    }
    $reparseRemove = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('update-index', '--force-remove', '--', 'reparse.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($reparseRemove.ExitCode -ne 0) {
        Add-Failure "Expected reparse fixture cleanup to succeed. Output: $($reparseRemove.Output.Trim())"
    }

    # leaf がregular fileでもparent platform linkなら外部directoryを辿るため拒否する。
    $parentReparseDirectory = Join-Path $trackedRoot 'parent-reparse'
    $parentReparsePath = Join-Path $parentReparseDirectory 'inside.md'
    $parentReparseTarget = Join-Path $tempRoot 'parent-reparse-external-target'
    New-Item -ItemType Directory -Path $parentReparseDirectory | Out-Null
    New-Item -ItemType Directory -Path $parentReparseTarget | Out-Null
    Set-Content `
        -LiteralPath $parentReparsePath `
        -Value 'synthetic regular parent-chain content' `
        -Encoding UTF8
    $parentReparseAdd = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('add', '--', 'parent-reparse/inside.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($parentReparseAdd.ExitCode -ne 0) {
        Add-Failure "Expected parent-reparse fixture add to succeed. Output: $($parentReparseAdd.Output.Trim())"
    }
    [System.IO.File]::Delete($parentReparsePath)
    [System.IO.Directory]::Delete($parentReparseDirectory)
    Set-Content `
        -LiteralPath (Join-Path $parentReparseTarget 'inside.md') `
        -Value 'synthetic external parent-chain content' `
        -Encoding UTF8
    try {
        New-Item `
            -ItemType $directoryLinkItemType `
            -Path $parentReparseDirectory `
            -Target $parentReparseTarget |
            Out-Null
        $parentReparseResult = Invoke-Scanner `
            -ScanPath $trackedRoot `
            -EnvironmentOverrides $adversarialEnvironment
        if (-not (Test-FixedScannerBoundaryFailure `
            $parentReparseResult)) {
            Add-Failure "Expected a tracked parent junction to fail closed without following it. Output: $($parentReparseResult.Output.Trim())"
        }
    }
    finally {
        if (Test-Path -LiteralPath $parentReparseDirectory) {
            (Get-Item -LiteralPath $parentReparseDirectory -Force).Delete()
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $parentReparseTarget 'inside.md'))) {
        Add-Failure 'Expected parent-junction cleanup not to alter the external synthetic target.'
    }
    $parentReparseRemove = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('update-index', '--force-remove', '--', 'parent-reparse/inside.md') `
        -IsolationRoot $fixtureIsolationRoot
    if ($parentReparseRemove.ExitCode -ne 0) {
        Add-Failure "Expected parent-reparse fixture cleanup to succeed. Output: $($parentReparseRemove.Output.Trim())"
    }

    if (-not (Test-PrivateMarkerWindowsHost)) {
        # Git pathは常にslash区切り。POSIXでだけ作れるliteral backslash名も
        # Windows path separatorへ再解釈し得る入力として一律拒否する。
        $backslashRelative = 'backslash\tracked.md'
        $backslashPath =
            [System.IO.Path]::Combine($trackedRoot, $backslashRelative)
        # PowerShell providerはPOSIX上でもbackslashをseparatorへ正規化するため、
        # 生の.NET APIでliteral backslash名を作り、Git境界そのものを検証する。
        [System.IO.File]::WriteAllText(
            $backslashPath,
            'synthetic backslash path',
            [System.Text.UTF8Encoding]::new($false)
        )
        $backslashAdd = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments @('add', '--', $backslashRelative) `
            -IsolationRoot $fixtureIsolationRoot
        if ($backslashAdd.ExitCode -ne 0) {
            Add-Failure "Expected POSIX backslash-name fixture add to succeed. Output: $($backslashAdd.Output.Trim())"
        } else {
            $backslashResult = Invoke-Scanner `
                -ScanPath $trackedRoot `
                -EnvironmentOverrides $adversarialEnvironment
            if (-not (Test-FixedScannerBoundaryFailure $backslashResult)) {
                Add-Failure "Expected a backslash Git path to fail closed. Output: $($backslashResult.Output.Trim())"
            }
        }
        $backslashRemove = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments @(
                'update-index',
                '--force-remove',
                '--',
                $backslashRelative
            ) `
            -IsolationRoot $fixtureIsolationRoot
        if ($backslashRemove.ExitCode -ne 0) {
            Add-Failure "Expected backslash-name fixture cleanup to succeed. Output: $($backslashRemove.Output.Trim())"
        }
        if ([System.IO.File]::Exists($backslashPath)) {
            [System.IO.File]::Delete($backslashPath)
        }
    }

    # Corrupt index は working-tree fallback に降格せず、Git present のまま拒否する。
    $targetIndexPath = Join-Path (Join-Path $trackedRoot '.git') 'index'
    $targetIndexBackup = [System.IO.File]::ReadAllBytes($targetIndexPath)
    try {
        [System.IO.File]::WriteAllBytes($targetIndexPath, [byte[]](1, 2, 3, 4))
        $malformedIndexResult = Invoke-Scanner `
            -ScanPath $trackedRoot `
            -EnvironmentOverrides $adversarialEnvironment
        if (-not (Test-FixedScannerBoundaryFailure `
            $malformedIndexResult)) {
            Add-Failure "Expected a malformed index to fail closed. Output: $($malformedIndexResult.Output.Trim())"
        }
    }
    finally {
        [System.IO.File]::WriteAllBytes($targetIndexPath, $targetIndexBackup)
    }

    # 実在する add/add conflict を作り、stage 1/2/3 のどれも blob scanへ進めない。
    $baseBranchResult = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments @('branch', '--show-current') `
        -IsolationRoot $fixtureIsolationRoot
    $baseBranch = $baseBranchResult.Output.Trim()
    $syntheticEmail = 'synthetic' + '@example.invalid'
    $identityArguments = @(
        '-c',
        'user.name=Synthetic Fixture',
        '-c',
        "user.email=$syntheticEmail",
        '-c',
        'commit.gpgSign=false'
    )
    $baseCommit = Invoke-HermeticGit `
        -WorkingDirectory $trackedRoot `
        -Arguments ($identityArguments + @('commit', '--quiet', '-m', 'synthetic base')) `
        -IsolationRoot $fixtureIsolationRoot
    if ($baseBranchResult.ExitCode -ne 0 -or
        [string]::IsNullOrWhiteSpace($baseBranch) -or
        $baseCommit.ExitCode -ne 0) {
        Add-Failure "Expected conflict fixture base commit to succeed. Output: $($baseCommit.Output.Trim())"
    } else {
        $sideSwitch = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments @('switch', '-c', 'synthetic-conflict-side') `
            -IsolationRoot $fixtureIsolationRoot
        $conflictPath = Join-Path $trackedRoot 'conflict.md'
        Set-Content -LiteralPath $conflictPath -Value 'synthetic side content' -Encoding UTF8
        $sideAdd = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments @('add', '--', 'conflict.md') `
            -IsolationRoot $fixtureIsolationRoot
        $sideCommit = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments ($identityArguments + @('commit', '--quiet', '-m', 'synthetic side')) `
            -IsolationRoot $fixtureIsolationRoot
        $baseSwitch = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments @('switch', $baseBranch) `
            -IsolationRoot $fixtureIsolationRoot
        Set-Content -LiteralPath $conflictPath -Value 'synthetic base content' -Encoding UTF8
        $baseAdd = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments @('add', '--', 'conflict.md') `
            -IsolationRoot $fixtureIsolationRoot
        $mainCommit = Invoke-HermeticGit `
            -WorkingDirectory $trackedRoot `
            -Arguments ($identityArguments + @('commit', '--quiet', '-m', 'synthetic main')) `
            -IsolationRoot $fixtureIsolationRoot
        if (@(
            $sideSwitch,
            $sideAdd,
            $sideCommit,
            $baseSwitch,
            $baseAdd,
            $mainCommit
        ) | Where-Object { $_.ExitCode -ne 0 }) {
            Add-Failure 'Expected conflict fixture branch setup to succeed.'
        } else {
            $mergeResult = Invoke-HermeticGit `
                -WorkingDirectory $trackedRoot `
                -Arguments ($identityArguments + @(
                    'merge',
                    '--no-edit',
                    'synthetic-conflict-side'
                )) `
                -IsolationRoot $fixtureIsolationRoot
            if ($mergeResult.ExitCode -eq 0 -or
                -not $mergeResult.StreamsCompleted -or
                -not $mergeResult.TreeStopped -or
                $mergeResult.Output -notmatch 'CONFLICT') {
                Add-Failure "Expected synthetic merge to produce a bounded conflict. Output: $($mergeResult.Output.Trim())"
            } else {
                $conflictResult = Invoke-Scanner `
                    -ScanPath $trackedRoot `
                    -EnvironmentOverrides $adversarialEnvironment
                if (-not (Test-FixedScannerBoundaryFailure `
                    $conflictResult)) {
                    Add-Failure "Expected unresolved index stages to fail closed. Output: $($conflictResult.Output.Trim())"
                }
            }
            if (Test-Path -LiteralPath (Join-Path (Join-Path $trackedRoot '.git') 'MERGE_HEAD')) {
                $mergeAbort = Invoke-HermeticGit `
                    -WorkingDirectory $trackedRoot `
                    -Arguments @('merge', '--abort') `
                    -IsolationRoot $fixtureIsolationRoot
                if ($mergeAbort.ExitCode -ne 0) {
                    Add-Failure "Expected conflict fixture cleanup to succeed. Output: $($mergeAbort.Output.Trim())"
                }
            }
        }
    }

    foreach ($sentinel in @($traceSentinel, $trace2Sentinel, $hookSentinel, $filterSentinel)) {
        if (Test-Path -LiteralPath $sentinel) {
            Add-Failure "Expected scanner Git children not to create ambient artifact: $(Split-Path -Leaf $sentinel)"
        }
    }

    # 別runがsystem tempへ同じprefixを作る状況を再現しつつ、このsuiteが所有する
    # namespaceだけを検査する。foreign rootはleakへ誤分類してはならない。
    $foreignScannerIsolationRoot = Join-Path `
        ([System.IO.Path]::GetTempPath()) `
        (
            'codex-windows-sandbox-troubleshooting-git-' +
            [System.Guid]::NewGuid().ToString('N')
        )
    New-Item `
        -ItemType Directory `
        -Path $foreignScannerIsolationRoot |
        Out-Null
    $remainingScannerIsolationRoots = @(
        Get-ChildItem -LiteralPath $scannerTempRoot `
            -Directory `
            -Filter 'codex-windows-sandbox-troubleshooting-git-*' `
            -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Name }
    )
    if ($remainingScannerIsolationRoots.Count -gt 0) {
        Add-Failure "Expected owned scanner isolation roots to be cleaned: $($remainingScannerIsolationRoots -join ', ')."
    }
}
finally {
    if ($null -ne $foreignScannerIsolationRoot -and
        (Test-Path -LiteralPath $foreignScannerIsolationRoot)) {
        Remove-Item `
            -LiteralPath $foreignScannerIsolationRoot `
            -Recurse `
            -Force
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

if ($RequireMacOSNativePosixContainment -and
    -not $macOSNativeContainmentVerified) {
    Add-Failure 'Expected Darwin forced-native POSIX containment and descendant cleanup evidence.'
}

if ($failures.Count -gt 0) {
    Write-Host 'Private marker scan self-test failed:'
    foreach ($failure in $failures) {
        Write-Host "- $failure"
    }
    exit 1
}

if ($RequireMacOSNativePosixContainment) {
    Write-Host (
        'POSIX containment evidence: platform=Darwin; auto-gate=' +
        $posixGateEvidence['auto'] +
        '; forced-gate=' +
        $posixGateEvidence['forced-native'] +
        '; nonzero-rejection=passed' +
        '; descendant-cleanup=passed.'
    )
}
Write-Host 'Private marker scan self-test passed.'
exit 0
