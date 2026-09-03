param(
    [switch]$SelfTest,
    [switch]$BuildOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$taskName = 'Bayshore-Codex-Session0-User-Probe'
$taskPath = '\'
$taskRoot = 'C:\ProgramData\BayshoreLabs\CodexSession0UserProbe'
$runCmd = Join-Path $taskRoot 'run.cmd'
$originalRunCmd = Join-Path $taskRoot 'run.cmd.codex-acceptance-original.bak'
$acceptanceScript = Join-Path $taskRoot 'acceptance.ps1'
$acceptanceCmd = Join-Path $taskRoot 'acceptance-run.cmd'
$acceptanceRequestPath = Join-Path $taskRoot 'acceptance-request.json'
$workspaceAcceptanceScript = Join-Path $PSScriptRoot '.codex-session0-acceptance.ps1'
$repositoryRoot = 'Y:\Bayshore Labs\Source\Codex'
$codexRsRoot = Join-Path $repositoryRoot 'codex-rs'
$cargoExe = 'C:\Users\bekelly\.cargo\bin\cargo.exe'
$cargoLockPath = Join-Path $codexRsRoot 'Cargo.lock'
$sourceCodex = Join-Path $codexRsRoot 'target\debug\codex.exe'
$sourceCommandRunner = Join-Path $codexRsRoot 'target\debug\codex-command-runner.exe'
$sourceSetupHelper = Join-Path $codexRsRoot 'target\debug\codex-windows-sandbox-setup.exe'
$controllerSummaryPath = Join-Path $taskRoot 'acceptance-controller-summary.json'
$expectedOriginalRunCmdHash = '483CF222D9881F85D35E7141999BF72D3B3C85B98569D2133EE93910241769EF'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$serialResults = [System.Collections.Generic.List[object]]::new()
$concurrencyResult = $null
$controllerFailure = $null
$restorationFailures = [System.Collections.Generic.List[string]]::new()
$candidate = $null
$startedAt = [DateTimeOffset]::UtcNow

function Write-AtomicJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $temporaryPath = '{0}.tmp-{1}-{2}' -f $Path, $PID, [Guid]::NewGuid().ToString('N')
    [System.IO.File]::WriteAllText(
        $temporaryPath,
        ($Value | ConvertTo-Json -Depth 12),
        $script:utf8NoBom)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $backupPath = '{0}.replace-backup-{1}-{2}' -f `
            $Path, $PID, [Guid]::NewGuid().ToString('N')
        try {
            [System.IO.File]::Replace($temporaryPath, $Path, $backupPath)
        }
        finally {
            if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
                [System.IO.File]::Delete($backupPath)
            }
        }
    }
    else {
        [System.IO.File]::Move($temporaryPath, $Path)
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($stream)
        ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Get-FileFingerprint {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path
    [ordered]@{
        Path = $item.FullName
        Sha256 = Get-Sha256 -Path $item.FullName
        Size = [int64]$item.Length
        LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
    }
}

function Write-AcceptanceRequest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('serial', 'concurrency')][string]$Mode,
        [Parameter(Mandatory = $true)][string]$RequestId,
        [string]$Path = $script:acceptanceRequestPath
    )

    Write-AtomicJson -Path $Path -Value ([ordered]@{
        RequestId = $RequestId
        Mode = $Mode
        CreatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    })
}

function Restore-ExactFileBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $temporaryPath = '{0}.codex-acceptance-{1}-{2}.tmp' -f `
        $Path, $PID, [Guid]::NewGuid().ToString('N')
    [System.IO.File]::WriteAllBytes($temporaryPath, $Bytes)
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Assert-FileMatchesFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Expected
    )

    $actual = Get-FileFingerprint -Path $Path
    if ($actual.Sha256 -cne [string]$Expected.Sha256 -or
        [int64]$actual.Size -ne [int64]$Expected.Size) {
        throw "Binary fingerprint mismatch for $Path; actual SHA-256/size was $($actual.Sha256)/$($actual.Size), expected $($Expected.Sha256)/$($Expected.Size)."
    }
    $actual
}

function Import-Vs2022BuildToolsX64Environment {
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vsWhere -PathType Leaf)) {
        throw "vswhere.exe is missing: $vsWhere"
    }

    $installationPath = @(
        & $vsWhere -latest -products Microsoft.VisualStudio.Product.BuildTools `
            -version '[17.0,18.0)' -requires Microsoft.VisualStudio.Workload.VCTools `
            -property installationPath 2>$null
    ) | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($installationPath)) {
        throw 'vswhere could not locate a Visual Studio 2022 Build Tools instance with the VC Tools workload.'
    }
    $installationPath = $installationPath.Trim()
    $vsDevCmd = Join-Path $installationPath 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf)) {
        throw "VsDevCmd.bat is missing: $vsDevCmd"
    }

    # These two overrides must survive the developer-environment import as an exact
    # pair. The Codex Cargo build uses them for its pinned rusty_v8 archive/bindings.
    $rustyV8Archive = [Environment]::GetEnvironmentVariable('RUSTY_V8_ARCHIVE', 'Process')
    $rustyV8Binding = [Environment]::GetEnvironmentVariable(
        'RUSTY_V8_SRC_BINDING_PATH',
        'Process')
    if ([string]::IsNullOrWhiteSpace($rustyV8Archive) -xor
        [string]::IsNullOrWhiteSpace($rustyV8Binding)) {
        throw 'RUSTY_V8_ARCHIVE and RUSTY_V8_SRC_BINDING_PATH must both be set or both be unset.'
    }

    $environmentLines = & $env:ComSpec /c (
        '"{0}" -no_logo -arch=x64 -host_arch=x64 >nul && set' -f $vsDevCmd)
    if ($LASTEXITCODE -ne 0) {
        throw "VsDevCmd.bat failed with exit code $LASTEXITCODE."
    }
    foreach ($line in $environmentLines) {
        if ($line -notmatch '^([^=]+)=(.*)$') {
            continue
        }
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
    [Environment]::SetEnvironmentVariable('RUSTY_V8_ARCHIVE', $rustyV8Archive, 'Process')
    [Environment]::SetEnvironmentVariable(
        'RUSTY_V8_SRC_BINDING_PATH',
        $rustyV8Binding,
        'Process')

    # The invoking shell may globally force LLVM. Native dependencies for the
    # MSVC target must select the compiler from the imported VS environment.
    $compilerOverrides = @(
        'CC',
        'CXX',
        'HOST_CC',
        'HOST_CXX',
        'TARGET_CC',
        'TARGET_CXX',
        'CC_x86_64-pc-windows-msvc',
        'CXX_x86_64-pc-windows-msvc',
        'CC_x86_64_pc_windows_msvc',
        'CXX_x86_64_pc_windows_msvc',
        'CC_X86_64_PC_WINDOWS_MSVC',
        'CXX_X86_64_PC_WINDOWS_MSVC'
    )
    foreach ($name in $compilerOverrides) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }

    foreach ($name in @('VCINSTALLDIR', 'WindowsSdkDir', 'INCLUDE', 'LIB')) {
        if ([string]::IsNullOrWhiteSpace(
                [Environment]::GetEnvironmentVariable($name, 'Process'))) {
            throw "$name was not populated by VsDevCmd.bat."
        }
    }
    $vcToolsInstallDir = [Environment]::GetEnvironmentVariable(
        'VCToolsInstallDir',
        'Process')
    if ([string]::IsNullOrWhiteSpace($vcToolsInstallDir)) {
        throw 'VCToolsInstallDir was not populated by VsDevCmd.bat.'
    }
    $expectedToolDirectory = [System.IO.Path]::GetFullPath(
        (Join-Path $vcToolsInstallDir 'bin\Hostx64\x64')).TrimEnd('\')
    $cl = Get-Command cl.exe -CommandType Application -ErrorAction Stop
    $link = Get-Command link.exe -CommandType Application -ErrorAction Stop
    foreach ($tool in @($cl, $link)) {
        $actualToolDirectory = [System.IO.Path]::GetFullPath(
            (Split-Path -Parent $tool.Source)).TrimEnd('\')
        if ($actualToolDirectory -ine $expectedToolDirectory) {
            throw "$($tool.Name) resolved to $($tool.Source), expected the Build Tools Hostx64\x64 directory $expectedToolDirectory."
        }
    }
    $kernel32Lib = @(
        [Environment]::GetEnvironmentVariable('LIB', 'Process').Split(';') |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { Join-Path $_ 'kernel32.lib' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    ) | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($kernel32Lib)) {
        throw 'kernel32.lib was not found through the LIB environment populated by VsDevCmd.bat.'
    }
    foreach ($rustTool in @($cargoExe, (Join-Path (Split-Path -Parent $cargoExe) 'rustc.exe'))) {
        if (-not (Test-Path -LiteralPath $rustTool -PathType Leaf)) {
            throw "The existing Rust/Cargo toolchain is missing: $rustTool"
        }
    }

    [pscustomobject][ordered]@{
        VsWhere = $vsWhere
        InstallationPath = $installationPath
        VsDevCmd = $vsDevCmd
        VCINSTALLDIR = $env:VCINSTALLDIR
        WindowsSdkDir = $env:WindowsSdkDir
        WindowsSDKVersion = $env:WindowsSDKVersion
        INCLUDE = $env:INCLUDE
        LIB = $env:LIB
        Cl = $cl.Source
        Link = $link.Source
        Kernel32Lib = $kernel32Lib
        Cargo = $cargoExe
        Rustc = Join-Path (Split-Path -Parent $cargoExe) 'rustc.exe'
        CC = [Environment]::GetEnvironmentVariable('CC', 'Process')
        CXX = [Environment]::GetEnvironmentVariable('CXX', 'Process')
        RustyV8Archive = $rustyV8Archive
        RustyV8SrcBindingPath = $rustyV8Binding
    }
}

function Build-AcceptanceCandidate {
    if (-not (Test-Path -LiteralPath $cargoExe -PathType Leaf)) {
        throw "Cargo executable is missing: $cargoExe"
    }
    $buildEnvironment = Import-Vs2022BuildToolsX64Environment
    $buildArguments = @(
        'build',
        '-p', 'codex-cli', '--bin', 'codex',
        '-p', 'codex-windows-sandbox',
        '--bin', 'codex-command-runner',
        '--bin', 'codex-windows-sandbox-setup'
    )
    $cargoLockBytes = [System.IO.File]::ReadAllBytes($cargoLockPath)
    $cargoLockBefore = Get-FileFingerprint -Path $cargoLockPath
    $buildStartedAt = [DateTimeOffset]::UtcNow
    $buildStarted = $false
    $buildExitCode = $null
    try {
        Push-Location -LiteralPath $codexRsRoot
        try {
            $buildStarted = $true
            & $cargoExe @buildArguments
            $buildExitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
    }
    finally {
        Restore-ExactFileBytes -Path $cargoLockPath -Bytes $cargoLockBytes
    }
    $cargoLockAfter = Assert-FileMatchesFingerprint -Path $cargoLockPath `
        -Expected $cargoLockBefore
    if (-not $buildStarted) {
        throw 'Acceptance candidate build did not start.'
    }
    if ($buildExitCode -ne 0) {
        throw "Acceptance candidate build failed with exit code $buildExitCode."
    }
    $buildFinishedAt = [DateTimeOffset]::UtcNow

    $sourceCodexFingerprint = Get-FileFingerprint -Path $sourceCodex
    $sourceRunnerFingerprint = Get-FileFingerprint -Path $sourceCommandRunner
    $sourceSetupFingerprint = Get-FileFingerprint -Path $sourceSetupHelper
    $runtimeName = 'acceptance-runtime-{0}-{1}-{2}-{3}' -f `
        $buildFinishedAt.ToString('yyyyMMdd-HHmmss-fff'),
        $sourceCodexFingerprint.Sha256.Substring(0, 16),
        $sourceRunnerFingerprint.Sha256.Substring(0, 16),
        $sourceSetupFingerprint.Sha256.Substring(0, 16)
    $runtimeDirectory = Join-Path $taskRoot $runtimeName
    New-Item -ItemType Directory -Path $runtimeDirectory | Out-Null
    $runtimeCodex = Join-Path $runtimeDirectory 'codex.exe'
    $runtimeCommandRunner = Join-Path $runtimeDirectory 'codex-command-runner.exe'
    $runtimeSetupHelper = Join-Path $runtimeDirectory 'codex-windows-sandbox-setup.exe'
    Copy-Item -LiteralPath $sourceCodex -Destination $runtimeCodex
    Copy-Item -LiteralPath $sourceCommandRunner -Destination $runtimeCommandRunner
    Copy-Item -LiteralPath $sourceSetupHelper -Destination $runtimeSetupHelper
    $codexFingerprint = Assert-FileMatchesFingerprint -Path $runtimeCodex `
        -Expected $sourceCodexFingerprint
    $runnerFingerprint = Assert-FileMatchesFingerprint -Path $runtimeCommandRunner `
        -Expected $sourceRunnerFingerprint
    $setupFingerprint = Assert-FileMatchesFingerprint -Path $runtimeSetupHelper `
        -Expected $sourceSetupFingerprint
    $manifestName = 'acceptance-candidate-{0}-{1}-{2}-{3}.json' -f `
        $buildFinishedAt.ToString('yyyyMMdd-HHmmss-fff'),
        $codexFingerprint.Sha256.Substring(0, 16),
        $runnerFingerprint.Sha256.Substring(0, 16),
        $setupFingerprint.Sha256.Substring(0, 16)
    $candidateManifestPath = Join-Path $taskRoot $manifestName
    $manifest = [ordered]@{
        ManifestPath = $candidateManifestPath
        BuildStartedAt = $buildStartedAt.ToString('o')
        BuildFinishedAt = $buildFinishedAt.ToString('o')
        BuildCommand = "$cargoExe $($buildArguments -join ' ')"
        BuildEnvironment = $buildEnvironment
        CargoLockBefore = $cargoLockBefore
        CargoLockAfter = $cargoLockAfter
        CargoLockRestoredExactly = $true
        RuntimeLayout = 'candidate-local'
        RuntimeDirectory = $runtimeDirectory
        Codex = $codexFingerprint
        CommandRunner = $runnerFingerprint
        SetupHelper = $setupFingerprint
    }
    Write-AtomicJson -Path $candidateManifestPath -Value $manifest
    [pscustomobject]$manifest
}

function Get-RunDirectoryNames {
    @(
        Get-ChildItem -LiteralPath $taskRoot -Directory -Filter 'run-*' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name
    )
}

function Get-NewEvidenceNames {
    param(
        [AllowNull()][AllowEmptyCollection()][string[]]$BeforeNames = @(),
        [AllowNull()][AllowEmptyCollection()][string[]]$AfterNames = @()
    )

    $baseline = @($BeforeNames | Where-Object { $null -ne $_ })
    @($AfterNames | Where-Object { $null -ne $_ -and $_ -notin $baseline })
}

function Restore-FileFromBackup {
    param(
        [Parameter(Mandatory = $true)][string]$Backup,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$ExpectedHash
    )

    Copy-Item -LiteralPath $Backup -Destination $Destination -Force
    $restoredHash = Get-Sha256 -Path $Destination
    if ($restoredHash -cne $ExpectedHash) {
        throw "Restored file hash was $restoredHash, expected $ExpectedHash."
    }
}

function Read-RunSummary {
    param([Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$RunDirectory)

    $path = Join-Path $RunDirectory.FullName 'run-summary.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Run summary is missing: $path"
    }
    $length = (Get-Item -LiteralPath $path).Length
    if ($length -eq 0) {
        throw "Run summary is empty: $path"
    }
    try {
        Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Run summary is not valid JSON: $path`n$($_ | Out-String)"
    }
}

function Assert-RunSummary {
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)][ValidateSet('serial', 'concurrency')][string]$ExpectedMode,
        [Parameter(Mandatory = $true)][string]$ExpectedRequestId
    )

    if (-not $Summary.Success) {
        $failures = @(
            foreach ($command in $Summary.Commands) {
                foreach ($failure in $command.Failures) {
                    '{0}: {1}' -f $command.Name, $failure
                }
            }
        )
        throw "Acceptance run $($Summary.RunId) failed: $($failures -join '; ')"
    }
    if ([int]$Summary.SessionId -ne 0) {
        throw "Acceptance run $($Summary.RunId) used SessionId=$($Summary.SessionId), expected 0."
    }
    if ([string]$Summary.Identity -ine 'BAYSHORE\bekelly') {
        throw "Acceptance run $($Summary.RunId) used identity '$($Summary.Identity)', expected BAYSHORE\bekelly."
    }
    if ([string]$Summary.Mode -cne $ExpectedMode) {
        throw "Acceptance run $($Summary.RunId) used mode '$($Summary.Mode)', expected '$ExpectedMode'."
    }
    if ([string]$Summary.RequestId -cne $ExpectedRequestId) {
        throw "Acceptance run $($Summary.RunId) used request '$($Summary.RequestId)', expected '$ExpectedRequestId'."
    }
    $expectedNames = if ($ExpectedMode -ceq 'serial') {
        @('cmd', 'pwsh', 'git', 'user32')
    }
    else {
        @('concurrent-a', 'concurrent-b')
    }
    $actualNames = @($Summary.Commands | Select-Object -ExpandProperty Name)
    if (Compare-Object -ReferenceObject $expectedNames -DifferenceObject $actualNames) {
        throw "Acceptance run $($Summary.RunId) did not report the expected $ExpectedMode commands."
    }
    if ($ExpectedMode -ceq 'concurrency' -and -not $Summary.Concurrency.Proven) {
        throw "Acceptance run $($Summary.RunId) did not prove concurrent candidate execution."
    }
}

function Wait-NewRuns {
    param(
        [AllowNull()][AllowEmptyCollection()][string[]]$BeforeNames = @(),
        [Parameter(Mandatory = $true)][int]$ExpectedCount,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Deadline
    )

    $baselineNames = @($BeforeNames | Where-Object { $null -ne $_ })
    do {
        $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
        $candidateRuns = @(
            Get-ChildItem -LiteralPath $taskRoot -Directory -Filter 'run-*' |
                Sort-Object CreationTime
        )
        $newNames = @(Get-NewEvidenceNames -BeforeNames $baselineNames -AfterNames $candidateRuns.Name)
        $newRuns = @($candidateRuns | Where-Object { $_.Name -in $newNames })
        $completeRuns = @(
            $newRuns |
                Where-Object {
                    $summaryPath = Join-Path $_.FullName 'run-summary.json'
                    (Test-Path -LiteralPath $summaryPath -PathType Leaf) -and
                        (Get-Item -LiteralPath $summaryPath).Length -gt 0
                }
        )
        if ($completeRuns.Count -ge $ExpectedCount -and $task.State -ne 'Running') {
            return @($completeRuns | Select-Object -First $ExpectedCount)
        }
        Start-Sleep -Milliseconds 250
    }
    while ([DateTimeOffset]::Now -lt $Deadline)

    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath
    throw "Timed out waiting for $ExpectedCount completed acceptance run(s); task state=$($task.State), new runs=$($newRuns.Count), complete runs=$($completeRuns.Count), LastTaskResult=$($taskInfo.LastTaskResult)."
}

function Invoke-SerialAcceptanceRun {
    param([Parameter(Mandatory = $true)][int]$Iteration)

    $beforeNames = @(Get-RunDirectoryNames)
    $requestedAt = [DateTimeOffset]::UtcNow
    $requestId = 'serial-{0}-{1}' -f $Iteration, [Guid]::NewGuid().ToString('N')
    Write-AcceptanceRequest -Mode 'serial' -RequestId $requestId
    Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    $runDirectory = @(
        Wait-NewRuns -BeforeNames $beforeNames -ExpectedCount 1 `
            -Deadline ([DateTimeOffset]::Now.AddMinutes(3))
    )[0]
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath
    $summary = Read-RunSummary -RunDirectory $runDirectory
    Assert-RunSummary -Summary $summary -ExpectedMode 'serial' -ExpectedRequestId $requestId
    if ([int64]$taskInfo.LastTaskResult -ne 0) {
        throw "Serial iteration $Iteration completed with LastTaskResult=$($taskInfo.LastTaskResult)."
    }
    [pscustomobject]@{
        Iteration = $Iteration
        RequestedAt = $requestedAt.ToString('o')
        LastRunTime = $taskInfo.LastRunTime.ToString('o')
        LastTaskResult = [int64]$taskInfo.LastTaskResult
        RunDirectory = $runDirectory.FullName
        Summary = $summary
    }
}

function Invoke-ConcurrentAcceptanceRuns {
    $beforeNames = @(Get-RunDirectoryNames)
    $requestedAt = [DateTimeOffset]::UtcNow
    $requestId = 'concurrency-{0}' -f [Guid]::NewGuid().ToString('N')
    Write-AcceptanceRequest -Mode 'concurrency' -RequestId $requestId
    Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    $runDirectory = @(
        Wait-NewRuns -BeforeNames $beforeNames -ExpectedCount 1 `
            -Deadline ([DateTimeOffset]::Now.AddMinutes(4))
    )[0]
    $summary = Read-RunSummary -RunDirectory $runDirectory
    Assert-RunSummary -Summary $summary -ExpectedMode 'concurrency' `
        -ExpectedRequestId $requestId
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath
    if ([int64]$taskInfo.LastTaskResult -ne 0) {
        throw "Concurrent acceptance completed with LastTaskResult=$($taskInfo.LastTaskResult)."
    }
    [pscustomobject]@{
        Performed = $true
        RequestedAt = $requestedAt.ToString('o')
        LastRunTime = $taskInfo.LastRunTime.ToString('o')
        LastTaskResult = [int64]$taskInfo.LastTaskResult
        RunDirectory = $runDirectory.FullName
        Summary = $summary
        Success = $true
    }
}

function Invoke-ControllerSelfTest {
    $selfTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'codex-session0-controller-selftest-{0}' -f [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $selfTestRoot | Out-Null
    $passed = [System.Collections.Generic.List[string]]::new()
    try {
        $controllerSource = [System.IO.File]::ReadAllText($PSCommandPath)
        if ($controllerSource -match '(?m)\b(?:Set|Register|Unregister)-ScheduledTask\b') {
            throw 'Controller still contains a scheduled-task definition mutation.'
        }
        $passed.Add('no scheduled-task definition mutation')

        $buildEnvironment = Import-Vs2022BuildToolsX64Environment
        $passed.Add('Visual Studio 2022 Build Tools x64 environment and kernel32.lib')

        $newFromNull = @(Get-NewEvidenceNames -BeforeNames $null -AfterNames @('run-a'))
        if ($newFromNull.Count -ne 1 -or $newFromNull[0] -ne 'run-a') {
            throw 'Null baseline did not accept the first evidence name.'
        }
        $passed.Add('null/empty baseline collection')
        if (@(Get-NewEvidenceNames -BeforeNames $null -AfterNames $null).Count -ne 0) {
            throw 'Null post-run collection did not normalize to empty.'
        }
        $passed.Add('null/empty post-run collection')
        $newFromPopulated = @(
            Get-NewEvidenceNames -BeforeNames @('run-a') -AfterNames @('run-a', 'run-b', 'run-c')
        )
        if ($newFromPopulated.Count -ne 2 -or
            $newFromPopulated[0] -ne 'run-b' -or $newFromPopulated[1] -ne 'run-c') {
            throw 'Populated evidence collection did not return every new name.'
        }
        $passed.Add('one or more matching evidence names')

        $missingRun = New-Item -ItemType Directory -Path (Join-Path $selfTestRoot 'missing-run')
        try {
            Read-RunSummary -RunDirectory $missingRun | Out-Null
            throw 'Missing run summary was accepted.'
        }
        catch {
            if ($_ -notmatch 'Run summary is missing') {
                throw
            }
        }
        $emptyRun = New-Item -ItemType Directory -Path (Join-Path $selfTestRoot 'empty-run')
        [System.IO.File]::WriteAllBytes(
            (Join-Path $emptyRun.FullName 'run-summary.json'),
            [byte[]]@())
        try {
            Read-RunSummary -RunDirectory $emptyRun | Out-Null
            throw 'Empty run summary was accepted.'
        }
        catch {
            if ($_ -notmatch 'Run summary is empty') {
                throw
            }
        }
        $passed.Add('missing and empty result files')

        $commandNames = @('cmd', 'pwsh', 'git', 'user32')
        $successRun = New-Item -ItemType Directory -Path (Join-Path $selfTestRoot 'success-run')
        $successSummary = [ordered]@{
            RunId = 'synthetic-success'
            Mode = 'serial'
            RequestId = 'synthetic-serial'
            Identity = 'BAYSHORE\bekelly'
            SessionId = 0
            Commands = @(
                foreach ($name in $commandNames) {
                    [ordered]@{ Name = $name; Failures = @(); Success = $true }
                }
            )
            Success = $true
        }
        Write-AtomicJson -Path (Join-Path $successRun.FullName 'run-summary.json') `
            -Value $successSummary
        $parsedSuccess = Read-RunSummary -RunDirectory $successRun
        Assert-RunSummary -Summary $parsedSuccess -ExpectedMode 'serial' `
            -ExpectedRequestId 'synthetic-serial'

        $failureRun = New-Item -ItemType Directory -Path (Join-Path $selfTestRoot 'failure-run')
        $failureSummary = [ordered]@{
            RunId = 'synthetic-failure'
            Mode = 'serial'
            RequestId = 'synthetic-failure'
            Identity = 'BAYSHORE\bekelly'
            SessionId = 0
            Commands = @(
                [ordered]@{ Name = 'cmd'; Failures = @('synthetic failure'); Success = $false }
            )
            Success = $false
        }
        Write-AtomicJson -Path (Join-Path $failureRun.FullName 'run-summary.json') `
            -Value $failureSummary
        try {
            Assert-RunSummary -Summary (Read-RunSummary -RunDirectory $failureRun) `
                -ExpectedMode 'serial' -ExpectedRequestId 'synthetic-failure'
            throw 'Synthetic failure summary was accepted.'
        }
        catch {
            if ($_ -notmatch 'synthetic failure') {
                throw
            }
        }
        $passed.Add('synthetic serial success/failure result parsing')

        $concurrencySummary = [ordered]@{
            RunId = 'synthetic-concurrency'
            Mode = 'concurrency'
            RequestId = 'synthetic-concurrency-request'
            Identity = 'BAYSHORE\bekelly'
            SessionId = 0
            Commands = @(
                [ordered]@{ Name = 'concurrent-a'; Failures = @(); Success = $true }
                [ordered]@{ Name = 'concurrent-b'; Failures = @(); Success = $true }
            )
            Concurrency = [ordered]@{
                WorkerCount = 2
                OverlapMilliseconds = 4900
                MinimumRequiredOverlapMilliseconds = 2000
                CompletionBarrierUsed = $true
                Proven = $true
            }
            Success = $true
        }
        $concurrencyRun = New-Item -ItemType Directory `
            -Path (Join-Path $selfTestRoot 'concurrency-run')
        Write-AtomicJson -Path (Join-Path $concurrencyRun.FullName 'run-summary.json') `
            -Value $concurrencySummary
        Assert-RunSummary -Summary (Read-RunSummary -RunDirectory $concurrencyRun) `
            -ExpectedMode 'concurrency' `
            -ExpectedRequestId 'synthetic-concurrency-request'
        $passed.Add('synthetic concurrent overlap result parsing')

        $requestPath = Join-Path $selfTestRoot 'acceptance-request.json'
        Write-AcceptanceRequest -Mode 'concurrency' -RequestId 'synthetic-request' `
            -Path $requestPath
        $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
        if ($request.Mode -cne 'concurrency' -or $request.RequestId -cne 'synthetic-request') {
            throw 'Acceptance request did not preserve its mode and correlation ID.'
        }
        $passed.Add('atomic serial/concurrency request handoff')

        $backup = Join-Path $selfTestRoot 'run.cmd.backup'
        $active = Join-Path $selfTestRoot 'run.cmd'
        [System.IO.File]::WriteAllText($backup, 'original', $utf8NoBom)
        Copy-Item -LiteralPath $backup -Destination $active
        $expectedHash = Get-Sha256 -Path $backup
        try {
            [System.IO.File]::WriteAllText($active, 'temporary', $utf8NoBom)
            throw 'synthetic pre-launch failure'
        }
        catch {
            if ($_ -notmatch 'synthetic pre-launch failure') {
                throw
            }
        }
        finally {
            Restore-FileFromBackup -Backup $backup -Destination $active -ExpectedHash $expectedHash
        }
        if ((Get-Sha256 -Path $active) -cne $expectedHash) {
            throw 'Pre-launch failure restoration did not restore the original wrapper.'
        }
        $passed.Add('controller restoration after pre-launch failure')

        $preservedFile = Join-Path $selfTestRoot 'preserved.lock'
        [System.IO.File]::WriteAllText($preservedFile, 'original-lock', $utf8NoBom)
        $preservedBytes = [System.IO.File]::ReadAllBytes($preservedFile)
        $preservedFingerprint = Get-FileFingerprint -Path $preservedFile
        [System.IO.File]::WriteAllText($preservedFile, 'changed-lock', $utf8NoBom)
        Restore-ExactFileBytes -Path $preservedFile -Bytes $preservedBytes
        Assert-FileMatchesFingerprint -Path $preservedFile `
            -Expected $preservedFingerprint | Out-Null
        $passed.Add('exact lockfile byte restoration')

        $acceptanceSelfTestScript = if (Test-Path -LiteralPath $workspaceAcceptanceScript -PathType Leaf) {
            $workspaceAcceptanceScript
        }
        else {
            $acceptanceScript
        }
        $acceptanceSelfTestOutput = & (Join-Path $PSHOME 'powershell.exe') `
            -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
            -File $acceptanceSelfTestScript -SelfTest
        if ($LASTEXITCODE -ne 0) {
            throw "Acceptance artifact self-test failed: $($acceptanceSelfTestOutput -join [Environment]::NewLine)"
        }
        $acceptanceSelfTest = $acceptanceSelfTestOutput -join [Environment]::NewLine |
            ConvertFrom-Json
        if (-not $acceptanceSelfTest.Success) {
            throw 'Acceptance artifact self-test reported failure.'
        }
        $passed.Add('acceptance artifact-state self-test')

        [pscustomobject]@{
            SelfTest = 'controller'
            Passed = @($passed)
            BuildEnvironment = $buildEnvironment
            AcceptanceSelfTest = $acceptanceSelfTest
            ScheduledTaskStarted = $false
            Success = $true
        } | ConvertTo-Json -Depth 8
    }
    finally {
        $resolvedRoot = [System.IO.Path]::GetFullPath($selfTestRoot)
        $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolvedRoot.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -and
            [System.IO.Path]::GetFileName($resolvedRoot).StartsWith(
                'codex-session0-controller-selftest-',
                [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    }
}

if ($SelfTest) {
    Invoke-ControllerSelfTest
    exit 0
}
if ($BuildOnly) {
    Build-AcceptanceCandidate | ConvertTo-Json -Depth 8
    exit 0
}

try {
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    if ($task.Principal.LogonType -ne 'Password') {
        throw "Task logon type changed to '$($task.Principal.LogonType)'; expected Password."
    }
    $originalHash = Get-Sha256 -Path $originalRunCmd
    if ($originalHash -cne $expectedOriginalRunCmdHash) {
        throw "Original run.cmd backup hash was $originalHash, expected $expectedOriginalRunCmdHash."
    }
    if (-not (Test-Path -LiteralPath $workspaceAcceptanceScript -PathType Leaf)) {
        throw "Workspace acceptance script is missing: $workspaceAcceptanceScript"
    }
    if (-not (Test-Path -LiteralPath $acceptanceCmd -PathType Leaf)) {
        throw "Acceptance command wrapper is missing: $acceptanceCmd"
    }

    Copy-Item -LiteralPath $workspaceAcceptanceScript -Destination $acceptanceScript -Force
    $candidate = Build-AcceptanceCandidate
    Copy-Item -LiteralPath $acceptanceCmd -Destination $runCmd -Force
    for ($iteration = 1; $iteration -le 3; $iteration++) {
        $serialResults.Add((Invoke-SerialAcceptanceRun -Iteration $iteration))
    }

    $concurrencyResult = Invoke-ConcurrentAcceptanceRuns
}
catch {
    $controllerFailure = $_ | Out-String
}
finally {
    try {
        Restore-FileFromBackup -Backup $originalRunCmd -Destination $runCmd `
            -ExpectedHash $expectedOriginalRunCmdHash
    }
    catch {
        $restorationFailures.Add("restore run.cmd: $($_ | Out-String)")
    }
}

$finishedAt = [DateTimeOffset]::UtcNow
$success = $null -eq $controllerFailure -and $restorationFailures.Count -eq 0
$controllerSummary = [ordered]@{
    StartedAt = $startedAt.ToString('o')
    FinishedAt = $finishedAt.ToString('o')
    TaskName = $taskName
    StoredPasswordLogonPreserved = $true
    StoredPasswordTaskDefinitionMutated = $false
    Candidate = $candidate
    SerialRuns = @($serialResults)
    Concurrency = $concurrencyResult
    ControllerFailure = $controllerFailure
    RestorationFailures = @($restorationFailures)
    OriginalRunCmdRestored = ($restorationFailures.Count -eq 0)
    Success = $success
}
Write-AtomicJson -Path $controllerSummaryPath -Value $controllerSummary

if (-not $success) {
    Write-Error (($controllerSummary | ConvertTo-Json -Depth 12))
    exit 1
}
Write-Output ($controllerSummary | ConvertTo-Json -Depth 4)
exit 0
