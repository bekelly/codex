param(
    [switch]$SelfTest,
    [switch]$ConcurrentWorker,
    [string]$CoordinationRoot,
    [string]$WorkerName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$taskRoot = 'C:\ProgramData\BayshoreLabs\CodexSession0UserProbe'
$candidateManifestPattern = 'acceptance-candidate-*.json'
$acceptanceRequestPath = Join-Path $taskRoot 'acceptance-request.json'
$codex = $null
$candidate = $null
$probe = 'C:\CodexSelfBuiltSandboxProbe'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$startedAt = [DateTimeOffset]::UtcNow
$runId = 'run-{0}-{1}' -f $startedAt.ToString('yyyyMMdd-HHmmss-fff'), $PID
$runRoot = if ($ConcurrentWorker) {
    $CoordinationRoot
}
elseif ($SelfTest) {
    $null
}
else {
    Join-Path $taskRoot $runId
}
if (-not $SelfTest -and -not $ConcurrentWorker) {
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
}

function Write-AtomicText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyString()][string]$Text
    )

    $temporaryPath = '{0}.tmp-{1}-{2}' -f $Path, $PID, [Guid]::NewGuid().ToString('N')
    [System.IO.File]::WriteAllText($temporaryPath, $Text, $script:utf8NoBom)
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Read-Artifact {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ State = 'missing'; Length = $null; Text = $null }
    }
    $length = (Get-Item -LiteralPath $Path).Length
    if ($length -eq 0) {
        return [pscustomobject]@{ State = 'empty'; Length = 0; Text = '' }
    }
    [pscustomobject]@{
        State = 'content'
        Length = $length
        Text = [System.IO.File]::ReadAllText($Path)
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

function Get-SandboxLogCheckpoint {
    $path = Join-Path (Join-Path $env:USERPROFILE '.codex\.sandbox') (
        'sandbox.{0}.log' -f [DateTime]::UtcNow.ToString('yyyy-MM-dd'))
    $length = if (Test-Path -LiteralPath $path -PathType Leaf) {
        (Get-Item -LiteralPath $path).Length
    }
    else {
        0
    }
    [pscustomobject]@{ Path = $path; Length = [int64]$length }
}

function Read-SandboxLogSince {
    param([Parameter(Mandatory = $true)]$Checkpoint)

    if (-not (Test-Path -LiteralPath $Checkpoint.Path -PathType Leaf)) {
        return ''
    }
    $stream = [System.IO.File]::Open(
        $Checkpoint.Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite)
    try {
        if ($Checkpoint.Length -gt $stream.Length) {
            return ''
        }
        [void]$stream.Seek($Checkpoint.Length, [System.IO.SeekOrigin]::Begin)
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
        try {
            $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-ResolvedRunnerPathFromLog {
    param(
        [AllowEmptyString()][string]$LogText,
        [Parameter(Mandatory = $true)][string]$ExpectedSourcePath
    )

    $paths = [System.Collections.Generic.List[string]]::new()
    $copyMatches = [regex]::Matches(
        $LogText,
        '(?m)helper copy: (?:validating|reused|recopied) command-runner source=(?<source>.+?) destination=(?<path>[^\r\n]+)$')
    foreach ($match in $copyMatches) {
        if ($match.Groups['source'].Value.Trim() -ieq $ExpectedSourcePath) {
            $paths.Add($match.Groups['path'].Value.Trim())
        }
    }
    $fallbackMatches = [regex]::Matches(
        $LogText,
        '(?m)helper copy failed for command-runner: .*; falling back to legacy path (?<path>[^\r\n]+)$')
    foreach ($match in $fallbackMatches) {
        $path = $match.Groups['path'].Value.Trim()
        if ($path -ieq $ExpectedSourcePath) {
            $paths.Add($path)
        }
    }
    if ($paths.Count -eq 0) { $null } else { $paths[$paths.Count - 1] }
}

function Get-ResolvedSetupPathFromLog {
    param(
        [AllowEmptyString()][string]$LogText,
        [Parameter(Mandatory = $true)][string]$ExpectedSourcePath
    )

    $matches = [regex]::Matches(
        $LogText,
        '(?m)setup refresh: spawning (?<path>.+?) \(cwd=')
    $paths = @(
        foreach ($match in $matches) {
            $path = $match.Groups['path'].Value.Trim()
            if ($path -ieq $ExpectedSourcePath) {
                $path
            }
        }
    )
    if ($paths.Count -eq 0) { $null } else { $paths[-1] }
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class CodexSession0WindowAclSnapshot
{
    private const int SeWindowObject = 7;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int AclSizeInformation = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct AclSizeInformationData
    {
        public uint AceCount;
        public uint AclBytesInUse;
        public uint AclBytesFree;
    }

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetProcessWindowStation();

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetThreadDesktop(uint threadId);

    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        IntPtr handle,
        int objectType,
        uint securityInfo,
        IntPtr owner,
        IntPtr group,
        out IntPtr dacl,
        IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAclInformation(
        IntPtr acl,
        out AclSizeInformationData information,
        uint informationLength,
        int informationClass);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static string Capture(IntPtr handle, string label)
    {
        if (handle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), label + " handle lookup failed");
        }

        IntPtr dacl;
        IntPtr securityDescriptor;
        uint code = GetSecurityInfo(
            handle,
            SeWindowObject,
            DaclSecurityInformation,
            IntPtr.Zero,
            IntPtr.Zero,
            out dacl,
            IntPtr.Zero,
            out securityDescriptor);
        if (code != 0)
        {
            throw new Win32Exception((int)code, "GetSecurityInfo failed for " + label);
        }

        try
        {
            if (dacl == IntPtr.Zero)
            {
                return "<NULL-DACL>";
            }
            AclSizeInformationData information;
            if (!GetAclInformation(
                dacl,
                out information,
                (uint)Marshal.SizeOf(typeof(AclSizeInformationData)),
                AclSizeInformation))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetAclInformation failed for " + label);
            }
            byte[] bytes = new byte[information.AclBytesInUse];
            Marshal.Copy(dacl, bytes, 0, bytes.Length);
            return Convert.ToBase64String(bytes);
        }
        finally
        {
            if (securityDescriptor != IntPtr.Zero)
            {
                LocalFree(securityDescriptor);
            }
        }
    }

}
'@

function Get-StableWindowAclSnapshot {
    $createdNew = $false
    $mutex = [System.Threading.Mutex]::new(
        $false,
        'Local\CodexSandboxDesktopBootstrapAcl',
        [ref]$createdNew)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        if (-not $acquired) {
            throw 'Timed out acquiring the production desktop-bootstrap ACL mutex for a stable DACL snapshot.'
        }
        $windowStation = [CodexSession0WindowAclSnapshot]::GetProcessWindowStation()
        $desktop = [CodexSession0WindowAclSnapshot]::GetThreadDesktop(
            [CodexSession0WindowAclSnapshot]::GetCurrentThreadId())
        [ordered]@{
            WindowStation = [ordered]@{
                Bytes = [CodexSession0WindowAclSnapshot]::Capture($windowStation, 'window station')
            }
            Desktop = [ordered]@{
                Bytes = [CodexSession0WindowAclSnapshot]::Capture($desktop, 'desktop')
            }
        }
    }
    finally {
        if ($acquired) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}

function ConvertTo-WindowsCommandLineArgument {
    param([AllowEmptyString()][Parameter(Mandatory = $true)][string]$Argument)

    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') {
        return $Argument
    }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append([char]'"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashes++
        }
        elseif ($character -eq [char]'"') {
            [void]$builder.Append([char]'\', (2 * $backslashes) + 1)
            [void]$builder.Append([char]'"')
            $backslashes = 0
        }
        else {
            [void]$builder.Append([char]'\', $backslashes)
            [void]$builder.Append($character)
            $backslashes = 0
        }
    }
    [void]$builder.Append([char]'\', 2 * $backslashes)
    [void]$builder.Append([char]'"')
    $builder.ToString()
}

function Invoke-CapturedNativeProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [AllowNull()][AllowEmptyCollection()][string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = @(
        $Arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument -Argument $_ }
    ) -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Process.Start returned false for $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        [System.IO.File]::WriteAllText($StdoutPath, $stdout, $script:utf8NoBom)
        [System.IO.File]::WriteAllText($StderrPath, $stderr, $script:utf8NoBom)
        $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
}

function Wait-CoordinationFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Deadline
    )

    while ([DateTimeOffset]::Now -lt $Deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return
        }
        Start-Sleep -Milliseconds 25
    }
    throw "Timed out waiting for concurrency coordination file: $Path"
}

function Start-ConcurrentWorkerProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $hostExecutable = Join-Path $PSHOME 'powershell.exe'
    $arguments = @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-ConcurrentWorker',
        '-CoordinationRoot', $Root,
        '-WorkerName', $Name
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $hostExecutable
    $startInfo.Arguments = @(
        $arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument -Argument $_ }
    ) -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        $process.Dispose()
        throw "Process.Start returned false for concurrency worker $Name"
    }
    $process
}

function Invoke-CandidateCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ExpectedOutput,
        [string]$ReadyPath,
        [string]$StartGatePath,
        [string]$CompletedPath,
        [string]$ValidationGatePath
    )

    $stdoutPath = Join-Path $runRoot "$Name.stdout.txt"
    $stderrPath = Join-Path $runRoot "$Name.stderr.txt"
    $exitPath = Join-Path $runRoot "$Name.exit.txt"
    $metadataPath = Join-Path $runRoot "$Name.result.json"
    $suffix = '.tmp-{0}-{1}' -f $PID, [Guid]::NewGuid().ToString('N')
    $stdoutTemporary = "$stdoutPath$suffix"
    $stderrTemporary = "$stderrPath$suffix"
    $codexFingerprint = Assert-FileMatchesFingerprint -Path $codex -Expected $candidate.Codex
    $commandRunnerSourceFingerprint = Assert-FileMatchesFingerprint `
        -Path ([string]$candidate.CommandRunner.Path) -Expected $candidate.CommandRunner
    $setupSourceFingerprint = Assert-FileMatchesFingerprint `
        -Path ([string]$candidate.SetupHelper.Path) -Expected $candidate.SetupHelper
    $sandboxLogCheckpoint = Get-SandboxLogCheckpoint
    $beforeAcl = Get-StableWindowAclSnapshot
    if (-not [string]::IsNullOrWhiteSpace($ReadyPath)) {
        Write-AtomicText -Path $ReadyPath -Text ([DateTimeOffset]::UtcNow.ToString('o'))
        Wait-CoordinationFile -Path $StartGatePath `
            -Deadline ([DateTimeOffset]::Now.AddSeconds(30))
    }
    $codexArguments = @(
        'sandbox'
        '-P'
        ':workspace'
        '-c'
        'windows.sandbox=elevated'
        '-C'
        $probe
        $Executable
    ) + $Arguments

    $commandStartedAt = [DateTimeOffset]::UtcNow
    $exitCode = Invoke-CapturedNativeProcess -FilePath $codex -Arguments $codexArguments `
        -StdoutPath $stdoutTemporary -StderrPath $stderrTemporary
    $commandFinishedAt = [DateTimeOffset]::UtcNow
    Move-Item -LiteralPath $stdoutTemporary -Destination $stdoutPath -Force
    Move-Item -LiteralPath $stderrTemporary -Destination $stderrPath -Force
    Write-AtomicText -Path $exitPath -Text ([string]$exitCode)
    if (-not [string]::IsNullOrWhiteSpace($CompletedPath)) {
        Write-AtomicText -Path $CompletedPath -Text ($commandFinishedAt.ToString('o'))
        Wait-CoordinationFile -Path $ValidationGatePath `
            -Deadline ([DateTimeOffset]::Now.AddSeconds(30))
    }
    $afterAcl = Get-StableWindowAclSnapshot
    $stdout = Read-Artifact -Path $stdoutPath
    $stderr = Read-Artifact -Path $stderrPath
    $exitArtifact = Read-Artifact -Path $exitPath
    $failures = [System.Collections.Generic.List[string]]::new()
    $sandboxLogText = Read-SandboxLogSince -Checkpoint $sandboxLogCheckpoint
    $resolvedSetupPath = Get-ResolvedSetupPathFromLog -LogText $sandboxLogText `
        -ExpectedSourcePath ([string]$candidate.SetupHelper.Path)
    $resolvedSetupFingerprint = $null
    if ($null -eq $resolvedSetupPath) {
        $failures.Add('sandbox log did not identify the setup-helper launch path')
    }
    else {
        try {
            $resolvedSetupFingerprint = Assert-FileMatchesFingerprint `
                -Path $resolvedSetupPath -Expected $candidate.SetupHelper
        }
        catch {
            $failures.Add("resolved setup helper did not match the source build: $($_.Exception.Message)")
        }
    }
    $resolvedCommandRunnerPath = Get-ResolvedRunnerPathFromLog -LogText $sandboxLogText `
        -ExpectedSourcePath ([string]$candidate.CommandRunner.Path)
    $resolvedCommandRunnerFingerprint = $null
    if ($null -eq $resolvedCommandRunnerPath) {
        $failures.Add('sandbox log did not identify the command-runner launch path')
    }
    else {
        try {
            $resolvedCommandRunnerFingerprint = Assert-FileMatchesFingerprint `
                -Path $resolvedCommandRunnerPath -Expected $candidate.CommandRunner
        }
        catch {
            $failures.Add("resolved command-runner did not match the source build: $($_.Exception.Message)")
        }
    }

    if ($null -eq $exitCode -or $exitArtifact.State -ne 'content' -or
        -not [int]::TryParse($exitArtifact.Text.Trim(), [ref]$exitCode)) {
        $failures.Add("exit-code artifact is $($exitArtifact.State), not a numeric value")
    }
    elseif ($exitCode -ne 0) {
        $failures.Add("process exit code was $exitCode")
    }
    if ($stdout.State -ne 'content' -or $stdout.Text -notmatch $ExpectedOutput) {
        $failures.Add("stdout state=$($stdout.State) did not contain '$ExpectedOutput'")
    }
    if ($stderr.State -eq 'missing') {
        $failures.Add('stderr artifact is missing')
    }
    $stderrText = if ($null -eq $stderr.Text) { '' } else { [string]$stderr.Text }
    if ($stderrText -match '0xC0000142|timed out after .*connecting runner|runner process was still alive') {
        $failures.Add('stderr contains a pre-main failure or runner pipe timeout')
    }
    if ($beforeAcl.WindowStation.Bytes -cne $afterAcl.WindowStation.Bytes) {
        $failures.Add('window-station DACL bytes changed across the completed command')
    }
    if ($beforeAcl.Desktop.Bytes -cne $afterAcl.Desktop.Bytes) {
        $failures.Add('desktop DACL bytes changed across the completed command')
    }

    $result = [ordered]@{
        Name = $Name
        HarnessIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        HarnessSessionId = (Get-Process -Id $PID).SessionId
        StartedAt = $commandStartedAt.ToString('o')
        FinishedAt = $commandFinishedAt.ToString('o')
        Executable = $Executable
        Arguments = $Arguments
        CodexFingerprint = $codexFingerprint
        CommandRunnerSourceFingerprint = $commandRunnerSourceFingerprint
        SetupHelperSourceFingerprint = $setupSourceFingerprint
        ResolvedSetupHelper = $resolvedSetupFingerprint
        ResolvedCommandRunner = $resolvedCommandRunnerFingerprint
        ExitArtifactState = $exitArtifact.State
        ExitCode = $exitCode
        StdoutState = $stdout.State
        StdoutLength = $stdout.Length
        StderrState = $stderr.State
        StderrLength = $stderr.Length
        ExpectedOutput = $ExpectedOutput
        WindowStationDaclRestoredExactly = ($beforeAcl.WindowStation.Bytes -ceq $afterAcl.WindowStation.Bytes)
        DesktopDaclRestoredExactly = ($beforeAcl.Desktop.Bytes -ceq $afterAcl.Desktop.Bytes)
        Failures = @($failures)
        Success = ($failures.Count -eq 0)
    }
    Write-AtomicText -Path $metadataPath -Text ($result | ConvertTo-Json -Depth 6)
    [pscustomobject]$result
}

function Get-ConcurrencyEvidence {
    param(
        [Parameter(Mandatory = $true)][object[]]$Results,
        [Parameter(Mandatory = $true)][DateTimeOffset]$GateOpenedAt,
        [int]$MinimumOverlapMilliseconds = 2000
    )

    $started = @($Results | ForEach-Object { [DateTimeOffset]::Parse($_.StartedAt) })
    $finished = @($Results | ForEach-Object { [DateTimeOffset]::Parse($_.FinishedAt) })
    $overlapStartedAt = @($started | Sort-Object -Descending)[0]
    $overlapFinishedAt = @($finished | Sort-Object)[0]
    $overlapMilliseconds = [Math]::Max(
        0,
        ($overlapFinishedAt - $overlapStartedAt).TotalMilliseconds)
    $workerSessionIds = @($Results | ForEach-Object { [int]$_.HarnessSessionId })
    $workerIdentities = @($Results | ForEach-Object { [string]$_.HarnessIdentity })
    $session0PrincipalPreserved = `
        -not ($workerSessionIds | Where-Object { $_ -ne 0 }) -and
        -not ($workerIdentities | Where-Object { $_ -ine 'BAYSHORE\bekelly' })
    $workersSucceeded = -not ($Results.Success -contains $false)
    [pscustomobject][ordered]@{
        WorkerCount = $Results.Count
        WorkerSessionIds = $workerSessionIds
        WorkerIdentities = $workerIdentities
        Session0PrincipalPreserved = $session0PrincipalPreserved
        WorkersSucceeded = $workersSucceeded
        StartGateOpenedAt = $GateOpenedAt.ToString('o')
        OverlapStartedAt = $overlapStartedAt.ToString('o')
        OverlapFinishedAt = $overlapFinishedAt.ToString('o')
        OverlapMilliseconds = $overlapMilliseconds
        MinimumRequiredOverlapMilliseconds = $MinimumOverlapMilliseconds
        CompletionBarrierUsed = $true
        Proven = ($overlapMilliseconds -ge $MinimumOverlapMilliseconds -and
            $session0PrincipalPreserved -and $workersSucceeded)
    }
}

function Invoke-ConcurrentCandidateCommands {
    $coordinationDirectory = Join-Path $runRoot 'coordination'
    New-Item -ItemType Directory -Path $coordinationDirectory | Out-Null
    $workerNames = @('concurrent-a', 'concurrent-b')
    $startGatePath = Join-Path $coordinationDirectory 'start.gate'
    $validationGatePath = Join-Path $coordinationDirectory 'validate.gate'
    $workers = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($name in $workerNames) {
            $workers.Add((Start-ConcurrentWorkerProcess -Name $name -Root $runRoot))
        }
        foreach ($name in $workerNames) {
            Wait-CoordinationFile -Path (Join-Path $coordinationDirectory "$name.ready") `
                -Deadline ([DateTimeOffset]::Now.AddSeconds(45))
        }
        $gateOpenedAt = [DateTimeOffset]::UtcNow
        Write-AtomicText -Path $startGatePath -Text ($gateOpenedAt.ToString('o'))
        foreach ($name in $workerNames) {
            Wait-CoordinationFile -Path (Join-Path $coordinationDirectory "$name.completed") `
                -Deadline ([DateTimeOffset]::Now.AddSeconds(60))
        }
        Write-AtomicText -Path $validationGatePath `
            -Text ([DateTimeOffset]::UtcNow.ToString('o'))

        $workerExitCodes = [System.Collections.Generic.List[int]]::new()
        foreach ($worker in $workers) {
            if (-not $worker.WaitForExit(60000)) {
                throw "Concurrency worker PID $($worker.Id) did not exit after validation release."
            }
            $workerExitCodes.Add($worker.ExitCode)
        }
        $results = @(
            foreach ($name in $workerNames) {
                $resultPath = Join-Path $runRoot "$name.result.json"
                if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
                    throw "Concurrency worker result is missing: $resultPath"
                }
                Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
            }
        )
        [pscustomobject]@{
            Results = $results
            Evidence = Get-ConcurrencyEvidence -Results $results `
                -GateOpenedAt $gateOpenedAt
            WorkerExitCodes = @($workerExitCodes)
        }
    }
    finally {
        foreach ($worker in $workers) {
            $worker.Dispose()
        }
    }
}

function Invoke-AcceptanceSelfTest {
    $selfTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'codex-session0-acceptance-selftest-{0}' -f [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $selfTestRoot | Out-Null
    $passed = [System.Collections.Generic.List[string]]::new()
    try {
        $missingPath = Join-Path $selfTestRoot 'missing.txt'
        $emptyPath = Join-Path $selfTestRoot 'empty.txt'
        $contentPath = Join-Path $selfTestRoot 'content.txt'
        [System.IO.File]::WriteAllBytes($emptyPath, [byte[]]@())
        Write-AtomicText -Path $contentPath -Text '42'
        $missing = Read-Artifact -Path $missingPath
        $empty = Read-Artifact -Path $emptyPath
        $content = Read-Artifact -Path $contentPath
        if ($missing.State -ne 'missing' -or $empty.State -ne 'empty' -or
            $content.State -ne 'content' -or $content.Text -ne '42') {
            throw 'Missing/empty/content artifact states were not distinguished correctly.'
        }
        $passed.Add('missing, empty, and populated result files')

        $fingerprintPath = Join-Path $selfTestRoot 'fingerprint.exe'
        [System.IO.File]::WriteAllText($fingerprintPath, 'fresh', $utf8NoBom)
        $expectedFingerprint = Get-FileFingerprint -Path $fingerprintPath
        $verifiedFingerprint = Assert-FileMatchesFingerprint -Path $fingerprintPath `
            -Expected $expectedFingerprint
        if ($verifiedFingerprint.Sha256 -cne $expectedFingerprint.Sha256) {
            throw 'Matching binary fingerprint was not accepted.'
        }
        [System.IO.File]::WriteAllText($fingerprintPath, 'stale', $utf8NoBom)
        try {
            Assert-FileMatchesFingerprint -Path $fingerprintPath `
                -Expected $expectedFingerprint | Out-Null
            throw 'Mismatched binary fingerprint was accepted.'
        }
        catch {
            if ($_ -notmatch 'Binary fingerprint mismatch') {
                throw
            }
        }
        $passed.Add('matching and stale binary fingerprints')

        $copiedRunner = Get-ResolvedRunnerPathFromLog -ExpectedSourcePath 'C:\candidate\codex-command-runner.exe' -LogText @'
[2026-09-02 15:00:00.000 codex.exe] helper copy: validating command-runner source=C:\candidate\codex-command-runner.exe destination=C:\cache\codex-command-runner-0.152.0.exe
[2026-09-02 15:00:00.001 codex.exe] helper launch resolution: using copied command-runner path C:\cache\codex-command-runner-0.152.0.exe
[2026-09-02 15:00:00.002 codex.exe] helper copy: validating command-runner source=C:\installed\codex-command-runner.exe destination=C:\cache\codex-command-runner-0.153.0-alpha.5.exe
[2026-09-02 15:00:00.003 codex.exe] helper launch resolution: using copied command-runner path C:\cache\codex-command-runner-0.153.0-alpha.5.exe
'@
        $fallbackRunner = Get-ResolvedRunnerPathFromLog -LogText @'
[2026-09-02 15:00:00.000 codex.exe] helper copy failed for command-runner: synthetic; falling back to legacy path C:\fallback\codex-command-runner.exe
'@ -ExpectedSourcePath 'C:\fallback\codex-command-runner.exe'
        $resolvedSetup = Get-ResolvedSetupPathFromLog -LogText @'
[2026-09-02 15:00:00.000 codex.exe] setup refresh: spawning C:\candidate\codex-windows-sandbox-setup.exe (cwd=C:\work, payload_len=42)
[2026-09-02 15:00:00.001 codex.exe] setup refresh: spawning C:\installed\codex-windows-sandbox-setup.exe (cwd=C:\other, payload_len=42)
'@ -ExpectedSourcePath 'C:\candidate\codex-windows-sandbox-setup.exe'
        if ($copiedRunner -cne 'C:\cache\codex-command-runner-0.152.0.exe' -or
            $fallbackRunner -cne 'C:\fallback\codex-command-runner.exe' -or
            $resolvedSetup -cne 'C:\candidate\codex-windows-sandbox-setup.exe') {
            throw 'Sandbox helper launch path parsing failed.'
        }
        $passed.Add('source-correlated setup and copied/fallback command-runner path parsing')

        $nativeStdout = Join-Path $selfTestRoot 'native.stdout.txt'
        $nativeStderr = Join-Path $selfTestRoot 'native.stderr.txt'
        $nativeExit = Invoke-CapturedNativeProcess `
            -FilePath "$env:SystemRoot\System32\cmd.exe" `
            -Arguments @(
                '/d',
                '/c',
                'echo SELFTEST_NATIVE_OUT & echo SELFTEST_NATIVE_ERR 1>&2 & exit /b 7'
            ) `
            -StdoutPath $nativeStdout -StderrPath $nativeStderr
        $nativeStdoutArtifact = Read-Artifact -Path $nativeStdout
        $nativeStderrArtifact = Read-Artifact -Path $nativeStderr
        if ($nativeExit -ne 7 -or
            $nativeStdoutArtifact.Text -notmatch 'SELFTEST_NATIVE_OUT' -or
            $nativeStderrArtifact.Text -notmatch 'SELFTEST_NATIVE_ERR') {
            throw 'Raw native stdout/stderr or numeric nonzero exit capture failed.'
        }
        $passed.Add('raw native stdout/stderr and numeric exit capture')

        $syntheticConcurrency = Get-ConcurrencyEvidence -Results @(
            [pscustomobject]@{
                StartedAt = '2026-09-03T10:00:00.0000000+00:00'
                FinishedAt = '2026-09-03T10:00:05.0000000+00:00'
                HarnessIdentity = 'BAYSHORE\bekelly'
                HarnessSessionId = 0
                Success = $true
            },
            [pscustomobject]@{
                StartedAt = '2026-09-03T10:00:00.1000000+00:00'
                FinishedAt = '2026-09-03T10:00:05.1000000+00:00'
                HarnessIdentity = 'BAYSHORE\bekelly'
                HarnessSessionId = 0
                Success = $true
            }
        ) -GateOpenedAt ([DateTimeOffset]::Parse('2026-09-03T10:00:00+00:00'))
        if (-not $syntheticConcurrency.Proven -or
            $syntheticConcurrency.WorkerCount -ne 2 -or
            $syntheticConcurrency.OverlapMilliseconds -ne 4900 -or
            -not $syntheticConcurrency.Session0PrincipalPreserved -or
            -not $syntheticConcurrency.WorkersSucceeded) {
            throw 'Concurrent process interval proof was calculated incorrectly.'
        }
        $passed.Add('two-worker process-overlap proof')

        [pscustomobject]@{
            SelfTest = 'acceptance'
            Passed = @($passed)
            Success = $true
        } | ConvertTo-Json -Depth 4
    }
    finally {
        $resolvedRoot = [System.IO.Path]::GetFullPath($selfTestRoot)
        $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolvedRoot.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -and
            [System.IO.Path]::GetFileName($resolvedRoot).StartsWith(
                'codex-session0-acceptance-selftest-',
                [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    }
}

if ($SelfTest) {
    Invoke-AcceptanceSelfTest
    exit 0
}

try {
    if (-not (Test-Path -LiteralPath $acceptanceRequestPath -PathType Leaf)) {
        throw "Acceptance request is missing: $acceptanceRequestPath"
    }
    $request = Get-Content -LiteralPath $acceptanceRequestPath -Raw | ConvertFrom-Json
    if ([string]$request.Mode -notin @('serial', 'concurrency') -or
        [string]::IsNullOrWhiteSpace([string]$request.RequestId)) {
        throw 'Acceptance request mode or correlation ID is invalid.'
    }
    $requestAge = $startedAt - [DateTimeOffset]::Parse([string]$request.CreatedAt)
    if ($requestAge -lt [TimeSpan]::FromMinutes(-1) -or
        $requestAge -gt [TimeSpan]::FromMinutes(5)) {
        throw "Acceptance request age was $requestAge; expected a request created within the last 5 minutes."
    }
    $candidateManifest = Get-ChildItem -LiteralPath $taskRoot -File `
        -Filter $candidateManifestPattern |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $candidateManifest) {
        throw "Acceptance candidate manifest is missing under $taskRoot."
    }
    $candidate = Get-Content -LiteralPath $candidateManifest.FullName -Raw | ConvertFrom-Json
    if ([string]$candidate.ManifestPath -cne $candidateManifest.FullName) {
        throw "Acceptance candidate manifest path mismatch: $($candidate.ManifestPath)"
    }
    $buildFinishedAt = [DateTimeOffset]::Parse([string]$candidate.BuildFinishedAt)
    $manifestAge = $startedAt - $buildFinishedAt
    if ($manifestAge -lt [TimeSpan]::FromMinutes(-1) -or
        $manifestAge -gt [TimeSpan]::FromMinutes(10)) {
        throw "Acceptance candidate manifest age was $manifestAge; expected a build completed within the last 10 minutes."
    }
    if ([string]$candidate.RuntimeLayout -cne 'candidate-local') {
        throw "Unsupported acceptance runtime layout: $($candidate.RuntimeLayout)"
    }
    $codex = [string]$candidate.Codex.Path
    Assert-FileMatchesFingerprint -Path $codex -Expected $candidate.Codex | Out-Null
    Assert-FileMatchesFingerprint -Path ([string]$candidate.CommandRunner.Path) `
        -Expected $candidate.CommandRunner | Out-Null
    Assert-FileMatchesFingerprint -Path ([string]$candidate.SetupHelper.Path) `
        -Expected $candidate.SetupHelper | Out-Null
    Remove-Item Env:CODEX_WINDOWS_SANDBOX_SESSION0_DIAGNOSTIC_RIGHTS -ErrorAction SilentlyContinue
    Remove-Item Env:CODEX_WINDOWS_SANDBOX_SESSION0_STARTUP_PROBE -ErrorAction SilentlyContinue
    $env:SBX_DEBUG = '1'

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $sessionId = (Get-Process -Id $PID).SessionId
    if ($ConcurrentWorker) {
        if ([string]$request.Mode -cne 'concurrency' -or
            [string]::IsNullOrWhiteSpace($runRoot) -or
            $WorkerName -notin @('concurrent-a', 'concurrent-b')) {
            throw 'Concurrent worker arguments or acceptance mode are invalid.'
        }
        $coordinationDirectory = Join-Path $runRoot 'coordination'
        $marker = $WorkerName.Replace('-', '_').ToUpperInvariant()
        $result = Invoke-CandidateCommand -Name $WorkerName `
            -Executable 'C:\Program Files\PowerShell\7\pwsh.exe' `
            -Arguments @(
                '-NoLogo',
                '-NoProfile',
                '-NonInteractive',
                '-Command',
                "Start-Sleep -Seconds 5; Write-Output SESSION0_${marker}_OK"
            ) `
            -ExpectedOutput "SESSION0_${marker}_OK" `
            -ReadyPath (Join-Path $coordinationDirectory "$WorkerName.ready") `
            -StartGatePath (Join-Path $coordinationDirectory 'start.gate') `
            -CompletedPath (Join-Path $coordinationDirectory "$WorkerName.completed") `
            -ValidationGatePath (Join-Path $coordinationDirectory 'validate.gate')
        if (-not $result.Success) {
            exit 1
        }
        exit 0
    }

    $concurrency = $null
    $concurrencyWorkerExitCodes = $null
    if ([string]$request.Mode -ceq 'concurrency') {
        $concurrent = Invoke-ConcurrentCandidateCommands
        $results = @($concurrent.Results)
        $concurrency = $concurrent.Evidence
        $concurrencyWorkerExitCodes = @($concurrent.WorkerExitCodes)
    }
    else {
        $results = @(
            Invoke-CandidateCommand -Name 'cmd' `
                -Executable 'C:\Windows\System32\cmd.exe' `
                -Arguments @('/d', '/c', 'echo SESSION0_CMD_OK') `
                -ExpectedOutput 'SESSION0_CMD_OK'
            Invoke-CandidateCommand -Name 'pwsh' `
                -Executable 'C:\Program Files\PowerShell\7\pwsh.exe' `
                -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Write-Output SESSION0_PWSH_OK') `
                -ExpectedOutput 'SESSION0_PWSH_OK'
            Invoke-CandidateCommand -Name 'git' `
                -Executable 'C:\Program Files\Git\cmd\git.exe' `
                -Arguments @('--version') `
                -ExpectedOutput '^git version '
            Invoke-CandidateCommand -Name 'user32' `
                -Executable 'C:\Windows\System32\where.exe' `
                -Arguments @('cmd.exe') `
                -ExpectedOutput '(?i)\\cmd\.exe'
        )
    }
    $finishedAt = [DateTimeOffset]::UtcNow
    $success = -not ($results.Success -contains $false) -and
        ($null -eq $concurrency -or $concurrency.Proven)
    $summary = [ordered]@{
        RunId = $runId
        Mode = [string]$request.Mode
        RequestId = [string]$request.RequestId
        StartedAt = $startedAt.ToString('o')
        FinishedAt = $finishedAt.ToString('o')
        Identity = $identity
        SessionId = $sessionId
        Codex = $codex
        Candidate = $candidate
        DiagnosticProbeEnvironmentRemoved = $true
        Commands = $results
        Concurrency = $concurrency
        ConcurrencyWorkerExitCodes = $concurrencyWorkerExitCodes
        Success = $success
    }
    Write-AtomicText -Path (Join-Path $runRoot 'run-summary.json') `
        -Text ($summary | ConvertTo-Json -Depth 8)
    Write-AtomicText -Path (Join-Path $taskRoot 'latest-run-id.txt') -Text $runId

    foreach ($result in $results) {
        Write-Output ('{0}: success={1} exit={2} stdout={3}/{4} stderr={5}/{6} winsta_restored={7} desktop_restored={8}' -f `
            $result.Name, $result.Success, $result.ExitCode, $result.StdoutState,
            $result.StdoutLength, $result.StderrState, $result.StderrLength,
            $result.WindowStationDaclRestoredExactly, $result.DesktopDaclRestoredExactly)
        foreach ($failure in $result.Failures) {
            Write-Output "  FAILURE: $failure"
        }
    }
    if (-not $success) {
        exit 1
    }
    exit 0
}
catch {
    $errorText = $_ | Out-String
    $errorName = if ($ConcurrentWorker -and -not [string]::IsNullOrWhiteSpace($WorkerName)) {
        "$WorkerName.harness-error.txt"
    }
    else {
        'harness-error.txt'
    }
    if (-not [string]::IsNullOrWhiteSpace($runRoot)) {
        Write-AtomicText -Path (Join-Path $runRoot $errorName) -Text $errorText
    }
    if (-not $ConcurrentWorker) {
        Write-AtomicText -Path (Join-Path $taskRoot 'latest-run-id.txt') -Text $runId
    }
    Write-Error $errorText -ErrorAction Continue
    exit 2
}
