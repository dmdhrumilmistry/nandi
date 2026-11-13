<#
.SYNOPSIS
Installs nandi on Windows. Written for an Intune Win32 app or platform
script; works from any deployment tool or by hand in an elevated shell.

.DESCRIPTION
- Downloads the release for this machine's architecture (x64 or ARM64) from
  GitHub and checks its SHA-256.
- Installs nandi.exe to "C:\Program Files\nandi" and adds it to the
  machine PATH.
- Writes policy packs and, optionally, a managed settings file to
  C:\ProgramData\nandi, writable by administrators only.
- Registers two scheduled tasks that run for every user who logs on:
  "nandi" (nandi run) and "nandi discover" (nandi discover --report at
  logon and every 6 hours).

Managed settings can also come from the ADMX policy (nandi.admx), which
writes HKLM\SOFTWARE\Policies\nandi.

.PARAMETER Version
Release tag, e.g. v0.2.0. Default: the latest release.

.PARAMETER Packs
Policy packs to install. Default: coding-agent, payments.

.PARAMETER ManagedSettings
Path to a YAML file to install as C:\ProgramData\nandi\managed.yaml.

.PARAMETER NoTasks
Install the binary and files only, without scheduled tasks.

.PARAMETER AgentHooks
Enforce nandi hooks in every coding agent that supports administrator-
enforced hooks (Claude Code, Codex, Gemini CLI, Copilot CLI, Windsurf).

.EXAMPLE
powershell.exe -ExecutionPolicy Bypass -File Install-Nandi.ps1 -ManagedSettings .\managed.yaml
#>
[CmdletBinding()]
param(
    [string]$Version = "latest",
    [string[]]$Packs = @("coding-agent", "payments"),
    [string]$ManagedSettings,
    [switch]$NoTasks,
    [switch]$AgentHooks
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Repo = "dmdhrumilmistry/nandi"
$InstallDir = Join-Path $env:ProgramFiles "nandi"
$DataDir = Join-Path $env:ProgramData "nandi"
$Exe = Join-Path $InstallDir "nandi.exe"

function Log($msg) { Write-Output "nandi install: $msg" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as administrator (or SYSTEM)."
}

$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$target = switch ($arch) {
    "AMD64" { "x86_64-pc-windows-msvc" }
    "ARM64" { "aarch64-pc-windows-msvc" }
    default { throw "Unsupported architecture $arch" }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($Version -eq "latest") {
    # Follow the releases/latest redirect rather than the GitHub API, which is
    # rate limited per IP (a problem behind a shared office NAT).
    $resp = Invoke-WebRequest "https://github.com/$Repo/releases/latest" -Method Head -UseBasicParsing
    $final = if ($resp.BaseResponse.ResponseUri) { $resp.BaseResponse.ResponseUri.AbsoluteUri }  # Windows PowerShell 5.1
             else { $resp.BaseResponse.RequestMessage.RequestUri.AbsoluteUri }                   # PowerShell 7
    $Version = ($final.TrimEnd("/") -split "/tag/")[-1]
    if ($Version -notlike "v*") { throw "Could not find the latest release" }
}
$name = "nandi-$Version-$target"
$url = "https://github.com/$Repo/releases/download/$Version/$name.zip"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Log "downloading $name"
    Invoke-WebRequest $url -OutFile "$tmp\$name.zip" -UseBasicParsing
    Invoke-WebRequest "$url.sha256" -OutFile "$tmp\$name.zip.sha256" -UseBasicParsing
    $expected = ((Get-Content "$tmp\$name.zip.sha256" -Raw).Trim() -split "\s+")[0]
    $actual = (Get-FileHash "$tmp\$name.zip" -Algorithm SHA256).Hash
    if ($actual -ne $expected.ToUpperInvariant()) { throw "Checksum mismatch for $name.zip" }
    Expand-Archive "$tmp\$name.zip" -DestinationPath $tmp -Force

    # Stop running copies so the binary can be replaced.
    Get-ScheduledTask -TaskName "nandi*" -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
    Get-Process nandi -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item "$tmp\$name\nandi.exe" $Exe -Force
    & $Exe version

    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (($machinePath -split ";") -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
    }

    # C:\ProgramData\nandi: readable by users, writable by administrators and
    # SYSTEM only, so users cannot change the managed settings or policies.
    New-Item -ItemType Directory -Path "$DataDir\policies" -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $none = [Security.AccessControl.PropagationFlags]::None
    foreach ($rule in @(
        @("*S-1-5-18", "FullControl"),      # SYSTEM
        @("*S-1-5-32-544", "FullControl"),  # Administrators
        @("*S-1-5-32-545", "ReadAndExecute") # Users
    )) {
        $sid = New-Object Security.Principal.SecurityIdentifier($rule[0].TrimStart("*"))
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, $rule[1], $inherit, $none, "Allow")))
    }
    Set-Acl -Path $DataDir -AclObject $acl

    foreach ($p in $Packs) {
        $lines = & $Exe policy pack $p
        [IO.File]::WriteAllLines("$DataDir\policies\$p.yaml", [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
        Log "policy pack $p"
    }
    if ($ManagedSettings) {
        Copy-Item $ManagedSettings "$DataDir\managed.yaml" -Force
        & $Exe managed
        if ($LASTEXITCODE -ne 0) { throw "The managed settings are not valid; see above." }
    }

    if ($AgentHooks) {
        & $Exe hook-config all --managed --write
        if ($LASTEXITCODE -ne 0) { Log "some agent hooks need attention, see above" }
    }

    if (-not $NoTasks) {
        $users = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Hidden
        $config = '"%LOCALAPPDATA%\nandi\nandi.yaml"'
        # conhost --headless keeps the console window of a long-running process hidden.
        $run = New-ScheduledTaskAction -Execute "conhost.exe" -Argument "--headless `"$Exe`" run -c $config"
        Register-ScheduledTask -TaskName "nandi" -Action $run -Principal $users -Settings $settings `
            -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Force | Out-Null
        $discover = New-ScheduledTaskAction -Execute "conhost.exe" -Argument "--headless `"$Exe`" discover --report -c $config"
        $every6h = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 6)
        Register-ScheduledTask -TaskName "nandi discover" -Action $discover -Principal $users -Settings $settings `
            -Trigger @((New-ScheduledTaskTrigger -AtLogOn), $every6h) -Force | Out-Null
        Log "scheduled tasks registered; they start at the next logon"
    }
    Log "installed $Version"
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
