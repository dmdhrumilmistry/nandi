# Removes nandi installed by Install-Nandi.ps1. Keeps C:\ProgramData\nandi
# (managed settings, policies) unless -Purge is given; users' own data under
# %LOCALAPPDATA%\nandi is left alone.
param([switch]$Purge)
$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:ProgramFiles "nandi"
Get-ScheduledTask -TaskName "nandi*" -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -InputObject $_ -Confirm:$false
}
Get-Process nandi -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
[Environment]::SetEnvironmentVariable("Path", (($machinePath -split ";") | Where-Object { $_ -and $_ -ne $InstallDir }) -join ";", "Machine")
if ($Purge) { Remove-Item (Join-Path $env:ProgramData "nandi") -Recurse -Force -ErrorAction SilentlyContinue }
Write-Output "nandi removed"
