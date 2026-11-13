# Intune detection rule for the Win32 app: installed when nandi.exe runs and
# reports the expected version (pass it as the first argument, or leave it
# out to accept any version).
param([string]$Version)
$exe = Join-Path $env:ProgramFiles "nandi\nandi.exe"
if (-not (Test-Path $exe)) { exit 1 }
$out = & $exe version 2>$null
if ($LASTEXITCODE -ne 0) { exit 1 }
if ($Version -and ($out -notmatch [regex]::Escape($Version.TrimStart("v")))) { exit 1 }
Write-Output $out
exit 0
