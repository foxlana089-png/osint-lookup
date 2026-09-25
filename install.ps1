# OSINT-Lookup - Remote-Installer
# Aufruf (PowerShell):
#   irm https://github.com/foxlana089-png/osint-lookup/releases/latest/download/install.ps1 | iex
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo  = "foxlana089-png/osint-lookup"
$asset = "osint-lookup.zip"
$dest  = Join-Path $env:LOCALAPPDATA "OSINT-Lookup"
$tmp   = Join-Path $env:TEMP "osint-lookup.zip"

function Step($text) { Write-Host ("  " + $text) -ForegroundColor Cyan }

Write-Host ""
Write-Host "  OSINT-Lookup - Installation" -ForegroundColor Magenta
Write-Host ""

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "  [X] Python nicht gefunden." -ForegroundColor Red
    Write-Host "      https://www.python.org/downloads/  (Haken: Add to PATH)"
    return
}

Step "1/3  Download $asset"
Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest/download/$asset" -OutFile $tmp

Step "2/3  Entpacken nach $dest"
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
New-Item -ItemType Directory -Path $dest | Out-Null
Expand-Archive -Path $tmp -DestinationPath $dest -Force
Remove-Item $tmp -Force

Step "3/3  Abhaengigkeiten (phonenumbers, tzdata) + Desktop-Link"
& python -m pip install --quiet --disable-pip-version-check phonenumbers tzdata

$lnk = (New-Object -ComObject WScript.Shell).CreateShortcut(
    (Join-Path ([Environment]::GetFolderPath('Desktop')) "osint.lnk"))
$lnk.TargetPath         = "$env:ComSpec"
$lnk.Arguments          = '/k ""{0}\start.bat""' -f $dest
$lnk.WorkingDirectory   = $dest
$lnk.Description        = "OSINT-Lookup"
$lnk.Save()

Write-Host ""
Write-Host "  [OK] Fertig - Desktop-Link 'osint' startet das Tool." -ForegroundColor Green
Write-Host "      Ziel: $dest"
Write-Host ""
Start-Process (Join-Path ([Environment]::GetFolderPath('Desktop')) "osint.lnk")
