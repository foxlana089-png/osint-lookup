@echo off
chcp 65001 >nul
setlocal
title OSINT-Lookup - Installation
cd /d "%~dp0"

echo.
echo   OSINT-Lookup wird installiert ...
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo   [X] Python nicht gefunden. Bitte Python 3 installieren:
  echo       https://www.python.org/downloads/
  echo       Haken bei "Add python.exe to PATH" setzen, dann dieses
  echo       Fenster noch einmal ausfuehren.
  echo.
  pause
  exit /b 1
)

echo   [1/3] Abhaengigkeiten: phonenumbers, tzdata
python -m pip install --quiet --disable-pip-version-check phonenumbers tzdata
if errorlevel 1 (
  echo   [X] pip-Installation fehlgeschlagen - Verbindung pruefen.
  echo.
  pause
  exit /b 1
)

echo   [2/3] Kurztest ...
python -c "import phonenumbers; import osint" >nul 2>nul
if errorlevel 1 (
  echo   [X] Test fehlgeschlagen - osint.py pruefen.
  echo.
  pause
  exit /b 1
)

echo   [3/3] Desktop-Verknuepfung "osint" wird erstellt
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Desktop')+'\osint.lnk');$s.TargetPath='%~dp0start.bat';$s.WorkingDirectory='%~dp0';$s.Description='OSINT-Lookup';$s.Save()"

echo.
echo   [OK] Fertig - Doppelklick auf den Desktop-Link "osint" startet das Tool.
echo        Alternativ: start.bat   oder   python osint.py ip 1.1.1.1
echo.
pause
exit /b 0
