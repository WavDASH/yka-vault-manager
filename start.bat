@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0dist\portable-1.1.0\YkaVaultManager\YkaVaultManager.exe" (
  start "" "%~dp0dist\portable-1.1.0\YkaVaultManager\YkaVaultManager.exe"
  exit /b 0
)
set "PYTHONPATH=%~dp0src"
if exist "%~dp0.tools\python313\pythonw.exe" (
  start "" "%~dp0.tools\python313\pythonw.exe" -m yka.gui
  exit /b 0
)
if exist "%~dp0.venv\Scripts\pythonw.exe" (
  start "" "%~dp0.venv\Scripts\pythonw.exe" -m yka.gui
  exit /b 0
)
echo Prepare Python dependencies and run scripts\build.ps1 first.
pause
exit /b 1
