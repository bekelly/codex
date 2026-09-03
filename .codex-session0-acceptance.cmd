@echo off
setlocal
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\ProgramData\BayshoreLabs\CodexSession0UserProbe\acceptance.ps1"
set "acceptance_exit=%ERRORLEVEL%"
exit /b %acceptance_exit%
