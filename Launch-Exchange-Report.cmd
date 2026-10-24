@echo off
REM ===========================================================================
REM  Exchange GUI Tool - HTML report generator launcher
REM
REM  Same rules as Launch-Exchange-Toolkit.cmd: powershell.exe by FULL PATH
REM  (cmd.exe searches the current folder first), -STA for WinForms, conhost
REM  so the console can be hidden on Windows 11, and -ExecutionPolicy Bypass
REM  kept to this launcher only. The script hides its own console by handle;
REM  -WindowStyle Hidden is not used because on some hosts it hides the form
REM  too.
REM
REM  No admin rights needed: it only reads a JSON file and writes HTML.
REM  Pass -NoHideConsole to watch the console.
REM ===========================================================================
setlocal
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%SystemRoot%\System32\conhost.exe" goto :nohost
start "" "%SystemRoot%\System32\conhost.exe" "%PSEXE%" -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Generate-ExchangeReport.ps1" %*
goto :done

:nohost
start "" "%PSEXE%" -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Generate-ExchangeReport.ps1" %*

:done
endlocal
