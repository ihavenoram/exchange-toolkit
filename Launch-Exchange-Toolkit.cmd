@echo off
REM ===========================================================================
REM  Exchange GUI Tool - launcher
REM
REM  -STA is REQUIRED: WinForms is unreliable in a multi-threaded apartment,
REM  and the failure is intermittent rather than obvious.
REM
REM  powershell.exe is called by FULL PATH. cmd.exe searches the current
REM  folder before PATH, so a bare name would run a powershell.exe planted
REM  beside this file.
REM
REM  conhost.exe is forced as the console host. On Windows 11 a normal
REM  console goes to Windows Terminal, and a Terminal window cannot be hidden
REM  by handle - the script's own console-hiding would do nothing. (Exchange
REM  servers use conhost anyway; this matters when run from a workstation.)
REM
REM  Run it elevated on the server: VSS, shadow copies, the Security log and
REM  IIS need it. The tool has a "Restart as administrator" button otherwise.
REM
REM  -ExecutionPolicy Bypass is kept to this launcher only, so the tool runs on
REM  an unknown server and on a file carrying a mark-of-the-web.
REM
REM  Pass -NoHideConsole to watch the console while it runs.
REM ===========================================================================
setlocal
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

echo.%*| find /i "NoHideConsole" >nul && goto :visible

if not exist "%SystemRoot%\System32\conhost.exe" goto :nohost
start "" "%SystemRoot%\System32\conhost.exe" "%PSEXE%" -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Exchange-Toolkit.ps1" %*
goto :done

:nohost
start "" "%PSEXE%" -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Exchange-Toolkit.ps1" %*
goto :done

:visible
"%PSEXE%" -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Exchange-Toolkit.ps1" %*
if errorlevel 1 pause

:done
endlocal
