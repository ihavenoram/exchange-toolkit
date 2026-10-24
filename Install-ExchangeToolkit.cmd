@echo off
REM ===========================================================================
REM  Exchange GUI Tool - installer
REM
REM  Double-click to install. Copies the toolkit to C:\Scripts (created if
REM  missing) and puts an "Exchange GUI Tool" shortcut, with its icon and set
REM  to run as administrator, on the all-users desktop. Run it again to
REM  update: the files are replaced and the shortcut rewritten.
REM
REM  Asks for administrator rights itself (C:\ and the all-users desktop
REM  need them). powershell.exe is called by FULL PATH: cmd.exe searches the
REM  current folder first.
REM ===========================================================================
setlocal
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "ETK_SELF=%~f0"

"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 (
    echo Administrator rights are needed - asking Windows for them...
    "%PSEXE%" -NoProfile -Command "Start-Process -FilePath $env:ETK_SELF -Verb RunAs"
    exit /b
)

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-ExchangeToolkit.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
