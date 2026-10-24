# Exchange GUI Tool 1.2.2 - https://ihavenoram.com - https://github.com/ihavenoram/exchange-toolkit
# MIT licence, (c) 2026 ihavenoram.com. If you publish something built on this, please credit ihavenoram.com.
#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the Exchange GUI Tool to C:\Scripts and puts a shortcut on the
    all-users desktop. Started by Install-ExchangeToolkit.cmd.

.DESCRIPTION
    Copies the toolkit, the HTML report generator, their launchers and the
    icon to the destination folder (created if missing), checks each copy
    against its source, and writes "Exchange GUI Tool.lnk" to the all-users
    desktop: target Launch-Exchange-Toolkit.cmd, the toolkit icon, and the
    "Run as administrator" flag set, because most checks need elevation.

    Running it again updates the files in place and rewrites the shortcut.

    -Destination, -Desktop, -NoElevationCheck and -Force exist so the test
    suite can install into temporary folders without admin rights.
#>
param(
    [string]$Destination = 'C:\Scripts',
    [string]$Desktop = '',
    [switch]$NoElevationCheck,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot
$files = @('Exchange-Toolkit.ps1', 'Launch-Exchange-Toolkit.cmd', 'Generate-ExchangeReport.ps1', 'Launch-Exchange-Report.cmd', 'ExchangeToolkit.ico')
$shortcutName = 'Exchange GUI Tool.lnk'

function Write-Step { param([string]$Text) Write-Host ('  ' + $Text) }

try {
    Write-Host ''
    Write-Host 'Exchange GUI Tool installer' -ForegroundColor Cyan
    Write-Host ''

    if (-not $NoElevationCheck) {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'This needs administrator rights. Run Install-ExchangeToolkit.cmd, which asks for them.'
        }
    }

    $missing = @($files | Where-Object { -not (Test-Path -LiteralPath (Join-Path $src $_)) })
    if ($missing.Count) { throw ('These files are missing next to the installer ({0}): {1}' -f $src, ($missing -join ', ')) }

    # An existing folder that a standard user owns could have its scripts
    # swapped for something else - which an administrator then runs elevated.
    if (Test-Path -LiteralPath $Destination) {
        $owner = (Get-Acl -LiteralPath $Destination).Owner
        if ($owner -notin @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'NT SERVICE\TrustedInstaller') -and -not $Force) {
            Write-Warning ('{0} already exists and is owned by {1}.' -f $Destination, $owner)
            Write-Warning 'If that account is not an administrator, it can change scripts that administrators run elevated.'
            $answer = Read-Host '  Install there anyway? (Y/N)'
            if ($answer -notmatch '^(y|yes)$') { Write-Host '  Nothing was changed.'; exit 2 }
        }
    } else {
        [void](New-Item -ItemType Directory -Path $Destination -Force)
        Write-Step ('Created {0}' -f $Destination)
    }

    foreach ($f in $files) {
        $from = Join-Path $src $f
        $to = Join-Path $Destination $f
        $existed = Test-Path -LiteralPath $to
        Copy-Item -LiteralPath $from -Destination $to -Force
        try { Unblock-File -LiteralPath $to } catch { }
        if ((Get-FileHash -LiteralPath $from).Hash -ne (Get-FileHash -LiteralPath $to).Hash) { throw ('The copy of {0} does not match the original.' -f $f) }
        Write-Step ('{0} {1}' -f $(if ($existed) { 'Updated' } else { 'Copied ' }), $to)
    }

    if (-not $Desktop) { $Desktop = [Environment]::GetFolderPath('CommonDesktopDirectory') }
    if (-not (Test-Path -LiteralPath $Desktop)) { throw ('The all-users desktop folder was not found ({0}).' -f $Desktop) }
    $lnk = Join-Path $Desktop $shortcutName
    $shell = New-Object -ComObject WScript.Shell
    try {
        $sc = $shell.CreateShortcut($lnk)
        $sc.TargetPath = Join-Path $Destination 'Launch-Exchange-Toolkit.cmd'
        $sc.WorkingDirectory = $Destination
        $sc.IconLocation = ('{0},0' -f (Join-Path $Destination 'ExchangeToolkit.ico'))
        $sc.Description = 'Exchange GUI Tool - Exchange Server health, mail flow, storage and security checks'
        $sc.WindowStyle = 7     # the launcher's own console starts minimised; the tool hides it
        $sc.Save()
    } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    # "Run as administrator": bit 0x20 of the shell link's flags byte at 0x15.
    $bytes = [IO.File]::ReadAllBytes($lnk)
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [IO.File]::WriteAllBytes($lnk, $bytes)
    Write-Step ('Shortcut  {0} (runs as administrator)' -f $lnk)

    Write-Host ''
    Write-Host ('Installed. Double-click "Exchange GUI Tool" on the desktop. Reports and logs go to {0}.' -f (Join-Path $Destination 'Output')) -ForegroundColor Green
    exit 0
} catch {
    Write-Host ''
    Write-Host ('Install failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
