<#
    Exchange Toolkit - on-premises Exchange Server checks (WinForms)
    ----------------------------------------------------------------
    A single-file tool for Windows PowerShell 5.1, built to be run ON an
    Exchange server (or against one from a workstation) when "email is slow",
    "mail flow stopped" or "Outlook keeps prompting".

    It exists because of a real case. A single Exchange 2019 server that was
    also the only domain controller needed restarting every morning. Mail flow,
    queues and back pressure all looked healthy. Two days of one-off commands
    eventually showed the cause was on the disk path, not in Exchange:
      * EDR rollback snapshots every 4 hours, plus "Previous Versions" tasks
        snapshotting the DATABASE volume at 07:00 - inside the morning rush
      * three backup products' filter drivers in every disk write
      * a file-level backup agent trying to copy the live .edb all day
      * the Exchange VSS writer stuck on "Retryable error"
      * event logs so small the Security log covered under a day
    None of that is visible from the Exchange cmdlets. This tool puts those
    checks next to the Exchange ones, so the next case takes minutes.

    Design stance, carried over from the sibling tools (SMTP Toolkit,
    NetSpeed, 3CX Checker):
      * Never invent a plausible answer. A check that could not run says so,
        and why. "Not measured" is its own state, never quietly "OK".
      * Every row says HOW it was arrived at (the Basis column): measured,
        server-reported, inference, registry...
      * Actions are separate from checks. "Run all" never changes anything.
        Every action shows its exact command, needs a confirmation, and is
        written to Output\Actions_<server>.log.

    Launch via Launch-Exchange-Toolkit.cmd (forces -STA, required for WinForms).
    Run elevated on the server: VSS, the Security log and several WMI classes
    need it, and the checks that cannot run without it say so.
#>
[CmdletBinding()]
param(
    # The console is hidden in-process by handle. Pass this to watch it run.
    [switch]$NoHideConsole,

    # Internal. Loads the engine functions and stops before the GUI. Used by
    # the tests, and by the worker runspace to rebuild identical definitions.
    [switch]$EngineOnly
)

#region ENGINE
# ===========================================================================
#  Everything between the ENGINE markers is extracted as text at startup and
#  re-created inside the worker runspace AND, for a remote target, inside an
#  Invoke-Command session on the Exchange server. So:
#    * nothing in here may touch WinForms or a $script: variable of the UI
#    * an OS-level check must return plain data only (strings, numbers,
#      ISO timestamps) - it may be serialised across a remoting boundary
#    * an OS-level check must never call an Exchange cmdlet, because over
#      Invoke-Command that would be a second hop with no credentials
# ===========================================================================

function Get-EtkVersion { '1.2.0' }

function Get-EtkJsonMarkers { @{ Begin = '<<<ETK_JSON_BEGIN>>>'; End = '<<<ETK_JSON_END>>>' } }

# ---------------------------------------------------------------------------
#  Result model
#
#  Ported from the SMTP Toolkit (which took it from NetSpeed). 'basis' says
#  HOW a result was arrived at. A section that did not run must record WHY.
#
#  One addition: a row may carry 'actions' - references to entries in the
#  action catalogue that make sense for that row (retry THIS queue, disable
#  THIS task). A row never runs anything itself; the GUI only offers them.
# ---------------------------------------------------------------------------

function New-EtkRow {
    param(
        [string]$Group,
        [string]$Check,
        [string]$Result,
        [ValidateSet('measured','server-reported','inference','registry','not measured','withheld')]
        [string]$Basis = 'measured',
        [ValidateSet('ok','warn','fail','info')][string]$Status = 'info',
        [string]$Detail = '',
        [object[]]$Actions = @()
    )
    [pscustomobject]@{
        group   = $Group
        check   = $Check
        result  = $Result
        basis   = $Basis
        status  = $Status
        detail  = $Detail
        actions = [object[]]@($Actions | Where-Object { $_ })
    }
}

function New-EtkActionRef {
    # What a row offers. 'args' must be plain strings: the reference travels
    # through JSON and, for a remote target, through remoting.
    param([string]$Id, [hashtable]$Arguments = @{}, [string]$Label = '')
    $a = [ordered]@{}
    foreach ($k in $Arguments.Keys) { $a[$k] = [string]$Arguments[$k] }
    [pscustomobject]@{ id = $Id; args = [pscustomobject]$a; label = $Label }
}

function New-EtkSection {
    param(
        [ValidateSet('measured','failed','skipped','unsupported')]
        [string]$State,
        [string]$Reason      = '',
        [string]$Method      = '',
        [string[]]$Caveats   = @(),
        $Rows                = @(),
        $Data                = $null,
        [datetime]$StartedUtc = [datetime]::MinValue,
        [double]$DurationSec  = 0
    )
    if ($State -ne 'measured' -and [string]::IsNullOrWhiteSpace($Reason)) {
        $Reason = 'No reason recorded - this is a bug in the tool, not a finding about the server.'
    }
    $started = $null
    if ($StartedUtc -ne [datetime]::MinValue) { $started = ConvertTo-EtkIso8601 $StartedUtc }
    $reasonVal = $null
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $reasonVal = $Reason }

    [pscustomobject]@{
        state       = $State
        reason      = $reasonVal
        startedUtc  = $started
        durationSec = [math]::Round($DurationSec, 2)
        method      = $Method
        caveats     = [object[]]$Caveats
        rows        = [object[]]@($Rows | Where-Object { $_ })
        data        = $Data
    }
}

function Set-EtkSectionTiming {
    param($Section, [datetime]$StartedUtc, [double]$DurationSec)
    if (-not $Section) { return $Section }
    try {
        $Section.startedUtc  = ConvertTo-EtkIso8601 $StartedUtc
        $Section.durationSec = [math]::Round($DurationSec, 2)
    } catch { }
    return $Section
}

function New-EtkSubscore {
    param(
        [string]$Name,
        [ValidateSet('green','amber','red','notmeasured')][string]$Level,
        [string]$Summary,
        [string]$Remedy = ''
    )
    [pscustomobject]@{ name = $Name; level = $Level; summary = $Summary; remedy = $Remedy }
}

function Get-EtkHealth {
    # Worst of the MEASURED subscores - never an average and no 0-100 score.
    # 'notmeasured' is always listed but never drags the verdict down.
    param($Subscores)
    $list = @($Subscores | Where-Object { $_ })
    $out = [pscustomobject]@{
        overall   = 'notmeasured'
        headline  = 'Nothing was measured.'
        subscores = [object[]]$list
        notes     = [object[]]@()
    }
    if ($list.Count -eq 0) { return $out }

    $measured = @($list | Where-Object { $_.level -ne 'notmeasured' })
    if ($measured.Count -eq 0) {
        $out.headline = 'No check produced a usable result. See each section''s reason.'
        return $out
    }

    $rank  = @{ 'green' = 0; 'amber' = 1; 'red' = 2 }
    $worst = $measured[0]
    foreach ($s in $measured) {
        if ($rank[$s.level] -gt $rank[$worst.level]) { $worst = $s }
    }
    $out.overall = $worst.level
    if ($worst.level -eq 'green') {
        $out.headline = 'Nothing measured here points at a problem on this server.'
    } else {
        $out.headline = ('{0}: {1}' -f $worst.name, $worst.summary)
    }

    $notMeasured = @($list | Where-Object { $_.level -eq 'notmeasured' } | ForEach-Object { $_.name })
    if ($notMeasured.Count -gt 0) {
        $out.notes = [object[]]@(('Not measured, and therefore not counted either way: {0}.' -f ($notMeasured -join ', ')))
    }
    return $out
}

function Get-EtkKnownLimits {
    # Published false negatives. A clean run is a statement about this server,
    # at this moment - not a promise.
    [object[]]@(
        'Every check is a snapshot. A problem that only appears at 07:00 (a scheduled snapshot, a backup job, the morning login rush) will not show in a run at 14:00 - use the Schedule timeline and the Evidence tab''s perf capture for time-of-day problems.',
        'Third-party products are identified from service names and driver file metadata. A product name in the Basis "inference" column is a best match, not a certificate of what is installed.',
        'Antivirus/EDR exclusions cannot be read from outside the product. The tool cannot tell you whether the Exchange folders are excluded - check the product''s own console.',
        'The VSS writer check parses English vssadmin output. On another display language it reports "unsupported" rather than guessing.',
        'Message tracking is capped (see the section). On a busy server a long window may only cover part of the period; the section says when the cap was hit.',
        'Disk latency is a 10-second sample. It shows whether the disks are struggling NOW, not whether they struggled this morning.',
        'Security sees the server''s own firewall, not the router: a port open here is only reachable from the internet if the router forwards it, and the router''s forwards cannot be read from the server. Behind NAT, a reverse proxy or an RD Gateway, a source address may be the router''s or the gateway''s.'
    )
}

# ---------------------------------------------------------------------------
#  Small conversions and formatting
# ---------------------------------------------------------------------------

function ConvertTo-EtkIso8601 {
    # ConvertTo-Json renders [datetime] as /Date(...)/ - every timestamp is
    # pre-formatted as a string instead.
    param($When)
    if ($null -eq $When) { return $null }
    try { $d = [datetime]$When } catch { return $null }
    if ($d -eq [datetime]::MinValue) { return $null }
    return $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function ConvertTo-EtkLocalStamp {
    # For display: local time, which is what a technician compares with
    # "the problem happens at 7".
    param($When)
    if ($null -eq $When) { return '' }
    try { $d = [datetime]$When } catch { return '' }
    if ($d -eq [datetime]::MinValue) { return '' }
    return $d.ToLocalTime().ToString('yyyy-MM-dd HH:mm')
}

function Format-EtkBytes {
    param($Bytes)
    if ($null -eq $Bytes) { return 'unknown' }
    $b = [double]$Bytes
    if ($b -ge 1TB) { return ('{0:N2} TB' -f ($b / 1TB)) }
    if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) }
    if ($b -ge 1MB) { return ('{0:N0} MB' -f ($b / 1MB)) }
    if ($b -ge 1KB) { return ('{0:N0} KB' -f ($b / 1KB)) }
    return ('{0:N0} bytes' -f $b)
}

function Format-EtkAge {
    param([timespan]$Span)
    if ($Span.TotalMinutes -lt 1) { return 'under a minute' }
    if ($Span.TotalHours -lt 1)   { return ('{0} min' -f [int]$Span.TotalMinutes) }
    if ($Span.TotalDays -lt 2)    { return ('{0:N1} h' -f $Span.TotalHours) }
    return ('{0:N1} days' -f $Span.TotalDays)
}

function Format-EtkSeconds {
    # Sub-second deliveries are normal on a healthy server; "0 s" hides that
    # anything was measured at all.
    param($Seconds)
    if ($null -eq $Seconds) { return 'n/a' }
    $s = [double]$Seconds
    if ($s -lt 10) { return ('{0:N1} s' -f $s) }
    if ($s -lt 120) { return ('{0:N0} s' -f $s) }
    return ('{0:N1} min' -f ($s / 60))
}

function Convert-EtkByteQuantity {
    # Exchange size values arrive as ByteQuantifiedSize locally but as a
    # STRING through remoting ("233.1 GB (250,301,382,656 bytes)"), where
    # .ToBytes() does not exist. Parsing the string works for both.
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = [string]$Value
    $m = [regex]::Match($s, '\(([\d,\.\s]+)\s*bytes\)')
    if ($m.Success) {
        $digits = ($m.Groups[1].Value -replace '[^\d]', '')
        if ($digits) { return [double]$digits }
    }
    if ($s -match '^\s*\d+\s*$') { return [double]$s }
    return $null
}

function ConvertTo-EtkTimeSpan {
    # TimeSpan values may arrive as TimeSpan, as "00:15:00", or as "1.00:00:00".
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [timespan]) { return $Value }
    $t = [timespan]::Zero
    if ([timespan]::TryParse([string]$Value, [ref]$t)) { return $t }
    return $null
}

function Get-EtkPercentile {
    param([double[]]$Values, [double]$P)
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { return $null }
    $idx = [math]::Ceiling(($P / 100.0) * $v.Count) - 1
    if ($idx -lt 0) { $idx = 0 }
    if ($idx -ge $v.Count) { $idx = $v.Count - 1 }
    return $v[$idx]
}

function Get-EtkFirstLine {
    param([string]$Text, [int]$Max = 220)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $line = ($Text -split "`r?`n")[0].Trim()
    if ($line.Length -gt $Max) { $line = $line.Substring(0, $Max) + '...' }
    return $line
}

function Get-EtkRegValue {
    # Raw registry API rather than the provider: faster, and it behaves the
    # same under SYSTEM in session 0 and inside a remoting session.
    param([string]$Path, [string]$Name)
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path)
        if (-not $k) { return $null }
        try { return $k.GetValue($Name) } finally { $k.Close() }
    } catch { return $null }
}

function Test-EtkElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Invoke-EtkNative {
    # Native tools (vssadmin, logman, wevtutil, appcmd) under a local
    # 'Continue': under 'Stop', ANY stderr line throws even with 2>$null
    # (house trap). The exit code is what decides success.
    param([string]$FilePath, [string[]]$ArgumentList = @())
    $ErrorActionPreference = 'Continue'
    $out = & $FilePath @ArgumentList 2>&1
    $code = $LASTEXITCODE
    $lines = @($out | ForEach-Object { [string]$_ })
    [pscustomobject]@{ exitCode = $code; output = ($lines -join [Environment]::NewLine); lines = [object[]]$lines }
}

function Get-EtkSystemTool {
    # Full paths only: a bare name can resolve to a planted copy in the
    # current folder.
    param([string]$Name)
    $p = Join-Path $env:SystemRoot ('System32\' + $Name)
    if (Test-Path -LiteralPath $p) { return $p }
    return $null
}

# ---------------------------------------------------------------------------
#  Host context and target
# ---------------------------------------------------------------------------

function Get-EtkHostContext {
    $cs = $null
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }
    $fqdn = $env:COMPUTERNAME
    try { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { }
    $exPath = Get-EtkRegValue 'SOFTWARE\Microsoft\ExchangeServer\v15\Setup' 'MsiInstallPath'
    $isSystem = $false
    try { $isSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem } catch { }
    [pscustomobject]@{
        computerName      = $env:COMPUTERNAME
        fqdn              = $fqdn
        domain            = $(if ($cs) { [string]$cs.Domain } else { '' })
        runAs             = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        elevated          = (Test-EtkElevated)
        isSystem          = $isSystem
        psVersion         = $PSVersionTable.PSVersion.ToString()
        timeZone          = [System.TimeZoneInfo]::Local.Id    # so the HTML report shows server time, wherever it is built
        exchangeInstalled = (-not [string]::IsNullOrWhiteSpace([string]$exPath))
        exchangeInstallPath = [string]$exPath
    }
}

function Test-EtkIsLocalTarget {
    param([string]$Server)
    if ([string]::IsNullOrWhiteSpace($Server)) { return $true }
    $s = $Server.Trim().ToLowerInvariant()
    if ($s -in @('.', 'localhost', '127.0.0.1', '::1')) { return $true }
    $short = $s.Split('.')[0]
    return ($short -eq $env:COMPUTERNAME.ToLowerInvariant())
}

function Get-EtkTarget {
    # The worker keeps the current target in a global, because the same
    # persistent runspace serves every job.
    if (-not $global:EtkTarget) {
        $global:EtkTarget = [pscustomobject]@{
            name = $env:COMPUTERNAME; fqdn = $env:COMPUTERNAME; isLocal = $true
            exchange = 'none'; exchangeDetail = 'Not connected yet - press Connect.'
            exchangeServer = $null; version = $null
        }
    }
    return $global:EtkTarget
}

function Invoke-EtkOs {
    # Runs an OS-level engine function on the target: directly when it is
    # this machine, otherwise through Invoke-Command with the engine text
    # shipped along, so both paths run the SAME code.
    param([Parameter(Mandatory)][string]$Name, [hashtable]$Parameters = @{})
    $t = Get-EtkTarget
    if ($t.isLocal) { return & $Name @Parameters }
    if ([string]::IsNullOrWhiteSpace($global:EtkEngineSource)) {
        throw 'The engine source is not available to ship to the remote server.'
    }
    $sb = {
        param($src, $fn, $p)
        . ([scriptblock]::Create($src))
        & $fn @p
    }
    return Invoke-Command -ComputerName $t.fqdn -ScriptBlock $sb -ArgumentList $global:EtkEngineSource, $Name, $Parameters -ErrorAction Stop
}

function Invoke-EtkOsSection {
    # Invoke-EtkOs for a function that returns a section: a remoting failure
    # becomes a 'failed' section with the reason instead of a thrown error.
    param([string]$Name, [hashtable]$Parameters = @{}, [string]$Group = '')
    $t0 = [datetime]::UtcNow
    try {
        $r = Invoke-EtkOs -Name $Name -Parameters $Parameters
        return $r
    } catch {
        $msg = $_.Exception.Message
        return (New-EtkSection -State failed -Reason ('Could not run on {0}: {1}' -f (Get-EtkTarget).name, $msg) -StartedUtc $t0 `
            -Rows @(New-EtkRow -Group $Group -Check 'Remote execution' -Result 'FAILED' -Basis 'not measured' -Status 'fail' -Detail $msg))
    }
}

# ---------------------------------------------------------------------------
#  Exchange connection
#
#  Preferred: a remote PowerShell session to http://<fqdn>/PowerShell/ with
#  Kerberos - the supported route, identical locally and from a workstation.
#  Only the cmdlets this tool uses are imported (seconds instead of a minute).
#
#  Fallback, ON the server only: the management snap-in. It bypasses RBAC and
#  is not supported for administration, so the section that used it says so.
#
#  The session is removed when the tool closes. An idle Exchange session left
#  open keeps long-polling /PowerShell (3-minute requests in the IIS log) and
#  produces MSExchange RBAC 74 "connection leak" events - both were seen on
#  the server this tool was built for.
# ---------------------------------------------------------------------------

function Get-EtkExchangeCommandList {
    @(
        'Get-ExchangeServer','Test-ServiceHealth','Get-ServerComponentState','Set-ServerComponentState',
        'Get-MailboxDatabase','Get-MailboxDatabaseCopyStatus','Mount-Database',
        'Get-ExchangeCertificate','Get-AuthConfig',
        'Get-Queue','Retry-Queue','Suspend-Queue','Resume-Queue',
        'Get-ExchangeDiagnosticInfo','Get-MessageTrackingLog','Get-TransportService',
        'Get-ReceiveConnector','Get-SendConnector'
    )
}

function Test-EtkExchangeAvailable {
    return [bool](Get-Command -Name 'Get-ExchangeServer' -ErrorAction SilentlyContinue)
}

function Get-EtkConnectPlan {
    # Pure. Which connection methods to try, in order, and why.
    #
    # Running as SYSTEM (ScreenConnect Backstage, an RMM) changes the answer:
    # remote PowerShell and Invoke-Command both sign in as the COMPUTER
    # account, which Exchange's /PowerShell endpoint normally refuses and
    # which has no admin rights on other servers. So under SYSTEM the snap-in
    # is the only route, and only on the Exchange server itself. Trying
    # remote PowerShell first would just add a wait before the same failure.
    param([bool]$IsSystem, [bool]$IsLocal, [bool]$AllowSnapin)
    $methods = @(); $notes = @()
    if (-not $IsSystem) {
        $methods += 'session'
        if ($IsLocal -and $AllowSnapin) { $methods += 'snapin' }
    } elseif (-not $IsLocal) {
        $notes += 'Running as SYSTEM cannot reach another server: Exchange remote PowerShell and Invoke-Command would both sign in as this computer''s account, which has no rights there. Run the tool on that server, or as your own account.'
    } elseif ($AllowSnapin) {
        $methods += 'snapin'
        $notes += 'Running as SYSTEM: remote PowerShell would sign in as the computer account, which Exchange normally refuses, so it is skipped and the management snap-in is used.'
    } else {
        $methods += 'session'
        $notes += 'Running as SYSTEM with the snap-in fallback turned off: remote PowerShell is tried, but it usually fails under SYSTEM. Tick "Allow snap-in fallback" if it does.'
    }
    [pscustomobject]@{ methods = [object[]]$methods; notes = [object[]]$notes }
}

function Connect-EtkExchange {
    param([string]$Server, [switch]$AllowSnapin)
    $t = Get-EtkTarget
    $t.name    = $(if ([string]::IsNullOrWhiteSpace($Server)) { $env:COMPUTERNAME } else { $Server.Trim() })
    $t.isLocal = (Test-EtkIsLocalTarget $t.name)
    $t.fqdn    = $t.name
    try { $t.fqdn = [System.Net.Dns]::GetHostEntry($t.name).HostName } catch { }
    $t.exchange = 'none'; $t.exchangeServer = $null; $t.version = $null

    Disconnect-EtkExchange

    $notes = New-Object System.Collections.Generic.List[string]
    $isSystem = $false
    try { $isSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem } catch { }
    $plan = Get-EtkConnectPlan -IsSystem $isSystem -IsLocal $t.isLocal -AllowSnapin ([bool]$AllowSnapin)
    foreach ($n in $plan.notes) { $notes.Add($n) }

    foreach ($method in $plan.methods) {
        if ($t.exchange -ne 'none') { break }
        if ($method -eq 'session') {
            try {
                $uri = ('http://{0}/PowerShell/' -f $t.fqdn)
                $s = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $uri -Authentication Kerberos -ErrorAction Stop
                $global:EtkExchangeSession = $s
                $mod = Import-PSSession -Session $s -CommandName (Get-EtkExchangeCommandList) -DisableNameChecking -AllowClobber -ErrorAction Stop
                Import-Module $mod -Global -DisableNameChecking -ErrorAction Stop
                $t.exchange = 'session'
                $t.exchangeDetail = ('Remote PowerShell session to {0}' -f $uri)
            } catch {
                $notes.Add(('Remote PowerShell to {0} failed: {1}' -f $t.fqdn, $_.Exception.Message))
                Disconnect-EtkExchange
            }
        } elseif ($method -eq 'snapin') {
            try {
                Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
                $t.exchange = 'snapin'
                $t.exchangeDetail = $(if ($isSystem) { 'Local management snap-in (running as SYSTEM; bypasses RBAC)' } else { 'Local management snap-in (fallback; bypasses RBAC)' })
            } catch {
                $notes.Add(('Snap-in failed: {0}' -f $_.Exception.Message))
            }
        }
    }

    if ($t.exchange -ne 'none') {
        try {
            $ex = Get-ExchangeServer -Identity $t.name.Split('.')[0] -ErrorAction Stop
            $t.exchangeServer = [string]$ex.Name
            $t.version = [string]$ex.AdminDisplayVersion
        } catch {
            $notes.Add(('Connected, but Get-ExchangeServer for {0} failed: {1}' -f $t.name, $_.Exception.Message))
        }
    } else {
        $t.exchangeDetail = ($notes -join ' | ')
        if (-not $t.exchangeDetail) { $t.exchangeDetail = 'Exchange cmdlets are not available.' }
    }
    [pscustomobject]@{
        target = $t.name; fqdn = $t.fqdn; isLocal = $t.isLocal; exchange = $t.exchange
        detail = $t.exchangeDetail; exchangeServer = $t.exchangeServer; version = $t.version
        notes = [object[]]$notes.ToArray()
    }
}

function Disconnect-EtkExchange {
    if ($global:EtkExchangeSession) {
        try { Remove-PSSession -Session $global:EtkExchangeSession -ErrorAction SilentlyContinue } catch { }
        $global:EtkExchangeSession = $null
    }
}

function Get-EtkExchangeUnavailableSection {
    param([string]$Group)
    $t = Get-EtkTarget
    $why = $t.exchangeDetail
    if ([string]::IsNullOrWhiteSpace($why)) { $why = 'Exchange cmdlets are not loaded.' }
    # No rows: the grid already shows a non-measured section as one row with
    # its reason, and a second row saying the same thing is noise.
    New-EtkSection -State unsupported -Reason ('Exchange not available: {0}' -f $why)
}

function Get-EtkExchangeServerName {
    $t = Get-EtkTarget
    if ($t.exchangeServer) { return $t.exchangeServer }
    return $t.name.Split('.')[0]
}

# ===========================================================================
#  OVERVIEW - server facts (OS-level, remote-capable)
# ===========================================================================

function Get-EtkExchangeProduct {
    # Product line from the build. Exchange Server SE RTM is 15.2.2562 - the
    # 2019 line continued with the same major/minor, so the build number is
    # the only discriminator. No SU table on purpose: it would go stale and a
    # stale table invents answers.
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return [pscustomobject]@{ product = 'unknown'; supported = $null; note = 'No version found.' } }
    $v = $null
    try { $v = [version]($Version -replace '[^\d\.]', '') } catch { }
    if (-not $v) { return [pscustomobject]@{ product = 'unknown'; supported = $null; note = ('Could not parse version "{0}".' -f $Version) } }
    if ($v.Major -eq 15 -and $v.Minor -eq 0) { return [pscustomobject]@{ product = 'Exchange 2013'; supported = $false; note = 'Exchange 2013 left support in April 2023.' } }
    if ($v.Major -eq 15 -and $v.Minor -eq 1) { return [pscustomobject]@{ product = 'Exchange 2016'; supported = $false; note = 'Exchange 2016 left support on 14 October 2025. No further public security updates.' } }
    if ($v.Major -eq 15 -and $v.Minor -eq 2) {
        if ($v.Build -ge 2562) { return [pscustomobject]@{ product = 'Exchange Server SE'; supported = $true; note = 'Subscription Edition - supported while its CUs and SUs are kept current.' } }
        return [pscustomobject]@{ product = 'Exchange 2019'; supported = $false; note = 'Exchange 2019 left support on 14 October 2025. The in-place upgrade to Exchange Server SE installs like a CU.' }
    }
    return [pscustomobject]@{ product = ('Exchange {0}' -f $v); supported = $null; note = 'Unrecognised version line.' }
}

function Test-EtkServerFacts {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Server'
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $cpu = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue)

        $rows.Add((New-EtkRow -Group $g -Check 'Windows' -Result ('{0} (build {1})' -f $os.Caption, $os.BuildNumber) -Status 'info'))

        $isVm = ([string]$cs.Model -match 'Virtual|VMware|KVM|HVM|Xen|QEMU' -or [string]$cs.Manufacturer -match 'Microsoft Corporation|VMware|QEMU|Xen')
        $hw = ('{0} {1}' -f $cs.Manufacturer, $cs.Model).Trim()
        $rows.Add((New-EtkRow -Group $g -Check 'Hardware' -Result $hw -Basis 'inference' -Status 'info' `
            -Detail $(if ($isVm) { 'Looks like a virtual machine. Host-level checkpoints, Dynamic Memory and host backups affect it - check them on the host.' } else { 'Looks like physical hardware.' })))

        $isDc = ([int]$cs.DomainRole -ge 4)
        $hyperv = [bool](Get-Service -Name vmms -ErrorAction SilentlyContinue)
        $roles = @()
        if ($isDc) { $roles += 'domain controller' }
        if ($hyperv) { $roles += 'Hyper-V host (vmms service present)' }
        if ($roles.Count -gt 0) {
            $rows.Add((New-EtkRow -Group $g -Check 'Also running' -Result ($roles -join ', ') -Status 'warn' `
                -Detail 'Exchange shares this machine with other roles. On a DC, a compromise of Exchange is a compromise of the domain, and the roles compete for memory and disk. Microsoft discourages both combinations.'))
        } else {
            $rows.Add((New-EtkRow -Group $g -Check 'Also running' -Result 'No domain controller or Hyper-V role found' -Status 'ok'))
        }

        $cores = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
        $logical = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $ram = [double]$cs.TotalPhysicalMemory
        $rows.Add((New-EtkRow -Group $g -Check 'CPU / RAM' -Result ('{0} cores / {1} logical, {2} RAM' -f $cores, $logical, (Format-EtkBytes $ram)) -Status 'info' `
            -Detail $(if ($logical -gt $cores -and -not $isVm) { 'Hyper-Threading is on. Microsoft''s Exchange guidance is to disable it on physical servers.' } else { '' })))

        $boot = $os.LastBootUpTime
        $up = (Get-Date) - $boot
        $rows.Add((New-EtkRow -Group $g -Check 'Last boot' -Result ('{0} (up {1})' -f (ConvertTo-EtkLocalStamp $boot), (Format-EtkAge $up)) -Status 'info'))

        $commitLimit = [double]$os.TotalVirtualMemorySize * 1KB
        $commitFree  = [double]$os.FreeVirtualMemory * 1KB
        $commitPct = $(if ($commitLimit -gt 0) { 100.0 * ($commitLimit - $commitFree) / $commitLimit } else { 0 })
        $st = 'ok'; if ($commitPct -ge 90) { $st = 'fail' } elseif ($commitPct -ge 80) { $st = 'warn' }
        $rows.Add((New-EtkRow -Group $g -Check 'Memory commit' -Result ('{0:N0}% used ({1} free of {2})' -f $commitPct, (Format-EtkBytes $commitFree), (Format-EtkBytes $commitLimit)) -Status $st `
            -Detail 'Commit near its limit means the server is genuinely short of memory; the Exchange store then shrinks its cache and reads more from disk.'))

        $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
        $auto = [bool]$cs.AutomaticManagedPagefile
        if ($pf.Count -gt 0) {
            $alloc = ($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum
            $peak  = ($pf | Measure-Object -Property PeakUsage -Sum).Sum
            $recommended = [math]::Round(($ram / 1MB) * 0.25)
            $st = 'info'
            $det = ('Exchange 2019/SE guidance: a FIXED page file of 25% of RAM (about {0:N0} MB here).' -f $recommended)
            if ($auto) { $st = 'warn'; $det = 'System-managed. ' + $det + ' HealthChecker reports a system-managed page file as "0 MB" - that is not "no page file".' }
            $rows.Add((New-EtkRow -Group $g -Check 'Page file' -Result ('{0:N0} MB allocated, peak use {1:N0} MB{2}' -f $alloc, $peak, $(if ($auto) { ', system-managed' } else { '' })) -Status $st -Detail $det))
        } else {
            $rows.Add((New-EtkRow -Group $g -Check 'Page file' -Result 'None found' -Status 'warn' -Detail 'No page file is in use. Exchange guidance is a fixed page file of 25% of RAM.'))
        }

        # Exchange build from the file on disk - present even when the
        # cmdlets are not, and its date says when the last CU/SU went on.
        $exPath = Get-EtkRegValue 'SOFTWARE\Microsoft\ExchangeServer\v15\Setup' 'MsiInstallPath'
        if ($exPath) {
            $exe = Join-Path $exPath 'bin\ExSetup.exe'
            if (Test-Path -LiteralPath $exe) {
                $fi = Get-Item -LiteralPath $exe
                $ver = $fi.VersionInfo.ProductVersion
                $prod = Get-EtkExchangeProduct $ver
                $age = (Get-Date) - $fi.LastWriteTime
                $st = 'ok'
                if ($prod.supported -eq $false) { $st = 'fail' }
                $rows.Add((New-EtkRow -Group 'Exchange' -Check 'Product' -Result ('{0} ({1})' -f $prod.product, $ver) -Basis 'inference' -Status $st -Detail $prod.note))
                $st = 'ok'; if ($age.TotalDays -gt 180) { $st = 'fail' } elseif ($age.TotalDays -gt 90) { $st = 'warn' }
                # The file date is when Microsoft BUILT the update, not when it
                # was installed (live server: file 12 Sep 2025, installed 16
                # Oct 2025). Build age is what matters for security anyway:
                # it is how old the newest fixes on this server are.
                $rows.Add((New-EtkRow -Group 'Exchange' -Check 'Age of installed build' -Result ('built {0} ({1} ago)' -f $fi.LastWriteTime.ToString('yyyy-MM-dd'), (Format-EtkAge $age)) -Status $st `
                    -Detail 'Date Microsoft built the installed CU/SU (ExSetup.exe), so the newest security fixes on this server are this old. Installation happens later; HealthChecker shows the install date. Security updates ship roughly monthly.'))
            } else {
                $rows.Add((New-EtkRow -Group 'Exchange' -Check 'Product' -Result 'ExSetup.exe not found' -Basis 'not measured' -Status 'warn' -Detail $exe))
            }
        } else {
            $rows.Add((New-EtkRow -Group 'Exchange' -Check 'Product' -Result 'Exchange is not installed on this machine' -Basis 'registry' -Status 'info'))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'CIM Win32_OperatingSystem/ComputerSystem/PageFileUsage, ExSetup.exe file version' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkRestarts {
    # Who restarted the server, and whether it went down cleanly. 1074 names
    # the process and account behind a planned restart (a scheduled task
    # shows as shutdown.exe), 6008 / 41 are unexpected shutdowns.
    param([int]$Days = 14)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Restarts'
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1074, 6008, 41; StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction SilentlyContinue |
            Sort-Object TimeCreated -Descending)
        $oldest = $null
        try { $oldest = (Get-WinEvent -LogName System -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { }
        if ($ev.Count -eq 0) {
            $cov = $(if ($oldest) { ' The System log only reaches back to {0}.' -f (ConvertTo-EtkLocalStamp $oldest) } else { '' })
            $rows.Add((New-EtkRow -Group $g -Check ('Last {0} days' -f $Days) -Result 'No restart events found' -Status 'info' -Detail ('Events 1074, 6008 and 41.' + $cov)))
        }
        $unexpected = 0
        $seen = @{}
        $shown = 0
        foreach ($e in $ev) {
            if ($shown -ge 12) { break }
            $when = ConvertTo-EtkLocalStamp $e.TimeCreated
            switch ($e.Id) {
                1074 {
                    $p = $e.Properties
                    $proc = ''; $user = ''; $reason = ''; $kind = ''
                    try { $proc = [string]$p[0].Value; $reason = [string]$p[2].Value; $kind = [string]$p[4].Value; $user = [string]$p[6].Value } catch { }
                    # A restart from the Start menu logs 1074 twice in the
                    # same second (Explorer.EXE and C:\Windows\Explorer.EXE).
                    $key = ('{0}|{1}|{2}' -f $e.TimeCreated.ToString('yyyyMMddHHmm'), $user, $kind)
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true; $shown++
                    $isTask = ($proc -match 'shutdown\.exe')
                    $rows.Add((New-EtkRow -Group $g -Check $when -Result ('{0} by {1}' -f $kind, $user) -Basis 'server-reported' -Status 'info' `
                        -Detail ('Started by {0}. Reason: {1}{2}' -f $proc, $reason, $(if ($isTask) { ' - shutdown.exe usually means a script or scheduled task.' } else { '' }))))
                }
                6008 {
                    $unexpected++; $shown++
                    $rows.Add((New-EtkRow -Group $g -Check $when -Result 'Unexpected shutdown (6008)' -Basis 'server-reported' -Status 'warn' -Detail (Get-EtkFirstLine $e.Message)))
                }
                41 {
                    $unexpected++; $shown++
                    $rows.Add((New-EtkRow -Group $g -Check $when -Result 'Kernel-Power 41: rebooted without a clean shutdown' -Basis 'server-reported' -Status 'warn' `
                        -Detail 'Power loss, a hard reset, a hang or a bugcheck. The Exchange database will have needed recovery at the next start.'))
                }
            }
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('System log events 1074/6008/41, last {0} days' -f $Days) -Rows $rows.ToArray() `
            -Data ([pscustomobject]@{ unexpected = $unexpected; systemLogOldest = (ConvertTo-EtkIso8601 $oldest) })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

# ===========================================================================
#  HEALTH - OS-level checks
# ===========================================================================

function Test-EtkServices {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Services'
    try {
        # The same set the Fix tab manages, so both tabs list the same services.
        $pat = Get-EtkManagedServicePattern
        $svc = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -match $pat })
        if (@($svc | Where-Object { $_.Name -like 'MSExchange*' }).Count -eq 0) {
            $sw.Stop()
            return Set-EtkSectionTiming (New-EtkSection -State skipped -Reason 'No Exchange services exist on this machine.' -Rows @(
                New-EtkRow -Group $g -Check 'Exchange services' -Result 'None found' -Status 'info')) $t0 $sw.Elapsed.TotalSeconds
        }
        $bad = @($svc | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
        foreach ($s in $bad) {
            $rows.Add((New-EtkRow -Group $g -Check $s.DisplayName -Result ('{0} (start mode Automatic)' -f $s.State) -Status 'fail' `
                -Detail ('{0} should be running. Check the Application log for why it stopped before restarting it.' -f $s.Name) `
                -Actions @(New-EtkActionRef -Id 'svc-restart' -Arguments @{ Name = $s.Name } -Label ('Start / restart {0}' -f $s.Name))))
        }
        $running = @($svc | Where-Object { $_.State -eq 'Running' })
        $rows.Add((New-EtkRow -Group $g -Check 'Exchange and IIS services' -Result ('{0} running, {1} automatic but stopped, {2} total' -f $running.Count, $bad.Count, $svc.Count) `
            -Status $(if ($bad.Count -gt 0) { 'fail' } else { 'ok' })))
        foreach ($name in @('MSExchangeTransport','MSExchangeFrontEndTransport','MSExchangeIS','W3SVC')) {
            $s = $svc | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            if ($s -and $s.State -eq 'Running') {
                $rows.Add((New-EtkRow -Group $g -Check $s.DisplayName -Result 'Running' -Status 'ok' `
                    -Actions @(New-EtkActionRef -Id 'svc-restart' -Arguments @{ Name = $s.Name } -Label ('Restart {0}' -f $s.Name))))
            }
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'CIM Win32_Service (MSExchange*, MSComplianceAudit, HostControllerService, wsbexchange, IIS, WinRM)' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkAppPools {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'IIS app pools'
    $dll = Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
    if (-not (Test-Path -LiteralPath $dll)) {
        return (New-EtkSection -State skipped -Reason 'IIS is not installed on this machine (Microsoft.Web.Administration.dll not found).')
    }
    if (-not (Test-EtkElevated)) {
        return (New-EtkSection -State unsupported -Reason 'Reading IIS application pools needs an elevated session.')
    }
    try {
        [void][Reflection.Assembly]::LoadFrom($dll)
        $sm = New-Object Microsoft.Web.Administration.ServerManager
        try {
            $pools = @($sm.ApplicationPools | Where-Object { $_.Name -like 'MSExchange*' })
            foreach ($p in $pools) {
                $state = 'unknown'
                try { $state = [string]$p.State } catch { }
                $rows.Add((New-EtkRow -Group $g -Check $p.Name -Result $state -Status $(if ($state -eq 'Started') { 'ok' } else { 'fail' }) `
                    -Actions @(New-EtkActionRef -Id 'apppool-recycle' -Arguments @{ Name = $p.Name } -Label ('Recycle {0}' -f $p.Name))))
            }
            if ($pools.Count -eq 0) { $rows.Add((New-EtkRow -Group $g -Check 'MSExchange* pools' -Result 'None found' -Status 'info')) }
        } finally { $sm.Dispose() }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Microsoft.Web.Administration ServerManager' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkDisks {
    param([string[]]$ExchangeVolumes = @())
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Disk space'
    try {
        $vols = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' -ErrorAction Stop | Where-Object { $_.Capacity -gt 0 -and $_.DriveLetter })
        foreach ($v in ($vols | Sort-Object DriveLetter)) {
            $pct = 100.0 * [double]$v.FreeSpace / [double]$v.Capacity
            $st = 'ok'; if ($pct -lt 5) { $st = 'fail' } elseif ($pct -lt 15) { $st = 'warn' }
            $isEx = ($ExchangeVolumes -contains ([string]$v.DriveLetter).ToUpperInvariant())
            $det = ''
            if ($isEx) { $det = 'Holds Exchange data (database, logs or transport queue). Transport back pressure stops accepting mail when this volume runs out of room.' }
            $rows.Add((New-EtkRow -Group $g -Check ('{0} {1}' -f $v.DriveLetter, $v.Label).Trim() -Result ('{0:N1}% free ({1} of {2})' -f $pct, (Format-EtkBytes $v.FreeSpace), (Format-EtkBytes $v.Capacity)) -Status $st -Detail $det))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'CIM Win32_Volume (fixed disks with a drive letter)' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkMemoryCache {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Memory'
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $free = [double]$os.FreePhysicalMemory * 1KB
        $total = [double]$os.TotalVisibleMemorySize * 1KB
        $rows.Add((New-EtkRow -Group $g -Check 'Available RAM' -Result ('{0} of {1}' -f (Format-EtkBytes $free), (Format-EtkBytes $total)) -Status 'info' `
            -Detail 'Exchange deliberately uses most of the RAM for its database cache, so low free memory on its own is normal.'))
        $top = @(Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 6)
        $rows.Add((New-EtkRow -Group $g -Check 'Largest processes' -Result (($top | ForEach-Object { '{0} {1}' -f $_.ProcessName, (Format-EtkBytes $_.WorkingSet64) }) -join ', ') -Status 'info' `
            -Detail 'Anything that is not Exchange (backup agents, SQL Express, AV) is memory the store cannot use for its cache.'))
        try {
            $c = Get-Counter -Counter '\MSExchange Database(*)\Database Cache Size (MB)', '\MSExchange Database(*)\Database Cache % Hit' -ErrorAction Stop
            $samples = @($c.CounterSamples | Where-Object { $_.CookedValue -gt 0 -and $_.InstanceName -notmatch '^_total$' })
            foreach ($s in $samples) {
                $isHit = ($s.Path -match '% Hit')
                $st = 'info'
                if ($isHit) { if ($s.CookedValue -lt 90) { $st = 'warn' } else { $st = 'ok' } }
                $rows.Add((New-EtkRow -Group $g -Check ('{0} - {1}' -f $(if ($isHit) { 'DB cache hit' } else { 'DB cache size' }), $s.InstanceName) `
                    -Result $(if ($isHit) { '{0:N1}%' -f $s.CookedValue } else { '{0:N0} MB' -f $s.CookedValue }) -Status $st `
                    -Detail $(if ($isHit) { 'A healthy store normally serves the high 90s from cache. Lower means more reads from disk.' } else { '' })))
            }
            if ($samples.Count -eq 0) { $rows.Add((New-EtkRow -Group $g -Check 'DB cache counters' -Result 'No non-zero instances' -Basis 'not measured' -Status 'info')) }
        } catch {
            $rows.Add((New-EtkRow -Group $g -Check 'DB cache counters' -Result 'Not available' -Basis 'not measured' -Status 'info' -Detail $_.Exception.Message))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'CIM, Get-Process, MSExchange Database counters' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkLogPreset {
    # The sizes the "Enlarge event logs" action applies. Logs are only ever
    # grown, never shrunk.
    [ordered]@{ Application = 1GB; System = 1GB; Security = 2GB }
}

function Test-EtkEventLogs {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Event log retention'
    $small = $false
    try {
        $preset = Get-EtkLogPreset
        foreach ($name in $preset.Keys) {
            try {
                $l = Get-WinEvent -ListLog $name -ErrorAction Stop
                $oldest = $null
                try { $oldest = (Get-WinEvent -LogName $name -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { }
                $cov = $null; if ($oldest) { $cov = (Get-Date) - $oldest }
                $st = 'ok'
                if ($cov -and $cov.TotalDays -lt 7 -and [double]$l.MaximumSizeInBytes -lt [double]$preset[$name]) { $st = 'warn'; $small = $true }
                $rows.Add((New-EtkRow -Group $g -Check $name -Result ('max {0}, covers {1}' -f (Format-EtkBytes $l.MaximumSizeInBytes), $(if ($cov) { Format-EtkAge $cov } else { 'unknown' })) -Status $st `
                    -Detail $(if ($st -eq 'warn') { 'Under 7 days of history: by the time a problem is reported, the evidence for its start may already be gone.' } else { '' })))
            } catch {
                $rows.Add((New-EtkRow -Group $g -Check $name -Result 'Could not read' -Basis 'not measured' -Status 'info' -Detail $_.Exception.Message))
            }
        }
        if ($small) {
            $rows.Add((New-EtkRow -Group $g -Check 'Enlarge logs' -Result 'Application/System 1 GB, Security 2 GB' -Status 'warn' `
                -Detail 'Grows the logs that are smaller than these sizes; never shrinks one. Takes effect immediately.' `
                -Actions @(New-EtkActionRef -Id 'eventlog-enlarge' -Label 'Enlarge event logs')))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-WinEvent -ListLog and oldest event' -Rows $rows.ToArray() `
            -Caveats @('Reading the Security log needs an elevated session.')) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkEventSignalDefs {
    # The event signals worth counting on an Exchange server. 'match' is an
    # optional message filter, so a generic id (1000 Application Error) only
    # counts when it names an Exchange process.
    @(
        @{ key = 'backpressure'; title = 'Transport back pressure'; log = 'Application'; provider = 'MSExchangeTransport'; ids = @(15004,15005,15006,15007); match = '';
           status = 'fail'; detail = 'Transport stopped or slowed accepting mail because a resource ran short (disk, memory, version buckets). The message names the resource.' }
        @{ key = 'slowio'; title = 'Slow database I/O (ESE)'; log = 'Application'; provider = 'ESE'; ids = @(508,509,510,533); match = '';
           status = 'fail'; detail = 'A database or log write/read took too long - the disks (or something in the disk path) could not keep up.' }
        @{ key = 'crash'; title = 'Exchange process crashes'; log = 'Application'; provider = 'Application Error'; ids = @(1000,1002); match = 'Exchange|EdgeTransport|w3wp|MSExchange|noderunner';
           status = 'fail'; severeMatch = 'EdgeTransport|Store\.Worker|MSExchangeTransport|MSExchangeFrontendTransport|MSExchangeDelivery|MSExchangeSubmission|w3wp';
           detail = 'An Exchange or IIS worker process crashed or hung. A mail-path process (transport, store, IIS) is a problem; a monitoring helper such as MSExchangeHMWorker restarts itself and is worth watching rather than acting on.' }
        @{ key = 'watson'; title = 'Exchange Watson reports'; log = 'Application'; provider = 'MSExchange Common'; ids = @(4999); match = '';
           status = 'warn'; detail = 'An Exchange component hit an unhandled exception. Recurring at the same minute each hour usually means a scheduled service (Mitigation/Flighting) failing, not an outage.' }
        @{ key = 'adaccess'; title = 'AD access problems'; log = 'Application'; provider = 'MSExchange ADAccess'; ids = @(2070,2114,2142,2601,2604); match = '';
           status = 'fail'; detail = 'Exchange had trouble reaching a domain controller or global catalog. Exchange stalls when AD does.' }
        @{ key = 'smtpauth'; title = 'Failed SMTP AUTH logins'; log = 'Application'; provider = 'MSExchangeFrontEndTransport'; ids = @(1035); match = '';
           status = 'warn'; detail = 'Password guessing against a client receive connector (usually 587). Closing the port at the firewall stops it; blocking single IPs does not.' }
        @{ key = 'unclean'; title = 'Unexpected shutdowns'; log = 'System'; provider = ''; ids = @(6008,41); match = '';
           status = 'warn'; detail = 'The server went down without a clean shutdown.' }
    )
}

function Get-EtkSignalCount {
    # Pure: counts and summarises a list of event-like objects (TimeCreated,
    # Id, ProviderName, Message) for one signal definition. Kept separate so
    # it can be tested without an event log.
    param($Events, [hashtable]$Def)
    $list = @($Events | Where-Object {
        ($Def.ids -contains [int]$_.Id) -and
        ([string]::IsNullOrEmpty($Def.provider) -or [string]$_.ProviderName -eq $Def.provider) -and
        ([string]::IsNullOrEmpty($Def.match) -or [string]$_.Message -match $Def.match)
    })
    $first = $null; $last = $null; $sample = ''
    if ($list.Count -gt 0) {
        $sorted = @($list | Sort-Object { [datetime]$_.TimeCreated })
        $first = $sorted[0].TimeCreated; $last = $sorted[-1].TimeCreated
        $sample = Get-EtkFirstLine ([string]$sorted[-1].Message)
    }
    # Severity: a definition with 'severeMatch' only keeps its full status
    # when at least one event matches it; otherwise it drops to a warning.
    $status = $Def.status
    if ($Def.severeMatch -and $list.Count -gt 0) {
        if (@($list | Where-Object { [string]$_.Message -match $Def.severeMatch }).Count -eq 0) { $status = 'warn' }
    }
    [pscustomobject]@{ key = $Def.key; count = $list.Count; first = $first; last = $last; sample = $sample; status = $status }
}

function Test-EtkEventSignals {
    param([int]$Hours = 24)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Event signals'
    try {
        $since = (Get-Date).AddHours(-$Hours)
        foreach ($d in (Get-EtkEventSignalDefs)) {
            $fh = @{ LogName = $d.log; Id = [int[]]$d.ids; StartTime = $since }
            if ($d.provider) { $fh.ProviderName = $d.provider }
            $ev = @()
            $err = $null
            try { $ev = @(Get-WinEvent -FilterHashtable $fh -MaxEvents 5000 -ErrorAction Stop) }
            catch { if ($_.Exception.Message -notmatch 'No events were found') { $err = $_.Exception.Message } }
            if ($err -and $err -match 'There is not an event provider') {
                # The source is not registered here at all (normal when the
                # product is not installed) - not a read failure.
                $rows.Add((New-EtkRow -Group $g -Check $d.title -Result ('Source {0} is not registered on this machine' -f $d.provider) -Basis 'not measured' -Status 'info'))
                continue
            }
            if ($err) {
                $rows.Add((New-EtkRow -Group $g -Check $d.title -Result 'Could not read' -Basis 'not measured' -Status 'info' -Detail $err))
                continue
            }
            $c = Get-EtkSignalCount -Events $ev -Def $d
            if ($c.count -eq 0) {
                $rows.Add((New-EtkRow -Group $g -Check $d.title -Result ('None in {0} h' -f $Hours) -Status 'ok'))
            } else {
                $rows.Add((New-EtkRow -Group $g -Check $d.title -Result ('{0} events, {1} to {2}' -f $c.count, (ConvertTo-EtkLocalStamp $c.first), (ConvertTo-EtkLocalStamp $c.last)) `
                    -Basis 'server-reported' -Status $c.status -Detail ('{0} Latest: {1}' -f $d.detail, $c.sample)))
            }
        }
        # Managed Availability: count only - the messages are long XML-ish
        # blocks and the count alone says whether Exchange has been healing
        # itself.
        try {
            $ma = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Exchange-ManagedAvailability/RecoveryActionResults'; StartTime = $since } -MaxEvents 2000 -ErrorAction Stop)
            $rows.Add((New-EtkRow -Group $g -Check 'Managed Availability recovery actions' -Result ('{0} in {1} h' -f $ma.Count, $Hours) -Basis 'server-reported' `
                -Status $(if ($ma.Count -gt 20) { 'warn' } else { 'info' }) -Detail 'Exchange restarting its own components (app pools, services). A burst lines up with the moment something went wrong.'))
        } catch {
            if ($_.Exception.Message -match 'No events were found') {
                $rows.Add((New-EtkRow -Group $g -Check 'Managed Availability recovery actions' -Result ('None in {0} h' -f $Hours) -Status 'ok'))
            }
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('Get-WinEvent, last {0} hours' -f $Hours) -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkLogNoise {
    # Pure. Given provider counts for one log, returns the dominant provider
    # when it writes more than the threshold share. That is how a snapshot
    # driver flooding the System log (and shrinking its history) was found.
    param([hashtable]$ProviderCounts, [double]$Threshold = 0.5)
    $total = 0
    foreach ($v in $ProviderCounts.Values) { $total += [int]$v }
    if ($total -eq 0) { return $null }
    $top = $null; $topCount = 0
    foreach ($k in $ProviderCounts.Keys) {
        if ([int]$ProviderCounts[$k] -gt $topCount) { $top = $k; $topCount = [int]$ProviderCounts[$k] }
    }
    $share = $topCount / [double]$total
    [pscustomobject]@{ provider = $top; count = $topCount; total = $total; share = $share; noisy = ($share -gt $Threshold) }
}

function Test-EtkLogNoise {
    param([int]$Sample = 20000)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Log noise'
    try {
        foreach ($log in @('System','Application')) {
            $ev = @(Get-WinEvent -LogName $log -MaxEvents $Sample -ErrorAction Stop)
            $counts = @{}
            foreach ($e in $ev) { $p = [string]$e.ProviderName; if ($counts.ContainsKey($p)) { $counts[$p]++ } else { $counts[$p] = 1 } }
            $n = Get-EtkLogNoise -ProviderCounts $counts
            $span = ''
            if ($ev.Count -gt 0) { $span = (Format-EtkAge ($ev[0].TimeCreated - $ev[-1].TimeCreated)) }
            if ($n -and $n.noisy) {
                $rows.Add((New-EtkRow -Group $g -Check $log -Result ('{0} wrote {1:N0}% of the last {2:N0} events ({3})' -f $n.provider, (100 * $n.share), $n.total, $span) -Status 'warn' `
                    -Detail 'One source is flooding this log, which shortens its history. Find out why it is so busy - in the case this tool was built for it was a snapshot driver reacting to persistent shadow copies.'))
            } elseif ($n) {
                $rows.Add((New-EtkRow -Group $g -Check $log -Result ('Busiest source {0} ({1:N0}% of {2:N0} events, {3})' -f $n.provider, (100 * $n.share), $n.total, $span) -Status 'ok'))
            }
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('Provider share of the last {0} events per log' -f $Sample) -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkDiskLatency {
    param([int]$Seconds = 10)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Disk latency'
    try {
        $n = [math]::Max(2, [int]($Seconds / 2))
        $c = Get-Counter -Counter '\LogicalDisk(*)\Avg. Disk sec/Read', '\LogicalDisk(*)\Avg. Disk sec/Write' -SampleInterval 2 -MaxSamples $n -ErrorAction Stop
        $acc = @{}
        foreach ($set in $c) {
            foreach ($s in $set.CounterSamples) {
                if ($s.InstanceName -match '^_total$|harddiskvolume') { continue }
                $kind = $(if ($s.Path -match 'sec/read') { 'read' } else { 'write' })
                $k = ('{0}|{1}' -f $s.InstanceName.ToUpperInvariant(), $kind)
                if (-not $acc.ContainsKey($k)) { $acc[$k] = New-Object System.Collections.Generic.List[double] }
                $acc[$k].Add([double]$s.CookedValue * 1000.0)
            }
        }
        foreach ($k in ($acc.Keys | Sort-Object)) {
            $parts = $k.Split('|')
            $avg = ($acc[$k] | Measure-Object -Average).Average
            $max = ($acc[$k] | Measure-Object -Maximum).Maximum
            $st = 'ok'; if ($avg -gt 50) { $st = 'fail' } elseif ($avg -gt 20) { $st = 'warn' }
            $rows.Add((New-EtkRow -Group $g -Check ('{0} {1}' -f $parts[0], $parts[1]) -Result ('avg {0:N1} ms, max {1:N1} ms' -f $avg, $max) -Status $st `
                -Detail $(if ($st -ne 'ok') { 'Exchange guidance: database reads under 20 ms on average. Higher means the disks, or something in the disk path (snapshots, filter drivers, a backup reading them), cannot keep up.' } else { '' })))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('LogicalDisk counters, {0} x 2 s samples' -f $n) -Rows $rows.ToArray() `
            -Caveats @('A sample of the last few seconds only. Use the Evidence tab''s perf capture for a problem that happens at a particular time of day.')) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State unsupported -Reason ('Performance counters not readable: {0} (counter names are localised; a non-English server needs a different path).' -f $_.Exception.Message) -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkFolderStats {
    # Transaction-log count and size in a log folder (flat). A growing count
    # means backups are not truncating logs. Only files that ARE transaction
    # logs are counted: on a live server the log folder was also the database
    # folder, and counting every file reported the 233 GB .edb as "logs".
    param([string[]]$Paths, [string]$Pattern = '^E[0-9A-F]{2}([0-9A-F]{8})?(tmp|res\d+)?\.(log|jrs)$')
    foreach ($p in $Paths) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $exists = Test-Path -LiteralPath $p
        $size = $null; $count = $null; $oldest = $null
        if ($exists) {
            $files = @(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $Pattern })
            $count = $files.Count
            $size = ($files | Measure-Object -Property Length -Sum).Sum
            $o = $files | Sort-Object LastWriteTime | Select-Object -First 1
            if ($o) { $oldest = ConvertTo-EtkIso8601 $o.LastWriteTime }
        }
        [pscustomobject]@{ path = $p; exists = $exists; bytes = $size; files = $count; oldestUtc = $oldest }
    }
}

# ===========================================================================
#  HEALTH - Exchange-side checks (run in the worker, through the session)
# ===========================================================================

function Test-EtkServiceHealth {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Service health'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $srv = Get-EtkExchangeServerName
        foreach ($r in @(Test-ServiceHealth -Server $srv -ErrorAction Stop)) {
            $notRunning = @($r.ServicesNotRunning | ForEach-Object { [string]$_ } | Where-Object { $_ })
            $ok = [bool]$r.RequiredServicesRunning
            $rows.Add((New-EtkRow -Group $g -Check ([string]$r.Role) -Result $(if ($ok) { 'All required services running' } else { 'Not running: ' + ($notRunning -join ', ') }) `
                -Basis 'server-reported' -Status $(if ($ok) { 'ok' } else { 'fail' })))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Test-ServiceHealth' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkComponents {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Component state'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    # Inactive by design on-premises: both belong to Exchange Online.
    $expectedInactive = @('ForwardSyncDaemon', 'ProvisioningRps')
    try {
        $srv = Get-EtkExchangeServerName
        $all = @(Get-ServerComponentState -Identity $srv -ErrorAction Stop)
        $bad = @($all | Where-Object { [string]$_.State -ne 'Active' -and $expectedInactive -notcontains [string]$_.Component })
        foreach ($c in $bad) {
            $rows.Add((New-EtkRow -Group $g -Check ([string]$c.Component) -Result ([string]$c.State) -Basis 'server-reported' -Status 'fail' `
                -Detail 'Inactive components survive a restart. Often left behind by maintenance mode or a failed CU. Set it Active with the same requester that made it inactive (usually Maintenance or Functional).' `
                -Actions @(New-EtkActionRef -Id 'component-active' -Arguments @{ Component = [string]$c.Component; Requester = 'Functional' } -Label ('Set {0} Active (Functional)' -f $c.Component),
                           (New-EtkActionRef -Id 'component-active' -Arguments @{ Component = [string]$c.Component; Requester = 'Maintenance' } -Label ('Set {0} Active (Maintenance)' -f $c.Component)))))
        }
        $rows.Add((New-EtkRow -Group $g -Check 'Server components' -Result ('{0} active, {1} inactive (excluding {2})' -f @($all | Where-Object { [string]$_.State -eq 'Active' }).Count, $bad.Count, ($expectedInactive -join ', ')) `
            -Basis 'server-reported' -Status $(if ($bad.Count -gt 0) { 'fail' } else { 'ok' })))
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-ServerComponentState' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkDatabaseInfo {
    # One read of the databases, shared by the Health and Storage tabs and
    # used to work out which volumes hold Exchange data.
    if (-not (Test-EtkExchangeAvailable)) { return @() }
    $srv = Get-EtkExchangeServerName
    $out = @()
    foreach ($d in @(Get-MailboxDatabase -Server $srv -Status -ErrorAction Stop)) {
        $out += [pscustomobject]@{
            name          = [string]$d.Name
            mounted       = [bool]$d.Mounted
            sizeBytes     = (Convert-EtkByteQuantity $d.DatabaseSize)
            whitespace    = (Convert-EtkByteQuantity $d.AvailableNewMailboxSpace)
            edbPath       = [string]$d.EdbFilePath
            logPath       = [string]$d.LogFolderPath
            circular      = [bool]$d.CircularLoggingEnabled
            lastFull      = (ConvertTo-EtkIso8601 $d.LastFullBackup)
            lastIncr      = (ConvertTo-EtkIso8601 $d.LastIncrementalBackup)
        }
    }
    return $out
}

function Get-EtkTransportInfo {
    if (-not (Test-EtkExchangeAvailable)) { return $null }
    $srv = Get-EtkExchangeServerName
    $ts = Get-TransportService -Identity $srv -ErrorAction Stop
    [pscustomobject]@{
        queuePath        = [string]$ts.QueueDatabasePath
        queueLogPath     = [string]$ts.QueueDatabaseLoggingPath
        trackingPath     = [string]$ts.MessageTrackingLogPath
        retryInterval    = [string]$ts.MessageRetryInterval
        maxPerDomain     = [string]$ts.MaxPerDomainOutboundConnections
        maxOutbound      = [string]$ts.MaxOutboundConnections
        expiration       = [string]$ts.MessageExpirationTimeout
    }
}

function Get-EtkQueuePath {
    # OS-level. Where the transport queue database lives. On Exchange
    # 2013-2019 it is set in EdgeTransport.exe.config, not on the transport
    # service object - Get-TransportService returned it EMPTY on a live
    # 2019 CU15 server. With no key in the config, Exchange uses the default
    # folder under the install path.
    $install = Get-EtkRegValue 'SOFTWARE\Microsoft\ExchangeServer\v15\Setup' 'MsiInstallPath'
    if (-not $install) { return $null }
    $cfg = Join-Path $install 'bin\EdgeTransport.exe.config'
    $q = $null; $ql = $null; $source = 'default'
    if (Test-Path -LiteralPath $cfg) {
        try {
            [xml]$x = Get-Content -LiteralPath $cfg -Raw
            $q  = [string]($x.configuration.appSettings.add | Where-Object { $_.key -eq 'QueueDatabasePath' } | Select-Object -First 1).value
            $ql = [string]($x.configuration.appSettings.add | Where-Object { $_.key -eq 'QueueDatabaseLoggingPath' } | Select-Object -First 1).value
            if ($q) { $source = 'EdgeTransport.exe.config' }
        } catch { }
    }
    $def = Join-Path $install 'TransportRoles\data\Queue'
    if (-not $q) { $q = $def }
    if (-not $ql) { $ql = $q }
    [pscustomobject]@{ queuePath = $q; queueLogPath = $ql; source = $source }
}

function Get-EtkDriveLetter {
    param([string]$Path)
    if ($Path -match '^\s*([A-Za-z]):') { return ($Matches[1].ToUpperInvariant() + ':') }
    return $null
}

function Get-EtkExchangeVolumes {
    # Drive letters that hold Exchange data, with what each holds - used to
    # decide whether a snapshot or a scheduled task touches Exchange.
    param($Databases, $Transport)
    $map = @{}
    foreach ($d in @($Databases)) {
        foreach ($pair in @(@($d.edbPath, ('database ' + $d.name)), @($d.logPath, ('logs ' + $d.name)))) {
            $l = Get-EtkDriveLetter $pair[0]
            if ($l) { if (-not $map.ContainsKey($l)) { $map[$l] = @() }; $map[$l] += $pair[1] }
        }
    }
    if ($Transport) {
        foreach ($pair in @(@($Transport.queuePath, 'transport queue'), @($Transport.queueLogPath, 'transport queue logs'))) {
            $l = Get-EtkDriveLetter $pair[0]
            if ($l) { if (-not $map.ContainsKey($l)) { $map[$l] = @() }; if ($map[$l] -notcontains $pair[1]) { $map[$l] += $pair[1] } }
        }
    }
    return $map
}

function Test-EtkDatabases {
    param($Databases, [object[]]$LogFolders = @())
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Databases'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $srv = Get-EtkExchangeServerName
        $copies = @()
        try { $copies = @(Get-MailboxDatabaseCopyStatus -Server $srv -ErrorAction Stop) } catch { }
        foreach ($d in @($Databases)) {
            $acts = @()
            if (-not $d.mounted) { $acts = @(New-EtkActionRef -Id 'db-mount' -Arguments @{ Identity = $d.name } -Label ('Mount {0}' -f $d.name)) }
            $rows.Add((New-EtkRow -Group $g -Check $d.name -Result ('{0}, {1}, {2} free inside' -f $(if ($d.mounted) { 'Mounted' } else { 'DISMOUNTED' }), (Format-EtkBytes $d.sizeBytes), (Format-EtkBytes $d.whitespace)) `
                -Basis 'server-reported' -Status $(if ($d.mounted) { 'ok' } else { 'fail' }) -Detail ('{0}{1}' -f $d.edbPath, $(if ($d.circular) { ' - circular logging ON' } else { '' })) -Actions $acts))
            $copy = $copies | Where-Object { ([string]$_.Name) -like ($d.name + '\*') } | Select-Object -First 1
            if ($copy) {
                $ci = [string]$copy.ContentIndexState
                # NotApplicable is not a fault state: Exchange is saying it has
                # no separate index state to report (2019 keeps the index
                # inside the database). Only a real failure state warns.
                $cist = $(if ($ci -eq 'Healthy') { 'ok' } elseif ($ci -eq 'NotApplicable' -or -not $ci) { 'info' } else { 'warn' })
                $rows.Add((New-EtkRow -Group $g -Check ('{0} search index' -f $d.name) -Result $(if ($ci) { $ci } else { 'not reported' }) -Basis 'server-reported' -Status $cist `
                    -Detail $(if ($cist -eq 'warn') { 'An unhealthy index makes Outlook/OWA search slow and keeps noderunner busy (CPU).' } elseif ($cist -eq 'info') { 'No index state reported - normal for Exchange 2019, which keeps the search index inside the database. If Outlook search is slow, run Test-ExchangeSearch.' } else { '' })))
            }
            $lf = $LogFolders | Where-Object { $_.path -eq $d.logPath } | Select-Object -First 1
            if ($lf -and $lf.exists) {
                $st = 'ok'; if ([int]$lf.files -gt 50000) { $st = 'fail' } elseif ([int]$lf.files -gt 10000) { $st = 'warn' }
                $rows.Add((New-EtkRow -Group $g -Check ('{0} transaction logs' -f $d.name) -Result ('{0:N0} log files, {1}' -f $lf.files, (Format-EtkBytes $lf.bytes)) -Status $st `
                    -Detail ('{0}. {1}' -f $d.logPath, $(if ($d.circular) { 'Circular logging is on, so Exchange removes logs itself and the count stays small whatever the backups do.' } else { 'Logs are only removed by a successful Exchange-aware FULL or INCREMENTAL backup. A growing pile means backups are not truncating them.' }))))
            }
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-MailboxDatabase -Status, Get-MailboxDatabaseCopyStatus, log folder listing' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkIisCertBindings {
    # OS-level. The certificate IIS actually serves on each https binding,
    # read from IIS itself. This is the measured answer to "which certificate
    # do clients see" - Get-ExchangeCertificate's Services field came back
    # EMPTY through remote PowerShell on a live 2019 CU15 server, so a check
    # built only on it silently skipped the real certificate.
    $dll = Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
    if (-not (Test-Path -LiteralPath $dll) -or -not (Test-EtkElevated)) { return @() }
    [void][Reflection.Assembly]::LoadFrom($dll)
    $sm = New-Object Microsoft.Web.Administration.ServerManager
    $out = @()
    try {
        foreach ($site in $sm.Sites) {
            foreach ($b in $site.Bindings) {
                if ($b.Protocol -ne 'https' -or -not $b.CertificateHash) { continue }
                $tp = (($b.CertificateHash | ForEach-Object { $_.ToString('X2') }) -join '')
                $storeName = $(if ($b.CertificateStoreName) { $b.CertificateStoreName } else { 'My' })
                $cert = Get-Item -LiteralPath ('Cert:\LocalMachine\{0}\{1}' -f $storeName, $tp) -ErrorAction SilentlyContinue
                $sans = @()
                if ($cert) { try { $sans = @($cert.DnsNameList | ForEach-Object { [string]$_.Unicode }) } catch { } }
                $out += [pscustomobject]@{
                    site = [string]$site.Name; binding = [string]$b.BindingInformation; thumbprint = $tp
                    subject = $(if ($cert) { [string]$cert.Subject } else { $null }); notAfter = $(if ($cert) { ConvertTo-EtkIso8601 $cert.NotAfter } else { $null })
                    sans = [object[]]$sans; found = [bool]$cert
                }
            }
        }
    } finally { $sm.Dispose() }
    return $out
}

function Test-EtkCertificates {
    param([object[]]$IisBindings = @())
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Certificates'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $srv = Get-EtkExchangeServerName
        $certs = @(Get-ExchangeCertificate -Server $srv -ErrorAction Stop)
        $auth = $null
        try { $auth = [string](Get-AuthConfig -ErrorAction Stop).CurrentCertificateThumbprint } catch { }
        $iisThumbs = @($IisBindings | ForEach-Object { [string]$_.thumbprint })
        $svcKnown = @($certs | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Services) -and [string]$_.Services -ne 'None' }).Count -gt 0

        # What IIS serves - measured, independent of the Services field.
        foreach ($b in ($IisBindings | Sort-Object site, binding)) {
            if (-not $b.found) {
                $rows.Add((New-EtkRow -Group $g -Check ('IIS {0} {1}' -f $b.site, $b.binding) -Result ('certificate {0} NOT in the store' -f $b.thumbprint) -Status 'fail' `
                    -Detail 'IIS is bound to a certificate that is missing from the machine store. HTTPS to this site fails.'))
                continue
            }
            $na = [datetime]$b.notAfter; $days = ($na - (Get-Date)).TotalDays
            $st = 'ok'; if ($days -lt 0) { $st = 'fail' } elseif ($days -lt 30) { $st = 'warn' }
            # Only the Default Web Site's real 443 bindings face clients. The
            # back end (444) and the loopback binding are Exchange talking to
            # itself; an expired cert there still breaks things, but not in
            # a way users see as a certificate prompt.
            $facing = ($b.site -eq 'Default Web Site' -and $b.binding -match ':443:' -and $b.binding -notmatch '^127\.0\.0\.1:|^\[::1\]:')
            $who = $(if ($facing) { 'Outlook, OWA and phones see this certificate.' } else { 'Used by Exchange internally (back end or loopback), not shown to clients.' })
            $rows.Add((New-EtkRow -Group $g -Check ('IIS {0} {1}' -f $b.site, $b.binding) -Result ('{0}, expires {1} ({2:N0} days)' -f ($b.subject -replace '^CN=', '' -replace ',.*$', ''), (ConvertTo-EtkLocalStamp $na), $days) `
                -Status $st -Detail ('Names on it: {0}. Thumbprint {1}. {2}' -f ((@($b.sans) -join ', ')), $b.thumbprint, $who)))
        }

        foreach ($c in $certs) {
            $tp = [string]$c.Thumbprint
            $svc = [string]$c.Services
            $isAuth = ($auth -and $tp -eq $auth)
            $isIis = ($iisThumbs -contains $tp)
            if ($isIis) { continue }      # already shown from the IIS side
            $bound = ($svc -match 'IIS|SMTP' -or $isAuth)
            if (-not $bound -and $svcKnown) { continue }
            $na = [datetime]$c.NotAfter
            $days = ($na - (Get-Date)).TotalDays
            $st = 'ok'; if ($days -lt 0) { $st = 'fail' } elseif ($days -lt 30) { $st = 'warn' }
            # With the Services field unreadable we cannot tell a bound
            # certificate from a leftover one, so expiry is reported but only
            # counted against the verdict for the Auth certificate.
            if (-not $bound) { $st = 'info' }
            $label = ([string]$c.Subject -replace '^CN=', '' -replace ',.*$', '')
            if ($isAuth) { $label = 'Auth (OAuth) certificate' }
            $rows.Add((New-EtkRow -Group $g -Check $label -Result ('expires {0} ({1:N0} days)' -f (ConvertTo-EtkLocalStamp $na), $days) -Basis 'server-reported' -Status $st `
                -Detail ('Services: {0}. Thumbprint {1}.{2}' -f $(if ($svc) { $svc } else { 'not reported' }), $tp, $(if ($isAuth -and $st -ne 'ok') { ' An expired Auth certificate breaks OWA/ECP sign-in and hybrid features.' } else { '' }))))
        }
        if ($auth -and -not ($certs | Where-Object { [string]$_.Thumbprint -eq $auth })) {
            $rows.Add((New-EtkRow -Group $g -Check 'Auth (OAuth) certificate' -Result ('Thumbprint {0} not found on this server' -f $auth) -Basis 'server-reported' -Status 'fail' `
                -Detail 'Get-AuthConfig points at a certificate this server does not have. OWA and ECP sign-in fail until it is fixed.'))
        }
        if (-not $svcKnown) {
            $rows.Add((New-EtkRow -Group $g -Check 'Services field' -Result 'Not reported by Get-ExchangeCertificate' -Basis 'not measured' -Status 'info' `
                -Detail 'The SMTP certificate cannot be identified this way. The IIS rows above come from IIS itself; check the SMTP certificate with Get-ExchangeCertificate in the Exchange Management Shell if needed.'))
        }
        if ($IisBindings.Count -eq 0) {
            $rows.Add((New-EtkRow -Group $g -Check 'IIS bindings' -Result 'Not read' -Basis 'not measured' -Status 'info' -Detail 'Needs an elevated session on the server (or IIS is not installed).'))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'IIS https bindings (measured), Get-ExchangeCertificate, Get-AuthConfig' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

# ===========================================================================
#  MAIL FLOW
# ===========================================================================

function Test-EtkQueues {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Queues'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $srv = Get-EtkExchangeServerName
        $q = @(Get-Queue -Server $srv -ErrorAction Stop)
        foreach ($x in ($q | Sort-Object { [int]$_.MessageCount } -Descending)) {
            $id = [string]$x.Identity
            $n = [int]$x.MessageCount
            $status = [string]$x.Status
            $st = 'ok'
            if ($n -gt 1000 -or $status -match 'Retry|Suspended') { $st = 'fail' } elseif ($n -gt 100) { $st = 'warn' }
            if ($id -match '\\Poison$' -and $n -gt 0) { $st = 'warn' }
            $acts = @(New-EtkActionRef -Id 'queue-retry' -Arguments @{ Identity = $id } -Label 'Retry this queue')
            if ($status -eq 'Suspended') { $acts += New-EtkActionRef -Id 'queue-resume' -Arguments @{ Identity = $id } -Label 'Resume this queue' }
            else { $acts += New-EtkActionRef -Id 'queue-suspend' -Arguments @{ Identity = $id } -Label 'Suspend this queue' }
            $det = [string]$x.LastError
            if ($id -match '\\Poison$' -and $n -gt 0) { $det = 'Messages that crashed transport while being processed. Inspect them; do not just resume. ' + $det }
            $rows.Add((New-EtkRow -Group $g -Check $id -Result ('{0} messages, {1}' -f $n, $status) -Basis 'server-reported' -Status $st -Detail $det -Actions $acts))
        }
        if ($q.Count -eq 0) { $rows.Add((New-EtkRow -Group $g -Check 'Queues' -Result 'No queues' -Basis 'server-reported' -Status 'ok')) }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-Queue' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function ConvertFrom-EtkBackPressureXml {
    # Pure. Reads the ResourceMeter entries out of the ResourceThrottling
    # diagnostic XML. Exchange 2019 CU15 (captured live) writes
    #   <ResourceMeter Resource="SystemMemory">
    #     <CurrentResourceUse>Low</CurrentResourceUse> <PreviousResourceUse/>
    #     <PressureTransitions>[PressureTransitions: MediumToHigh=94 ...]</...>
    #     <Pressure>48</Pressure>
    # Other builds have used *PressureState names, so both are read. A missing
    # state stays unknown - it is never defaulted to "Low".
    param([string]$Xml)
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml($Xml)
    $get = {
        param($node, [string[]]$names)
        foreach ($name in $names) {
            $c = $node.SelectSingleNode($name)
            if ($c) { return $c.InnerText.Trim() }
            $a = $node.Attributes[$name]
            if ($a) { return $a.Value.Trim() }
        }
        return $null
    }
    $out = @()
    foreach ($n in @($doc.SelectNodes('//ResourceMeter'))) {
        $trans = & $get $n @('PressureTransitions')
        $medium = $null; $high = $null
        if ($trans -match 'LowToMedium=(\d+)') { $medium = [int]$Matches[1] }
        if ($trans -match 'MediumToHigh=(\d+)') { $high = [int]$Matches[1] }
        $out += [pscustomobject]@{
            resource = (& $get $n @('Resource'))
            pressure = (& $get $n @('Pressure'))
            state    = (& $get $n @('CurrentResourceUse', 'CurrentPressureState'))
            previous = (& $get $n @('PreviousResourceUse', 'PreviousPressureState'))
            mediumAt = $medium
            highAt   = $high
        }
    }
    return $out
}

function Get-EtkBackPressureAggregate {
    # Pure. The overall level transport is acting on (AggregateUse), or $null.
    param([string]$Xml)
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml($Xml)
    $n = $doc.SelectSingleNode('//ResourceTracker/AggregateUse')
    if ($n) { return $n.InnerText.Trim() }
    return $null
}

function Test-EtkBackPressure {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Back pressure'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $srv = Get-EtkExchangeServerName
        $info = Get-ExchangeDiagnosticInfo -Server $srv -Process EdgeTransport -Component ResourceThrottling -ErrorAction Stop
        $raw = $null
        try { $raw = [string]$info.Result } catch { }
        if ([string]::IsNullOrWhiteSpace($raw)) { $raw = [string]$info }
        $meters = @(ConvertFrom-EtkBackPressureXml -Xml $raw)
        $agg = Get-EtkBackPressureAggregate -Xml $raw
        if ($agg) {
            $ast = $(if ($agg -match 'High') { 'fail' } elseif ($agg -match 'Medium') { 'warn' } else { 'ok' })
            $rows.Add((New-EtkRow -Group $g -Check 'Overall (AggregateUse)' -Result $agg -Basis 'server-reported' -Status $ast `
                -Detail 'The level transport is acting on right now: Medium throttles new connections, High stops accepting mail.'))
        }
        foreach ($m in $meters) {
            $state = $m.state
            $st = 'ok'
            if ([string]::IsNullOrWhiteSpace($state)) { $st = 'info'; $state = 'state unknown' }
            elseif ($state -match 'High') { $st = 'fail' }
            elseif ($state -match 'Medium') { $st = 'warn' }
            $thr = $(if ($null -ne $m.mediumAt -and $null -ne $m.highAt) { ('Medium from {0}, High from {1}.' -f $m.mediumAt, $m.highAt) } else { '' })
            $rows.Add((New-EtkRow -Group $g -Check $m.resource -Result ('{0} (pressure {1})' -f $state, $m.pressure) -Basis 'server-reported' -Status $st `
                -Detail ('{0} {1}' -f $(if ($st -eq 'fail') { 'High: transport has stopped accepting mail because of this resource.' } elseif ($st -eq 'warn') { 'Medium: transport is throttling incoming mail.' } else { '' }), $thr).Trim()))
        }
        if ($meters.Count -eq 0) { $rows.Add((New-EtkRow -Group $g -Check 'Resource meters' -Result 'None found in the diagnostic output' -Basis 'not measured' -Status 'info')) }
        $keep = $raw; if ($keep.Length -gt 20000) { $keep = $keep.Substring(0, 20000) }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-ExchangeDiagnosticInfo -Process EdgeTransport -Component ResourceThrottling' -Rows $rows.ToArray() `
            -Data ([pscustomobject]@{ rawXml = $keep })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkTrackingSummary {
    # Pure. From message-tracking entries (Timestamp, EventId, MessageId):
    #   * counts per 10-minute bucket and event type - an empty bucket in the
    #     middle of a busy period is a stall
    #   * per DISTINCT message, the time from first RECEIVE to first
    #     DELIVER/SEND/SENDEXTERNAL, as median / p90 / max per bucket
    # Event rows are not messages; counting rows as "messages" overstates
    # everything, which is why latency is per MessageId.
    param($Entries, [int]$BucketMinutes = 10)
    $types = @('RECEIVE','DELIVER','SEND','SENDEXTERNAL','FAIL','DEFER')
    $buckets = @{}
    $byMsg = @{}
    foreach ($e in @($Entries)) {
        $ts = [datetime]$e.Timestamp
        $b = $ts.Date.AddMinutes([math]::Floor($ts.TimeOfDay.TotalMinutes / $BucketMinutes) * $BucketMinutes)
        $key = $b.ToString('yyyy-MM-dd HH:mm')
        if (-not $buckets.ContainsKey($key)) {
            $h = [ordered]@{}; foreach ($t in $types) { $h[$t] = 0 }; $buckets[$key] = $h
        }
        $ev = [string]$e.EventId
        if ($buckets[$key].Contains($ev)) { $buckets[$key][$ev]++ }
        $mid = [string]$e.MessageId
        if (-not $mid) { continue }
        if (-not $byMsg.ContainsKey($mid)) { $byMsg[$mid] = @{ recv = $null; done = $null } }
        if ($ev -eq 'RECEIVE') { if (-not $byMsg[$mid].recv -or $ts -lt $byMsg[$mid].recv) { $byMsg[$mid].recv = $ts } }
        elseif ($ev -in @('DELIVER','SEND','SENDEXTERNAL')) { if (-not $byMsg[$mid].done -or $ts -lt $byMsg[$mid].done) { $byMsg[$mid].done = $ts } }
    }
    $lat = @{}
    foreach ($k in $byMsg.Keys) {
        $m = $byMsg[$k]
        if ($m.recv -and $m.done -and $m.done -ge $m.recv) {
            $b = $m.recv.Date.AddMinutes([math]::Floor($m.recv.TimeOfDay.TotalMinutes / $BucketMinutes) * $BucketMinutes).ToString('yyyy-MM-dd HH:mm')
            if (-not $lat.ContainsKey($b)) { $lat[$b] = New-Object System.Collections.Generic.List[double] }
            $lat[$b].Add(($m.done - $m.recv).TotalSeconds)
        }
    }
    $rowsOut = @()
    foreach ($k in ($buckets.Keys | Sort-Object)) {
        $l = @(); if ($lat.ContainsKey($k)) { $l = [double[]]$lat[$k].ToArray() }
        $rowsOut += [pscustomobject]@{
            bucket = $k
            counts = [pscustomobject]$buckets[$k]
            messages = $l.Count
            medianSec = $(if ($l.Count) { Get-EtkPercentile $l 50 } else { $null })
            p90Sec    = $(if ($l.Count) { Get-EtkPercentile $l 90 } else { $null })
            maxSec    = $(if ($l.Count) { ($l | Measure-Object -Maximum).Maximum } else { $null })
        }
    }
    $all = @(); foreach ($v in $lat.Values) { $all += $v.ToArray() }
    [pscustomobject]@{
        buckets = [object[]]$rowsOut
        distinctMessages = $byMsg.Count
        timedMessages = $all.Count
        medianSec = $(if ($all.Count) { Get-EtkPercentile ([double[]]$all) 50 } else { $null })
        p90Sec    = $(if ($all.Count) { Get-EtkPercentile ([double[]]$all) 90 } else { $null })
        maxSec    = $(if ($all.Count) { ($all | Measure-Object -Maximum).Maximum } else { $null })
    }
}

function Test-EtkThroughput {
    param([int]$Hours = 2, [int]$Cap = 50000)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Throughput'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $srv = Get-EtkExchangeServerName
        $end = Get-Date; $start = $end.AddHours(-$Hours)
        $raw = @(Get-MessageTrackingLog -Server $srv -Start $start -End $end -ResultSize $Cap -ErrorAction Stop |
            Select-Object Timestamp, EventId, MessageId)
        $capped = ($raw.Count -ge $Cap)
        $s = Get-EtkTrackingSummary -Entries $raw
        $fails = 0; foreach ($b in $s.buckets) { $fails += [int]$b.counts.FAIL }
        $st = 'ok'; if ($s.p90Sec -gt 300) { $st = 'fail' } elseif ($s.p90Sec -gt 60) { $st = 'warn' }
        $rows.Add((New-EtkRow -Group $g -Check ('Last {0} h' -f $Hours) -Result ('{0:N0} distinct messages; receive-to-delivery median {1}, p90 {2}, max {3}' -f $s.distinctMessages, `
            (Format-EtkSeconds $s.medianSec), (Format-EtkSeconds $s.p90Sec), (Format-EtkSeconds $s.maxSec)) `
            -Basis 'server-reported' -Status $st -Detail ('Timed {0:N0} messages that were both received and delivered/sent inside the window. {1} FAIL events.{2}' -f $s.timedMessages, $fails, $(if ($capped) { (' Result cap of {0:N0} rows hit - the window is only partly covered.' -f $Cap) } else { '' }))))
        $peak = 0; foreach ($b in $s.buckets) { $n = [int]$b.counts.RECEIVE; if ($n -gt $peak) { $peak = $n } }
        foreach ($b in $s.buckets) {
            $c = $b.counts
            $bst = 'info'
            if ($null -ne $b.p90Sec -and $b.p90Sec -gt 300) { $bst = 'fail' } elseif ($null -ne $b.p90Sec -and $b.p90Sec -gt 60) { $bst = 'warn' }
            $rows.Add((New-EtkRow -Group $g -Check $b.bucket -Result ('in {0} / delivered {1} / sent {2} / ext {3} / fail {4}' -f $c.RECEIVE, $c.DELIVER, $c.SEND, $c.SENDEXTERNAL, $c.FAIL) `
                -Basis 'server-reported' -Status $bst -Detail $(if ($b.messages) { 'p90 {0}, max {1} over {2} messages' -f (Format-EtkSeconds $b.p90Sec), (Format-EtkSeconds $b.maxSec), $b.messages } else { '' })))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('Get-MessageTrackingLog, {0} h, cap {1}' -f $Hours, $Cap) -Rows $rows.ToArray() `
            -Data ([pscustomobject]@{ summary = $s; capped = $capped })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkTransportConfig {
    param($Transport)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Transport settings'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $t = $Transport
        $ri = ConvertTo-EtkTimeSpan $t.retryInterval
        $rows.Add((New-EtkRow -Group $g -Check 'MessageRetryInterval' -Result $t.retryInterval -Basis 'server-reported' `
            -Status $(if ($ri -and $ri.TotalMinutes -gt 5) { 'warn' } else { 'ok' }) `
            -Detail 'How long a message waits after a temporary delivery failure. HealthChecker recommends 5 minutes; 15 makes every hiccup feel like "slow email".'))
        $mp = 0; [void][int]::TryParse($t.maxPerDomain, [ref]$mp)
        $rows.Add((New-EtkRow -Group $g -Check 'MaxPerDomainOutboundConnections' -Result $t.maxPerDomain -Basis 'server-reported' `
            -Status $(if ($mp -gt 0 -and $mp -lt 40) { 'warn' } else { 'ok' }) -Detail 'HealthChecker recommends 40.'))
        $qsrc = [string]$t.queuePathSource
        $rows.Add((New-EtkRow -Group $g -Check 'Transport queue database' -Result $(if ($t.queuePath) { $t.queuePath } else { 'unknown' }) `
            -Basis $(if ($qsrc -eq 'default') { 'inference' } elseif ($qsrc) { 'measured' } else { 'server-reported' }) -Status 'info' `
            -Detail ('{0}Everything that slows writes on this volume (snapshots, filter drivers, a backup reading it) slows every message.' -f $(if ($qsrc -eq 'default') { 'No QueueDatabasePath in EdgeTransport.exe.config, so this is the default location. ' } elseif ($qsrc) { 'From EdgeTransport.exe.config. ' } else { '' }))))
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-TransportService' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkConnectors {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Connectors'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $srv = Get-EtkExchangeServerName
        foreach ($c in @(Get-ReceiveConnector -Server $srv -ErrorAction Stop)) {
            $bind = (@($c.Bindings) | ForEach-Object { [string]$_ }) -join ' '
            $perm = [string]$c.PermissionGroups
            $auth = [string]$c.AuthMechanism
            $st = 'info'; $det = ('Auth: {0}. Permission groups: {1}.' -f $auth, $perm)
            $isClient = ($bind -match ':587|:465')
            if ($isClient -and $perm -match 'AnonymousUsers') { $st = 'warn'; $det = 'A client submission connector that accepts anonymous users. ' + $det }
            if ($isClient) { $det += ' Client submission port: if it is forwarded from the internet, it is a password-guessing target.' }
            $rows.Add((New-EtkRow -Group $g -Check ('Receive: {0}' -f $c.Name) -Result $(if ($c.Enabled) { $bind } else { 'DISABLED ' + $bind }) -Basis 'server-reported' -Status $st -Detail $det))
        }
        foreach ($c in @(Get-SendConnector -ErrorAction Stop)) {
            $hosts = (@($c.SmartHosts) | ForEach-Object { [string]$_ }) -join ', '
            $spaces = (@($c.AddressSpaces) | ForEach-Object { [string]$_ }) -join ', '
            $rows.Add((New-EtkRow -Group $g -Check ('Send: {0}' -f $c.Name) -Result $(if ($hosts) { 'via ' + $hosts } else { 'DNS (MX) delivery' }) -Basis 'server-reported' `
                -Status $(if ($c.Enabled) { 'info' } else { 'warn' }) -Detail ('Address space: {0}.{1}' -f $spaces, $(if (-not $c.Enabled) { ' Disabled.' } else { '' }))))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-ReceiveConnector, Get-SendConnector' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

# ===========================================================================
#  STORAGE & BACKUP (OS-level, remote-capable unless noted)
# ===========================================================================

function Get-EtkFilterDriverInfo {
    # Volume class filter drivers sit in the path of EVERY read and write.
    # Identified from the driver file's own version metadata (measured), not
    # from a list of guessed names.
    $cls = 'SYSTEM\CurrentControlSet\Control\Class\{71A27CDD-812A-11D0-BEC7-08002BE2092F}'
    $out = @()
    foreach ($kind in @('UpperFilters','LowerFilters')) {
        $v = Get-EtkRegValue $cls $kind
        foreach ($name in @($v | Where-Object { $_ })) {
            $img = Get-EtkRegValue ('SYSTEM\CurrentControlSet\Services\' + $name) 'ImagePath'
            $path = $null
            if ($img) {
                $p = ([string]$img) -replace '^\\SystemRoot\\', ($env:SystemRoot + '\') -replace '^System32\\', ($env:SystemRoot + '\System32\') -replace '^\\\?\?\\', ''
                if (Test-Path -LiteralPath $p) { $path = $p }
            }
            if (-not $path) {
                $p = Join-Path $env:SystemRoot ('System32\drivers\{0}.sys' -f $name)
                if (Test-Path -LiteralPath $p) { $path = $p }
            }
            $company = $null; $product = $null; $desc = $null; $ver = $null
            if ($path) {
                try {
                    $vi = (Get-Item -LiteralPath $path).VersionInfo
                    $company = $vi.CompanyName; $product = $vi.ProductName; $desc = $vi.FileDescription; $ver = $vi.FileVersion
                } catch { }
            }
            $out += [pscustomobject]@{ name = [string]$name; position = $kind; path = $path; company = $company; product = $product; description = $desc; version = $ver }
        }
    }
    return $out
}

function Get-EtkFilterVerdict {
    # Pure. Microsoft's own drivers are expected; each third-party one is a
    # product hooking every disk write. More than one is the pattern behind
    # "three backup products on one Exchange server".
    param($Drivers)
    $third = @($Drivers | Where-Object { [string]$_.company -notmatch '^Microsoft' })
    [pscustomobject]@{ thirdParty = [object[]]$third; count = $third.Count; multiple = ($third.Count -gt 1) }
}

function Test-EtkVolumeFilters {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Volume filter drivers'
    try {
        $d = @(Get-EtkFilterDriverInfo)
        $v = Get-EtkFilterVerdict -Drivers $d
        foreach ($x in $d) {
            $isMs = ([string]$x.company -match '^Microsoft')
            $who = $(if ($x.company) { ('{0} - {1}' -f $x.company, $(if ($x.product) { $x.product } else { $x.description })) } elseif ($x.path) { 'File has no vendor metadata' } else { 'Driver file not found' })
            $rows.Add((New-EtkRow -Group $g -Check ('{0} ({1})' -f $x.name, $x.position) -Result $who -Basis 'measured' -Status $(if ($isMs) { 'ok' } else { 'info' }) `
                -Detail $(if ($isMs) { 'Windows component.' } else { ('Third-party filter in every disk read/write. {0} {1}' -f $x.path, $x.version).Trim() })))
        }
        if ($v.multiple) {
            $rows.Add((New-EtkRow -Group $g -Check 'Third-party volume filters' -Result ('{0} installed: {1}' -f $v.count, (($v.thirdParty | ForEach-Object { $_.name }) -join ', ')) -Status 'warn' `
                -Detail 'Several products intercepting every disk write. Usually backup/snapshot products, often one of them left over from a product no longer in use. Keep one; remove the others with their vendor''s uninstaller in a maintenance window.'))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Volume class UpperFilters/LowerFilters + driver file version info' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function ConvertFrom-EtkVssWriters {
    # Pure. Parses English `vssadmin list writers`. Returns $null when the
    # text does not look like English vssadmin output, so the caller can say
    # "unsupported" instead of reporting zero writers.
    param([string]$Text)
    if ($Text -notmatch 'Writer name:') { return $null }
    $out = @()
    foreach ($block in ($Text -split "(?m)^\s*(?=Writer name:)")) {
        $mName = [regex]::Match($block, "Writer name:\s*'([^']*)'")
        if (-not $mName.Success) { continue }
        $mState = [regex]::Match($block, 'State:\s*\[(\d+)\]\s*(.+)')
        $mErr = [regex]::Match($block, 'Last error:\s*(.+)')
        $out += [pscustomobject]@{
            name      = $mName.Groups[1].Value.Trim()
            stateCode = $(if ($mState.Success) { [int]$mState.Groups[1].Value } else { $null })
            state     = $(if ($mState.Success) { $mState.Groups[2].Value.Trim() } else { $null })
            lastError = $(if ($mErr.Success) { $mErr.Groups[1].Value.Trim() } else { $null })
        }
    }
    return $out
}

function Test-EtkVssWriters {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'VSS writers'
    if (-not (Test-EtkElevated)) { return (New-EtkSection -State unsupported -Reason 'vssadmin needs an elevated session.') }
    $exe = Get-EtkSystemTool 'vssadmin.exe'
    if (-not $exe) { return (New-EtkSection -State unsupported -Reason 'vssadmin.exe not found.') }
    try {
        $r = Invoke-EtkNative -FilePath $exe -ArgumentList @('list', 'writers')
        $w = ConvertFrom-EtkVssWriters -Text $r.output
        if ($null -eq $w) {
            $sw.Stop()
            return Set-EtkSectionTiming (New-EtkSection -State unsupported -Reason ('vssadmin output was not English or not recognised (exit {0}). First line: {1}' -f $r.exitCode, (Get-EtkFirstLine $r.output))) $t0 $sw.Elapsed.TotalSeconds
        }
        $bad = @($w | Where-Object { $_.lastError -and $_.lastError -ne 'No error' -or ($_.stateCode -and $_.stateCode -notin @(1, 5)) })
        foreach ($x in $w) {
            $isEx = ($x.name -match 'Exchange')
            $st = 'ok'
            if ($x.state -match 'Failed' -or ($x.lastError -and $x.lastError -notmatch 'No error|Retryable')) { $st = 'fail' }
            elseif ($x.lastError -match 'Retryable' -or ($x.stateCode -and $x.stateCode -notin @(1, 5))) { $st = 'warn' }
            if (-not $isEx -and $st -eq 'ok') { continue }
            $det = ''
            if ($isEx -and $st -ne 'ok') { $det = 'The last backup (or snapshot) that called the Exchange writer did not complete cleanly. Until an Exchange-aware backup succeeds, transaction logs are not truncated and LastFullBackup does not move.' }
            elseif ($isEx) { $det = 'Last operation completed cleanly.' }
            $rows.Add((New-EtkRow -Group $g -Check $x.name -Result ('{0} / {1}' -f $x.state, $x.lastError) -Basis 'server-reported' -Status $st -Detail $det))
        }
        $sentinel = @($w | Where-Object { $_.name -match 'Sentinel' })
        if ($sentinel.Count -gt 0) {
            $rows.Add((New-EtkRow -Group $g -Check 'EDR writers' -Result ($sentinel.name -join ', ') -Basis 'inference' -Status 'info' `
                -Detail 'SentinelOne is registered with VSS. Its Rollback feature takes snapshots every 4 hours by default; see Shadow copies for whether they persist on this server.'))
        }
        $rows.Add((New-EtkRow -Group $g -Check 'All writers' -Result ('{0} writers, {1} not clean' -f $w.Count, $bad.Count) -Basis 'server-reported' -Status $(if ($bad.Count) { 'warn' } else { 'ok' })))
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'vssadmin list writers' -Rows $rows.ToArray() -Data ([pscustomobject]@{ writers = [object[]]$w })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkSnapshotCadence {
    # Pure. From creation times, the typical spacing between snapshots and
    # whether it is regular. An inference, labelled as one: "about every 4 h"
    # is consistent with EDR rollback snapshots, "07:00 and 12:00 weekdays"
    # with Windows Previous Versions - but neither proves who took them.
    param([datetime[]]$Times)
    $t = @($Times | Sort-Object -Unique)
    if ($t.Count -lt 3) { return [pscustomobject]@{ intervalHours = $null; regular = $false; samples = $t.Count; guess = '' } }
    $gaps = New-Object System.Collections.Generic.List[double]
    for ($i = 1; $i -lt $t.Count; $i++) {
        $h = ($t[$i] - $t[$i - 1]).TotalHours
        if ($h -gt 0.5) { $gaps.Add($h) }     # same-set siblings are seconds/minutes apart
    }
    if ($gaps.Count -lt 2) { return [pscustomobject]@{ intervalHours = $null; regular = $false; samples = $t.Count; guess = '' } }
    $med = Get-EtkPercentile ([double[]]$gaps.ToArray()) 50
    $near = @($gaps | Where-Object { [math]::Abs($_ - $med) -le [math]::Max(0.5, $med * 0.15) }).Count
    $regular = ($near / [double]$gaps.Count) -ge 0.7
    $guess = ''
    if ($regular -and [math]::Abs($med - 4) -le 0.5) { $guess = 'about every 4 h - the default cadence of SentinelOne Rollback snapshots' }
    elseif ($regular -and [math]::Abs($med - 24) -le 1) { $guess = 'about daily - a scheduled backup or Previous Versions task' }
    elseif ($regular) { $guess = ('about every {0:N1} h' -f $med) }
    [pscustomobject]@{ intervalHours = [math]::Round($med, 2); regular = $regular; samples = $t.Count; guess = $guess }
}

function ConvertTo-EtkVolumeKey {
    # Pure. Win32_Volume.DeviceID ends in a backslash; Win32_ShadowCopy
    # .VolumeName sometimes does and sometimes does not (both seen on one
    # live server, for snapshots of the same volume). Compare on one form.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    return $Path.Trim().TrimEnd('\').ToLowerInvariant()
}

function Get-EtkVolumeMap {
    # Volume GUID path (normalised) -> drive letter.
    $map = @{}
    foreach ($v in @(Get-CimInstance Win32_Volume -ErrorAction SilentlyContinue)) {
        if ($v.DeviceID) { $map[(ConvertTo-EtkVolumeKey ([string]$v.DeviceID))] = $(if ($v.DriveLetter) { [string]$v.DriveLetter } else { [string]$v.Label }) }
    }
    return $map
}

function Test-EtkShadowCopies {
    param([hashtable]$ExchangeVolumes = @{})
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Shadow copies'
    if (-not (Test-EtkElevated)) { return (New-EtkSection -State unsupported -Reason 'Reading shadow copies needs an elevated session.') }
    try {
        $vmap = Get-EtkVolumeMap
        $sc = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)
        $storage = @(Get-CimInstance Win32_ShadowStorage -ErrorAction SilentlyContinue)
        $byVol = $sc | Group-Object { ConvertTo-EtkVolumeKey ([string]$_.VolumeName) }
        $copiesOut = @()
        $inFlight = @()
        foreach ($grp in ($byVol | Sort-Object { $vmap[$_.Name] })) {
            $letter = $vmap[[string]$grp.Name]; if (-not $letter) { $letter = [string]$grp.Name }
            $times = @($grp.Group | Where-Object { $_.Persistent } | ForEach-Object { $_.InstallDate } | Where-Object { $_ })
            $persistent = @($grp.Group | Where-Object { $_.Persistent })
            $clientAcc = @($grp.Group | Where-Object { $_.ClientAccessible })
            $transient = @($grp.Group | Where-Object { -not $_.Persistent })
            foreach ($x in $transient) { $inFlight += [pscustomobject]@{ volume = $letter; created = $x.InstallDate } }
            $cad = Get-EtkSnapshotCadence -Times ([datetime[]]$times)
            $exWhat = $ExchangeVolumes[$letter.TrimEnd('\').ToUpperInvariant()]
            $st = 'info'
            $det = ('{0} persistent, {1} client-accessible (Previous Versions type), {2} non-persistent.' -f $persistent.Count, $clientAcc.Count, $transient.Count)
            if ($exWhat -and $persistent.Count -gt 0) {
                $st = 'warn'
                $det = ('Holds {0}. While a snapshot exists, the first write to every block costs an extra copy, and that data is written constantly. ' -f (@($exWhat) -join ', ')) + $det
            }
            # The date range covers every snapshot; only the cadence is
            # restricted to persistent ones (a transient backup snapshot is
            # not part of a schedule).
            $allTimes = @($grp.Group | ForEach-Object { $_.InstallDate } | Where-Object { $_ } | Sort-Object)
            $oldest = ($allTimes | Select-Object -First 1)
            $newest = ($allTimes | Select-Object -Last 1)
            $rows.Add((New-EtkRow -Group $g -Check $letter -Result ('{0} snapshots, {1} to {2}' -f $grp.Count, (ConvertTo-EtkLocalStamp $oldest), (ConvertTo-EtkLocalStamp $newest)) -Status $st -Detail $det))
            if ($cad.guess) {
                $rows.Add((New-EtkRow -Group $g -Check ('{0} cadence' -f $letter) -Result $cad.guess -Basis 'inference' -Status 'info' `
                    -Detail ('Median gap {0} h across {1} snapshots. Who takes them is an inference from the timing; confirm in the product.' -f $cad.intervalHours, $cad.samples)))
            }
            foreach ($s in @($grp.Group | Sort-Object InstallDate -Descending | Select-Object -First 3)) {
                $rows.Add((New-EtkRow -Group $g -Check ('{0} {1}' -f $letter, (ConvertTo-EtkLocalStamp $s.InstallDate)) -Result ([string]$s.ID) -Status 'info' `
                    -Detail ('{0}{1}' -f $(if ($s.Persistent) { 'Persistent. ' } else { '' }), $(if ($s.ClientAccessible) { 'Client-accessible (Previous Versions).' } else { 'Created by an application (backup / EDR).' })) `
                    -Actions @(New-EtkActionRef -Id 'shadow-delete' -Arguments @{ ShadowId = [string]$s.ID; Volume = $letter } -Label 'Delete this shadow copy')))
            }
            $copiesOut += [pscustomobject]@{ volume = $letter; count = $grp.Count; persistent = $persistent.Count; clientAccessible = $clientAcc.Count
                oldestUtc = (ConvertTo-EtkIso8601 $oldest); newestUtc = (ConvertTo-EtkIso8601 $newest); cadence = $cad }
        }
        if ($inFlight.Count -gt 0) {
            # Non-persistent snapshots exist only while the program that made
            # them is using them - normally a backup that is running now.
            $first = ($inFlight | Sort-Object created | Select-Object -First 1).created
            $vols = (@($inFlight | ForEach-Object { $_.volume } | Sort-Object -Unique) -join ', ')
            $age = (Get-Date) - [datetime]$first
            $rows.Add((New-EtkRow -Group $g -Check 'Snapshots in use right now' -Result ('{0} held since {1} ({2})' -f $vols, (ConvertTo-EtkLocalStamp $first), (Format-EtkAge $age)) -Basis 'inference' `
                -Status $(if ($age.TotalHours -gt 2) { 'warn' } else { 'info' }) `
                -Detail 'Non-persistent snapshots exist only while a backup (or a file-level agent using VSS) is reading them. While held, every write to those volumes pays the copy-on-write penalty. One held for hours means a backup that runs long or never lets go.'))
        }
        if ($sc.Count -eq 0) { $rows.Add((New-EtkRow -Group $g -Check 'All volumes' -Result 'No shadow copies' -Status 'ok')) }
        foreach ($s in $storage) {
            $vol = $null; $diff = $null
            try { $vol = $vmap[(ConvertTo-EtkVolumeKey ([string]$s.Volume.DeviceID))]; $diff = $vmap[(ConvertTo-EtkVolumeKey ([string]$s.DiffVolume.DeviceID))] } catch { }
            if (-not $vol) { $vol = ([string]$s.Volume) -replace '.*DeviceID="([^"]+)".*', '$1' -replace '\\\\', '\'; $k = ConvertTo-EtkVolumeKey $vol; if ($vmap[$k]) { $vol = $vmap[$k] } }
            if ([double]$s.UsedSpace -le 0) { continue }
            $rows.Add((New-EtkRow -Group $g -Check ('{0} storage area' -f $vol) -Result ('{0} used of {1} max' -f (Format-EtkBytes $s.UsedSpace), (Format-EtkBytes $s.MaxSpace)) -Status 'info' `
                -Detail 'Space holding the old copies of blocks changed since each snapshot. Large and growing on an Exchange volume = a lot of write activity paying the snapshot penalty.'))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'CIM Win32_ShadowCopy / Win32_ShadowStorage / Win32_Volume' -Rows $rows.ToArray() `
            -Data ([pscustomobject]@{ volumes = [object[]]$copiesOut })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkAgentCatalog {
    # Service-name and display-name patterns for products that snapshot or
    # read the disks. The product name is an inference from these patterns.
    @(
        @{ product = 'StorageCraft ShadowProtect / SPX'; kind = 'image backup';      pattern = '^(SPXService|ShadowProtect|ShadowProtectSvc|stc_)|StorageCraft' }
        @{ product = 'Veeam Agent';                      kind = 'image backup';      pattern = '^VeeamEndpointBackupSvc$|Veeam Agent' }
        @{ product = 'Veeam Backup & Replication';       kind = 'backup server';     pattern = '^VeeamBackupSvc$|Veeam Backup Service' }
        @{ product = 'Acronis';                          kind = 'image backup';      pattern = 'Acronis|^(AcrSch2Svc|MMS|AcronisAgent)$' }
        @{ product = 'Datto / Shadowsnap';               kind = 'image backup';      pattern = 'Datto|ShadowSnap|^(DattoBackupAgent)$' }
        @{ product = 'Arcserve';                         kind = 'image backup';      pattern = 'Arcserve|^(CASAD2DWebSvc)$' }
        @{ product = 'Windows Server Backup';            kind = 'image backup';      pattern = '^wbengine$' }
        @{ product = 'CrashPlan / Code42';               kind = 'file backup';       pattern = 'CrashPlan|Code42' }
        @{ product = 'Carbonite';                        kind = 'file backup';       pattern = 'Carbonite' }
        @{ product = 'Commvault';                        kind = 'backup agent';      pattern = 'Commvault|^GxCVD' }
        @{ product = 'SentinelOne';                      kind = 'EDR (snapshots)';   pattern = 'SentinelOne|^Sentinel(Agent|HelperService|StaticEngine)' }
    )
}

function Find-EtkAgents {
    # Pure. Matches services (Name, DisplayName, State, StartMode) against
    # the catalogue.
    param($Services)
    $out = @()
    foreach ($c in (Get-EtkAgentCatalog)) {
        $hits = @($Services | Where-Object { [string]$_.Name -match $c.pattern -or [string]$_.DisplayName -match $c.pattern })
        if ($hits.Count -eq 0) { continue }
        $running = @($hits | Where-Object { [string]$_.State -eq 'Running' })
        $out += [pscustomobject]@{ product = $c.product; kind = $c.kind; services = [object[]]@($hits | ForEach-Object { '{0} ({1})' -f $_.Name, $_.State }); active = ($running.Count -gt 0) }
    }
    return $out
}

function Test-EtkAgents {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Backup & snapshot software'
    try {
        $svc = @(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode)
        $found = @(Find-EtkAgents -Services $svc)
        foreach ($a in $found) {
            $rows.Add((New-EtkRow -Group $g -Check $a.product -Result $(if ($a.active) { 'Active' } else { 'Installed, not running' }) -Basis 'inference' -Status 'info' `
                -Detail ('{0}. Services: {1}' -f $a.kind, ($a.services -join ', '))))
        }
        $imaging = @($found | Where-Object { $_.active -and $_.kind -match 'image backup|EDR' })
        if ($imaging.Count -gt 1) {
            $rows.Add((New-EtkRow -Group $g -Check 'Overlap' -Result ('{0} products that snapshot the disks are active' -f $imaging.Count) -Basis 'inference' -Status 'warn' `
                -Detail ('{0}. Each takes its own snapshots and calls the VSS writers (Exchange freezes writes briefly every time). One Exchange-aware backup is enough; exclude the Exchange folders from everything else and turn off EDR snapshot features for this server.' -f (($imaging | ForEach-Object { $_.product }) -join ', '))))
        }
        if ($found.Count -eq 0) { $rows.Add((New-EtkRow -Group $g -Check 'Known products' -Result 'None recognised' -Basis 'inference' -Status 'info' -Detail 'Only products in the built-in list are recognised.')) }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'CIM Win32_Service matched against a vendor list' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function ConvertFrom-EtkSentinelConfig {
    # Pure. `SentinelCtl.exe configure` (no arguments) prints one setting per
    # line as "key<spaces>value", e.g.
    #   agent.vssSnapshots                                        true
    # Returns key -> value as strings.
    param([string]$Text)
    $map = @{}
    foreach ($ln in ($Text -split "`r?`n")) {
        $m = [regex]::Match($ln, '^\s*([A-Za-z][\w\.\-]*)\s{2,}(\S.*?)\s*$')
        if ($m.Success) { $map[$m.Groups[1].Value] = $m.Groups[2].Value }
    }
    return $map
}

function Find-EtkSentinelCtl {
    # The agent lives in a versioned folder; take the newest one present.
    $root = Join-Path $env:ProgramFiles 'SentinelOne'
    if (-not (Test-Path -LiteralPath $root)) { return $null }
    $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Filter 'Sentinel Agent*' -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'SentinelCtl.exe') })
    if ($dirs.Count -eq 0) { return $null }
    $best = $dirs | Sort-Object { $v = $null; [void][version]::TryParse(($_.Name -replace '^Sentinel Agent\s*', ''), [ref]$v); $v } -Descending | Select-Object -First 1
    return (Join-Path $best.FullName 'SentinelCtl.exe')
}

function Test-EtkSentinelSnapshots {
    # Measured, not inferred: reads the agent's own local configuration.
    # The 4-hourly shadow-copy cadence only SUGGESTS SentinelOne; this says
    # whether its snapshot feature is switched on in this agent. The key name
    # (agent.vssSnapshots) was read from agent 25.2.6.442 on a live server.
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'SentinelOne snapshots'
    $exe = Find-EtkSentinelCtl
    if (-not $exe) { return (New-EtkSection -State skipped -Reason 'SentinelOne agent (SentinelCtl.exe) not found.') }
    if (-not (Test-EtkElevated)) { return (New-EtkSection -State unsupported -Reason 'Reading the SentinelOne agent configuration needs an elevated session.') }
    try {
        $r = Invoke-EtkNative -FilePath $exe -ArgumentList @('configure')
        $cfg = ConvertFrom-EtkSentinelConfig -Text $r.output
        $ver = Split-Path (Split-Path $exe -Parent) -Leaf
        if ($cfg.Count -eq 0) {
            $sw.Stop()
            return Set-EtkSectionTiming (New-EtkSection -State failed -Reason ('SentinelCtl configure returned no settings (exit {0}): {1}' -f $r.exitCode, (Get-EtkFirstLine $r.output))) $t0 $sw.Elapsed.TotalSeconds
        }
        $vss = $cfg['agent.vssSnapshots']
        if ($null -eq $vss) {
            $rows.Add((New-EtkRow -Group $g -Check 'agent.vssSnapshots' -Result 'Setting not present in this agent version' -Basis 'not measured' -Status 'info' `
                -Detail ('{0}. Look for a snapshot/VSS key with: SentinelCtl.exe configure | Select-String vss' -f $ver)))
        } elseif ($vss -match '^(true|1|yes|on)$') {
            $rows.Add((New-EtkRow -Group $g -Check 'agent.vssSnapshots' -Result 'ON - this agent takes VSS snapshots (Rollback)' -Basis 'measured' -Status 'warn' `
                -Detail ('{0}. On a server with Exchange-aware image backups this duplicates them and slows every write while the snapshots exist. Turn it off in a console policy for servers (a local change with SentinelCtl configure -k <passphrase> -p agent.vssSnapshots -v false can be reverted by the next policy sync). Existing snapshots stay until deleted.' -f $ver)))
        } else {
            $rows.Add((New-EtkRow -Group $g -Check 'agent.vssSnapshots' -Result ('Off ({0})' -f $vss) -Basis 'measured' -Status 'ok' `
                -Detail ('{0}. No new SentinelOne snapshots. Snapshots taken before it was switched off remain until deleted - see Shadow copies. If it was changed locally, recheck after the next policy sync.' -f $ver)))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('{0} configure' -f $exe) -Rows $rows.ToArray() `
            -Data ([pscustomobject]@{ agentVersion = $ver; vssSnapshots = $vss })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Get-EtkCrashPlanPattern {
    # Both slash directions: W lines use backslashes, I lines (files actually
    # backed up) use forward slashes - seen side by side on a live server.
    '\.edb\b|[\\/]E0[0-9A-F]*(tmp)?\.log|TransportRoles|[\\/]Exchange Server[\\/]'
}

function ConvertFrom-EtkCrashPlanLine {
    # Pure. One backup_files.log line. Two shapes seen on a live server:
    #   W 10/24/26 07:50AM 62  - D:\Exchange Server\...\E00.log
    #   I 10/24/26 09:37AM 62 <md5> 0 D:/Exchange Server/.../x.edb (250450280448) [317,...]
    # An I line carries the file size and a block-hash list, so it records a
    # file CrashPlan READ and backed up; a W line has neither (most likely a
    # file it could not open). Dates are US month/day/year.
    param([string]$Line)
    $m = [regex]::Match($Line, '^(?<k>[A-Z])\s+(?<d>\d{1,2}/\d{1,2}/\d{2})\s+(?<t>\d{1,2}:\d{2}[AP]M)\s+(?<rest>.*)$')
    if (-not $m.Success) { return $null }
    $when = $null
    $dt = [datetime]::MinValue
    # [string[]] is load-bearing: an untyped @(...) is object[], PowerShell
    # binds a different TryParseExact overload, and every date fails to parse.
    # AssumeLocal too: the log is in the server's wall-clock time, and an
    # "Unspecified" kind is later treated as UTC and shifted by the offset.
    if ([datetime]::TryParseExact(('{0} {1}' -f $m.Groups['d'].Value, $m.Groups['t'].Value), [string[]]@('M/d/yy h:mmtt', 'MM/dd/yy hh:mmtt'), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$dt)) { $when = $dt }
    $rest = $m.Groups['rest'].Value
    $p = [regex]::Match($rest, '(?<path>[A-Za-z]:[\\/].+?)(\s+\((?<size>\d+)\))?(\s+\[.*)?\s*$')
    [pscustomobject]@{
        kind = $m.Groups['k'].Value
        when = $when
        path = $(if ($p.Success) { $p.Groups['path'].Value.Trim() } else { $null })
        size = $(if ($p.Success -and $p.Groups['size'].Success) { [double]$p.Groups['size'].Value } else { $null })
    }
}

function Get-EtkCrashPlanSummary {
    # Pure. From the Exchange-matching lines: how often CrashPlan actually
    # read the live database, when it last did, and how many attempts failed.
    #
    # A plain loop that fully parses only the database reads: the live server
    # had 137,000 matching lines, and parsing every one through the pipeline
    # took 49 s. Lines arrive in file order (oldest file first, each file in
    # time order), so the last W line seen is the latest.
    param([string[]]$Lines)
    $edbReads = New-Object System.Collections.Generic.List[object]
    $otherReads = 0; $failed = 0; $lastFail = $null
    foreach ($ln in $Lines) {
        if ([string]::IsNullOrEmpty($ln)) { continue }
        $k = $ln[0]
        if ($k -eq 'I') {
            if ($ln.IndexOf('.edb', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $p = ConvertFrom-EtkCrashPlanLine $ln
                if ($p -and $p.path -match '\.edb$') { $edbReads.Add($p) } else { $otherReads++ }
            } else { $otherReads++ }
        } elseif ($k -eq 'W') { $failed++; $lastFail = $ln }
    }
    $sorted = @($edbReads | Sort-Object when)
    $latest = $null; if ($sorted.Count) { $latest = $sorted[$sorted.Count - 1] }
    $lf = $null; if ($lastFail) { $lf = (ConvertFrom-EtkCrashPlanLine $lastFail).when }
    [pscustomobject]@{
        edbReads = $sorted.Count
        edbReadDays = @($sorted | Where-Object { $_.when } | ForEach-Object { $_.when.Date } | Sort-Object -Unique).Count
        latestEdbRead = $(if ($latest) { $latest.when } else { $null })
        latestEdbSize = $(if ($latest) { $latest.size } else { $null })
        otherReads = $otherReads
        failed = $failed
        latestFail = $lf
    }
}

function Find-EtkCrashPlanExchangeLines {
    # Pure. Lines of CrashPlan's backup_files.log that name Exchange data.
    param([string[]]$Lines)
    $p = Get-EtkCrashPlanPattern
    @($Lines | Where-Object { $_ -match $p })
}

function Test-EtkCrashPlan {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'CrashPlan'
    $dir = Join-Path $env:ProgramData 'CrashPlan\log'
    if (-not (Test-Path -LiteralPath $dir)) { return (New-EtkSection -State skipped -Reason ('CrashPlan log folder not found ({0}).' -f $dir)) }
    try {
        # Files in DATE order, newest last, so "latest" really is latest.
        $files = @(Get-ChildItem -LiteralPath $dir -Filter 'backup_files.log*' -File -ErrorAction Stop | Sort-Object LastWriteTime)
        # Streamed, not collected: += on an array of every line took 58 s on
        # a live server. FileShare.ReadWrite because CrashPlan holds the
        # current log open for writing.
        $rx = New-Object System.Text.RegularExpressions.Regex((Get-EtkCrashPlanPattern), 'Compiled')
        $hits = New-Object System.Collections.Generic.List[string]
        $lineCount = 0
        foreach ($f in $files) {
            try {
                $fs = New-Object System.IO.FileStream($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $rd = New-Object System.IO.StreamReader($fs)
                try {
                    while ($null -ne ($ln = $rd.ReadLine())) { $lineCount++; if ($rx.IsMatch($ln)) { $hits.Add($ln) } }
                } finally { $rd.Dispose() }
            } catch { }
        }
        if ($hits.Count -eq 0) {
            $rows.Add((New-EtkRow -Group $g -Check 'Exchange files in backup log' -Result 'None' -Status 'ok' -Detail ('{0} lines checked in {1} log files.' -f $lineCount, $files.Count)))
        } else {
            $sum = Get-EtkCrashPlanSummary -Lines $hits.ToArray()
            if ($sum.edbReads -gt 0) {
                $rows.Add((New-EtkRow -Group $g -Check 'Live Exchange database READ by CrashPlan' -Result ('{0} times on {1} day(s); latest {2}, {3}' -f $sum.edbReads, $sum.edbReadDays, (ConvertTo-EtkLocalStamp $sum.latestEdbRead), (Format-EtkBytes $sum.latestEdbSize)) `
                    -Status 'warn' `
                    -Detail 'CrashPlan read the whole live database file (an "I" line with size and block hashes). On Windows it does that from a VSS snapshot of every volume, held for as long as the read takes - every write to those volumes pays the snapshot penalty meanwhile - and the copy is not an Exchange-consistent backup. Exclude the Exchange folders in the CrashPlan console; the image backup already covers Exchange properly.'))
            }
            if ($sum.failed -gt 0) {
                $rows.Add((New-EtkRow -Group $g -Check 'Exchange files CrashPlan could not read' -Result ('{0} attempts; latest {1}' -f $sum.failed, (ConvertTo-EtkLocalStamp $sum.latestFail)) -Status $(if ($sum.edbReads -gt 0) { 'info' } else { 'warn' }) `
                    -Detail '"W" lines - most likely files that were locked open. Wasted attempts; same fix: exclude the Exchange folders.'))
            }
            if ($sum.otherReads -gt 0) {
                $rows.Add((New-EtkRow -Group $g -Check 'Other Exchange files read' -Result ('{0} (logs, queue)' -f $sum.otherReads) -Status 'info'))
            }
            if ($sum.edbReads -eq 0 -and $sum.failed -eq 0) {
                $rows.Add((New-EtkRow -Group $g -Check 'Exchange files in backup log' -Result ('{0} entries; latest: {1}' -f $hits.Count, (Get-EtkFirstLine $hits[$hits.Count - 1] 160)) -Status 'warn' `
                    -Detail 'CrashPlan''s selection includes Exchange files. Exclude the Exchange folders in the CrashPlan console.'))
            }
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('{0}\backup_files.log*' -f $dir) -Rows $rows.ToArray() `
            -Caveats @('Code42 does not document the log format. I lines carry a size and block hashes (file read and backed up); W lines carry neither (most likely could not be read).')) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkInWindow {
    # Pure. Is a time of day ("HH:mm") inside [start, end)? Handles a window
    # that crosses midnight.
    param([string]$Time, [string]$Start, [string]$End)
    try {
        $t = [timespan]::Parse($Time); $s = [timespan]::Parse($Start); $e = [timespan]::Parse($End)
    } catch { return $false }
    if ($s -le $e) { return ($t -ge $s -and $t -lt $e) }
    return ($t -ge $s -or $t -lt $e)
}

function Format-EtkDaysOfWeek {
    # Task Scheduler stores weekdays as a bitmask: Sun=1 Mon=2 ... Sat=64.
    param([string]$Mask)
    $n = 0
    if (-not [int]::TryParse($Mask, [ref]$n) -or $n -le 0) { return $Mask }
    if ($n -eq 62) { return 'Mon-Fri' }
    if ($n -eq 127) { return 'every day' }
    $names = @('Sun','Mon','Tue','Wed','Thu','Fri','Sat')
    $out = @(); for ($i = 0; $i -lt 7; $i++) { if ($n -band (1 -shl $i)) { $out += $names[$i] } }
    return ($out -join ',')
}

function Format-EtkRepeat {
    param([string]$Iso)
    if ([string]::IsNullOrWhiteSpace($Iso)) { return '' }
    try { $t = [System.Xml.XmlConvert]::ToTimeSpan($Iso) } catch { return $Iso }
    if ($t.TotalHours -ge 1 -and $t.TotalHours -eq [math]::Floor($t.TotalHours)) { return ('every {0} h' -f $t.TotalHours) }
    return ('every {0} min' -f $t.TotalMinutes)
}

function ConvertTo-EtkScheduleEntries {
    # Pure. Flattens plain task records (TaskName, TaskPath, Action, Triggers
    # with Kind/StartBoundary/DaysOfWeek/Interval, LastRunTime, LastResult,
    # Author, Created) into one entry per trigger, with flags.
    param($Tasks, [string]$WindowStart = '05:00', [string]$WindowEnd = '09:00', [hashtable]$ExchangeVolumes = @{}, [hashtable]$VolumeLetters = @{})
    $out = @()
    foreach ($t in @($Tasks)) {
        $action = [string]$t.Action
        $isShadow = ([string]$t.TaskName -match '^ShadowCopyVolume(\{[0-9a-fA-F-]+\})')
        $vol = $null
        if ($isShadow) {
            $guid = $Matches[1]
            $vol = $VolumeLetters[$guid.ToLowerInvariant()]
            if (-not $vol -and $action -match 'Volume(\{[0-9a-fA-F-]+\})') { $vol = $VolumeLetters[$Matches[1].ToLowerInvariant()] }
        }
        $isReboot = ($action -match 'shutdown(\.exe)?["\s].*(/r|/s|-r|-s)\b' -or $action -match 'Restart-Computer|Stop-Computer')
        # Jobs that load the disks or the server - the ones worth a warning
        # when they land in the busy window. An updater checking in is not.
        $isHeavy = ($isShadow -or $isReboot -or $action -match '(?i)vssadmin|wbadmin|backup|robocopy|FreeFileSync|defrag|chkdsk|Optimize-Volume|ShadowProtect|Veeam|Acronis|CrashPlan|sqlcmd|\.bak\b')
        foreach ($tr in @($t.Triggers)) {
            # Only calendar triggers have a time of day. A logon or boot
            # trigger's StartBoundary is an activation date, and showing it as
            # "00:00" would invent a schedule. A one-off trigger in the past
            # never fires again, so it is not "inside the window" either.
            $kind = [string]$tr.Kind
            $tod = ''; $past = $false
            if ($tr.StartBoundary -and ($kind -in @('Daily', 'Weekly', 'Time', 'Monthly', 'MonthlyDOW', ''))) {
                try {
                    $sb = [datetime]$tr.StartBoundary
                    $tod = $sb.ToString('HH:mm')
                    if ($kind -eq 'Time' -and -not $tr.Interval -and $sb -lt (Get-Date)) { $past = $true }
                } catch { }
            }
            $inWin = ($tod -and -not $past -and (Test-EtkInWindow -Time $tod -Start $WindowStart -End $WindowEnd))
            # A task that repeats more often than the window is long fires
            # inside it whatever its start time (repetition assumed to run
            # all day - the usual setting).
            if (-not $inWin -and $tod -and -not $past -and $tr.Interval) {
                try {
                    $iv = [System.Xml.XmlConvert]::ToTimeSpan([string]$tr.Interval)
                    $ws = [timespan]::Parse($WindowStart); $we = [timespan]::Parse($WindowEnd)
                    $len = ($we - $ws).TotalMinutes; if ($len -le 0) { $len += 1440 }
                    if ($iv.TotalMinutes -gt 0 -and $iv.TotalMinutes -le $len) { $inWin = $true }
                } catch { }
            }
            $exVol = $null
            if ($vol) { $exVol = $ExchangeVolumes[$vol.TrimEnd('\').ToUpperInvariant()] }
            if ($past) { $kind = 'one-off, already ran' }
            $out += [pscustomobject]@{
                task = ('{0}{1}' -f $t.TaskPath, $t.TaskName); name = [string]$t.TaskName; time = $tod; kind = $kind
                days = (Format-EtkDaysOfWeek ([string]$tr.DaysOfWeek)); repeat = (Format-EtkRepeat ([string]$tr.Interval)); action = $action; state = [string]$t.State
                lastRun = $t.LastRunTime; lastResult = $t.LastResult; author = [string]$t.Author; created = $t.Created
                shadowVolume = $vol; touchesExchange = [bool]$exVol; exchangeWhat = $exVol; isReboot = $isReboot; isHeavy = $isHeavy; inWindow = $inWin
            }
        }
        if (@($t.Triggers).Count -eq 0) {
            $out += [pscustomobject]@{ task = ('{0}{1}' -f $t.TaskPath, $t.TaskName); name = [string]$t.TaskName; time = ''; kind = 'none'; days = ''; repeat = ''
                action = $action; state = [string]$t.State; lastRun = $t.LastRunTime; lastResult = $t.LastResult; author = [string]$t.Author; created = $t.Created
                shadowVolume = $vol; touchesExchange = $false; exchangeWhat = $null; isReboot = $isReboot; isHeavy = $isHeavy; inWindow = $false }
        }
    }
    return @($out | Sort-Object @{ Expression = { if ($_.time) { $_.time } else { '99:99' } } }, task)
}

function Get-EtkScheduledTaskRecords {
    # Non-Microsoft tasks plus the Previous Versions tasks (which live in the
    # root folder but are created by Windows), as plain records.
    $tasksDir = Join-Path $env:SystemRoot 'System32\Tasks'
    $out = @()
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -or $_.TaskName -like 'ShadowCopyVolume*' })) {
        $info = $null
        try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }
        $created = $null
        try {
            $f = Join-Path $tasksDir (($t.TaskPath.TrimStart('\')) + $t.TaskName)
            if (Test-Path -LiteralPath $f -ErrorAction SilentlyContinue) { $created = ConvertTo-EtkIso8601 (Get-Item -LiteralPath $f -Force -ErrorAction Stop).CreationTime }
        } catch { }
        if (-not $created -and $t.Date) { try { $created = ConvertTo-EtkIso8601 ([datetime]$t.Date) } catch { } }
        $trig = @()
        foreach ($tr in @($t.Triggers)) {
            $kind = ($tr.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', '')
            $days = ''
            try { if ($tr.DaysOfWeek) { $days = [string]$tr.DaysOfWeek } } catch { }
            $iv = ''
            try { if ($tr.Repetition -and $tr.Repetition.Interval) { $iv = [string]$tr.Repetition.Interval } } catch { }
            $trig += [pscustomobject]@{ Kind = $kind; StartBoundary = [string]$tr.StartBoundary; DaysOfWeek = $days; Interval = $iv; Enabled = [bool]$tr.Enabled }
        }
        $act = (@($t.Actions) | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join ' | '
        $out += [pscustomobject]@{
            TaskName = [string]$t.TaskName; TaskPath = [string]$t.TaskPath; State = [string]$t.State; Action = $act; Triggers = [object[]]$trig
            Author = [string]$t.Author; Created = $created
            LastRunTime = $(if ($info) { ConvertTo-EtkIso8601 $info.LastRunTime } else { $null })
            LastResult = $(if ($info) { [string]$info.LastTaskResult } else { $null })
        }
    }
    return $out
}

function Test-EtkSchedule {
    param([string]$WindowStart = '05:00', [string]$WindowEnd = '09:00', [hashtable]$ExchangeVolumes = @{})
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.Generic.List[object]
    $g = 'Schedule'
    try {
        $letters = @{}
        foreach ($v in @(Get-CimInstance Win32_Volume -ErrorAction SilentlyContinue)) {
            if ($v.DeviceID -match '(\{[0-9a-fA-F-]+\})' -and $v.DriveLetter) { $letters[$Matches[1].ToLowerInvariant()] = [string]$v.DriveLetter }
        }
        $records = @(Get-EtkScheduledTaskRecords)
        $entries = @(ConvertTo-EtkScheduleEntries -Tasks $records -WindowStart $WindowStart -WindowEnd $WindowEnd -ExchangeVolumes $ExchangeVolumes -VolumeLetters $letters)
        foreach ($e in $entries) {
            $flags = @()
            $st = 'info'
            if ($e.inWindow) {
                $flags += ('runs inside the busy window {0}-{1}' -f $WindowStart, $WindowEnd)
                if ($e.isHeavy) { $st = 'warn' }
            }
            if ($e.isReboot) {
                $flags += 'restarts or shuts down the server'
                # A one-off that already fired will never run again.
                if ($e.kind -ne 'one-off, already ran') { $st = 'warn' }
            }
            if ($e.touchesExchange) { $flags += ('snapshots {0} (holds {1})' -f $e.shadowVolume, (@($e.exchangeWhat) -join ', ')); $st = 'warn' }
            if ($e.state -eq 'Disabled') { $st = 'info'; $flags += 'disabled' }
            $label = $e.name
            if ($e.shadowVolume) { $label = ('Previous Versions snapshot of {0}' -f $e.shadowVolume) }
            $when = $(if ($e.time) { $e.time } else { '(no time)' })
            $sched = (@($e.kind, $e.days, $e.repeat) | Where-Object { $_ }) -join ', '
            $acts = @()
            if ($e.name -like 'ShadowCopyVolume*') {
                if ($e.state -eq 'Disabled') { $acts = @(New-EtkActionRef -Id 'task-enable' -Arguments @{ TaskName = $e.name; TaskPath = ($e.task.Substring(0, $e.task.Length - $e.name.Length)) } -Label 'Enable this task') }
                else { $acts = @(New-EtkActionRef -Id 'task-disable' -Arguments @{ TaskName = $e.name; TaskPath = ($e.task.Substring(0, $e.task.Length - $e.name.Length)) } -Label 'Disable this task') }
            }
            $rows.Add((New-EtkRow -Group $g -Check ('{0}  {1}' -f $when, $label) -Result $sched -Status $st `
                -Detail ('{0}{1}Action: {2}. Last run {3} (result {4}). Created {5} by {6}.' -f ($flags -join '; '), $(if ($flags.Count) { '. ' } else { '' }), $e.action, (ConvertTo-EtkLocalStamp $e.lastRun), $e.lastResult, (ConvertTo-EtkLocalStamp $e.created), $(if ($e.author) { $e.author } else { 'unknown' })) `
                -Actions $acts))
        }
        if ($entries.Count -eq 0) { $rows.Add((New-EtkRow -Group $g -Check 'Scheduled tasks' -Result 'No non-Microsoft tasks' -Status 'ok')) }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-ScheduledTask (non-\Microsoft\ plus ShadowCopyVolume*), task file creation time' -Rows $rows.ToArray() `
            -Data ([pscustomobject]@{ entries = [object[]]$entries })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkExchangeBackup {
    param($Databases)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Exchange backups'
    if (-not (Test-EtkExchangeAvailable)) { return (Get-EtkExchangeUnavailableSection $g) }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Databases)) {
        $last = $null
        foreach ($s in @($d.lastFull, $d.lastIncr)) { if ($s) { $x = [datetime]$s; if (-not $last -or $x -gt $last) { $last = $x } } }
        $st = 'fail'; $res = 'Never'
        if ($last) {
            $age = (Get-Date) - $last
            $res = ('{0} ({1} ago)' -f (ConvertTo-EtkLocalStamp $last), (Format-EtkAge $age))
            if ($age.TotalDays -le 2) { $st = 'ok' } elseif ($age.TotalDays -le 7) { $st = 'warn' }
        }
        if ($d.circular -and $st -ne 'ok') { $st = 'warn' }
        $rows.Add((New-EtkRow -Group $g -Check ('{0} last Exchange-aware backup' -f $d.name) -Result $res -Basis 'server-reported' -Status $st `
            -Detail ('Full: {0}. Incremental: {1}. Only a backup that calls the Exchange VSS writer moves these dates and truncates logs; an image or file backup that skips the writer does not count.{2}' -f `
                $(if ($d.lastFull) { ConvertTo-EtkLocalStamp $d.lastFull } else { 'never' }), $(if ($d.lastIncr) { ConvertTo-EtkLocalStamp $d.lastIncr } else { 'never' }), $(if ($d.circular) { ' Circular logging is on, so logs do not depend on backups.' } else { '' }))))
    }
    $sw.Stop()
    return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Get-MailboxDatabase -Status (LastFullBackup / LastIncrementalBackup)' -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
}

# ===========================================================================
#  SECURITY (OS-level, remote-capable)
#
#  Failed logins by source address, recent interactive/RDP logons, and what
#  this server's own firewall lets in. Read-only, and nothing here sends
#  anything off the server: the optional IP location lookup is separate,
#  runs only from its button, and a test proves no check calls it.
# ===========================================================================

function Test-EtkPublicIp {
    # Pure. True only for a routable public address. Private, loopback,
    # link-local, CGNAT, unspecified, multicast, unique-local IPv6 and
    # anything that is not an address at all are false.
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $false }
    $s = $Ip.Trim()
    # [IPAddress]::TryParse accepts "1" as 0.0.0.1 - insist on a real shape.
    if ($s -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and $s -notmatch ':') { return $false }
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($s, [ref]$addr)) { return $false }
    if ($addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() }
    $b = $addr.GetAddressBytes()
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }   # carrier-grade NAT
        if ($b[0] -ge 224) { return $false }                                          # multicast and reserved
        return $true
    }
    if ([System.Net.IPAddress]::IsLoopback($addr) -or $addr.IsIPv6LinkLocal -or $addr.IsIPv6SiteLocal -or $addr.IsIPv6Multicast) { return $false }
    if (($b[0] -band 0xFE) -eq 0xFC) { return $false }                                # fc00::/7 unique local
    if (@($b | Where-Object { $_ -ne 0 }).Count -eq 0) { return $false }              # ::
    return $true
}

function Test-EtkAccessDenied {
    param([string]$Message)
    return ($Message -match 'unauthorized operation|Access is denied|access to the path .* is denied')
}

function ConvertFrom-EtkSmtpAuthMessage {
    # Pure. Event 1035 names the receive connector and ends with the source
    # address in square brackets. It does NOT name the account tried.
    param([string]$Message)
    $ip = ''; $conn = ''
    $all = [regex]::Matches([string]$Message, '\[([0-9A-Fa-f\.:]+)\]')
    if ($all.Count) { $ip = $all[$all.Count - 1].Groups[1].Value }
    $c = [regex]::Match([string]$Message, 'Receive connector (.+?)\.\s')
    if ($c.Success) { $conn = $c.Groups[1].Value.Trim() }
    [pscustomobject]@{ ip = $ip; connector = $conn }
}

function ConvertFrom-EtkEventXml {
    # Pure. EventData by NAME, so a field moving position between Windows
    # versions cannot shift every value by one.
    param([string]$Xml)
    $h = @{}
    try {
        $x = [xml]$Xml
        foreach ($d in @($x.Event.EventData.Data)) {
            if ($d -is [System.Xml.XmlElement] -and $d.GetAttribute('Name')) { $h[$d.GetAttribute('Name')] = [string]$d.InnerText }
        }
    } catch { }
    return $h
}

function Get-EtkSecurityXPath {
    # Pure. Filtering in the query keeps the thousands of network logons
    # (type 3) on an Exchange server out of PowerShell entirely.
    param([int]$Id, [int]$Hours, [int[]]$LogonTypes = @())
    $ms = [int64]$Hours * 3600000
    $x = ('*[System[(EventID={0}) and TimeCreated[timediff(@SystemTime) <= {1}]]]' -f $Id, $ms)
    if ($LogonTypes.Count) {
        $x += (' and *[EventData[{0}]]' -f ((@($LogonTypes | ForEach-Object { "Data[@Name='LogonType']='$_'" })) -join ' or '))
    }
    return $x
}

function Get-EtkIisFieldIndex {
    # Pure. Column positions from an IIS '#Fields:' line.
    param([string]$Fields)
    $names = @(($Fields -replace '^#Fields:\s*', '') -split '\s+' | Where-Object { $_ })
    $ix = @{}
    for ($i = 0; $i -lt $names.Count; $i++) { $ix[$names[$i]] = $i }
    return $ix
}

function ConvertFrom-EtkIisFailure {
    # Pure. One IIS log line to a failed-login record, or $null. Only 401.1
    # (bad credentials) counts: 401.2 is the normal first leg of Negotiate /
    # NTLM, sent to every client before it authenticates.
    param([hashtable]$Index, [string]$Line)
    foreach ($k in @('date', 'time', 'c-ip', 'sc-status', 'sc-substatus')) { if (-not $Index.ContainsKey($k)) { return $null } }
    $p = $Line -split ' '
    if ($p.Count -le $Index['sc-substatus'] -or $p.Count -le $Index['c-ip']) { return $null }
    if ($p[$Index['sc-status']] -ne '401' -or $p[$Index['sc-substatus']] -ne '1') { return $null }
    $ts = [datetime]::MinValue
    if (-not [datetime]::TryParseExact(($p[$Index['date']] + ' ' + $p[$Index['time']]), 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$ts)) { return $null }
    $user = ''; if ($Index.ContainsKey('cs-username') -and $p.Count -gt $Index['cs-username']) { $user = [uri]::UnescapeDataString($p[$Index['cs-username']]) }
    if ($user -eq '-') { $user = '' }
    $uri = ''; if ($Index.ContainsKey('cs-uri-stem') -and $p.Count -gt $Index['cs-uri-stem']) { $uri = $p[$Index['cs-uri-stem']] }
    $app = ''
    if ($uri -match '^/([^/]+)') { $app = '/' + $Matches[1] }
    [pscustomobject]@{ when = $ts.ToLocalTime(); ip = $p[$Index['c-ip']]; source = 'IIS'; account = $user; detail = $app }
}

function Get-EtkFailedLoginSummary {
    # Pure. Failed-login records (when, ip, source, account, detail) to rows
    # per source address, a summary row, and the addresses worth a look.
    param($Records, [int]$Hours = 24, [int]$Top = 25, [int]$WarnPerIp = 10, [int]$WarnTotal = 100, [string]$Group = 'Failed logins')
    $list = @($Records | Where-Object { $_ })
    $by = @{}
    $srcTotals = @{}
    foreach ($r in $list) {
        $ip = ([string]$r.ip).Trim()
        if (-not $ip -or $ip -eq '-') { $ip = '(no address)' }
        if (-not $by.ContainsKey($ip)) {
            $by[$ip] = @{ ip = $ip; count = 0; first = $null; last = $null; sources = @{}; public = (Test-EtkPublicIp $ip)
                accounts = New-Object System.Collections.Generic.List[string]; seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                details = New-Object System.Collections.Generic.List[string] }
        }
        $e = $by[$ip]; $e.count++
        $w = [datetime]$r.when
        if ($null -eq $e.first -or $w -lt $e.first) { $e.first = $w }
        if ($null -eq $e.last -or $w -gt $e.last) { $e.last = $w }
        $src = [string]$r.source
        if ($e.sources.ContainsKey($src)) { $e.sources[$src]++ } else { $e.sources[$src] = 1 }
        if ($srcTotals.ContainsKey($src)) { $srcTotals[$src]++ } else { $srcTotals[$src] = 1 }
        $acc = ([string]$r.account).Trim()
        if ($acc -and $acc -ne '-' -and $e.seen.Add($acc)) { $e.accounts.Add($acc) }
        $det = [string]$r.detail
        if ($det -and -not $e.details.Contains($det)) { $e.details.Add($det) }
    }
    $fmtSources = { param($h) (@($h.Keys | Sort-Object { -[int]$h[$_] }, { $_ } | ForEach-Object { '{0} {1}' -f $_, $h[$_] })) -join ', ' }
    $entries = @($by.Values | Sort-Object @{ Expression = { $_.count }; Descending = $true }, @{ Expression = { $_.ip } })
    $publicEntries = @($entries | Where-Object { $_.public })
    $publicTotal = 0; foreach ($e in $publicEntries) { $publicTotal += $e.count }
    $suspect = [string[]]@($publicEntries | Where-Object { $_.count -ge $WarnPerIp } | ForEach-Object { $_.ip })
    $rows = New-Object System.Collections.Generic.List[object]
    if ($list.Count -eq 0) {
        $rows.Add((New-EtkRow -Group $Group -Check 'Failed logins' -Result ('None in the last {0} h' -f $Hours) -Basis 'server-reported' -Status 'ok'))
    } else {
        $st = 'info'; $det = ('By source: {0}.' -f (& $fmtSources $srcTotals))
        if ($publicTotal -ge $WarnTotal) {
            $st = 'warn'
            $det = ('Sustained password guessing from the internet. {0} Close the targeted port at the router or firewall if nothing outside needs it (587 is the usual one): blocking single addresses does not stop a spray, which rotates them.' -f $det)
        }
        $rows.Add((New-EtkRow -Group $Group -Check 'Failed logins' -Result ('{0} in {1} h from {2} address(es); {4} of them from {3} public address(es)' -f $list.Count, $Hours, $entries.Count, $publicEntries.Count, $publicTotal) `
            -Basis 'server-reported' -Status $st -Detail $det))
        $internal = @($entries | Where-Object { -not $_.public })
        $oneInternal = ($publicEntries.Count -eq 0 -and $internal.Count -eq 1 -and $internal[0].count -ge $WarnPerIp)
        foreach ($e in @($entries | Select-Object -First $Top)) {
            $acc = ''
            if ($e.accounts.Count) {
                $shown = @($e.accounts | Select-Object -First 8)
                $acc = 'Accounts tried: ' + ($shown -join ', ')
                if ($e.accounts.Count -gt 8) { $acc += (' (+{0} more)' -f ($e.accounts.Count - 8)) }
                $acc += '.'
            } elseif (@($e.sources.Keys) -contains 'SMTP AUTH') { $acc = 'SMTP AUTH failures (1035) do not record the account tried.' }
            $via = $(if ($e.details.Count) { ' Via: ' + ((@($e.details | Select-Object -First 4)) -join ', ') + '.' } else { '' })
            $note = ''
            if ($oneInternal) { $note = ' Every failure comes from this one internal address: it is probably the router or a reverse proxy, so the real sources are hidden from the server.' }
            $rows.Add((New-EtkRow -Group $Group -Check ('{0} ({1})' -f $e.ip, $(if ($e.public) { 'public' } elseif ($e.ip -eq '(no address)') { 'none recorded' } else { 'internal' })) `
                -Result ('{0} failures ({1}), {2} to {3}' -f $e.count, (& $fmtSources $e.sources), (ConvertTo-EtkLocalStamp $e.first), (ConvertTo-EtkLocalStamp $e.last)) `
                -Basis 'server-reported' -Status $(if ($e.public -and $e.count -ge $WarnPerIp) { 'warn' } else { 'info' }) -Detail (($acc + $via + $note).Trim())))
        }
        if ($entries.Count -gt $Top) {
            $rows.Add((New-EtkRow -Group $Group -Check ('{0} more address(es)' -f ($entries.Count - $Top)) -Result 'Not listed - fewer failures each' -Basis 'server-reported' -Status 'info'))
        }
    }
    [pscustomobject]@{ rows = [object[]]$rows.ToArray(); suspectIps = $suspect; publicIps = [string[]]@($publicEntries | ForEach-Object { $_.ip }); total = $list.Count; publicTotal = $publicTotal }
}

function Read-EtkSharedLines {
    # Lines of a file another process may be writing (IIS keeps today's log
    # open), read without taking a lock.
    param([string]$Path)
    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $sr = New-Object System.IO.StreamReader($fs)
    try { while ($null -ne ($ln = $sr.ReadLine())) { $ln } } finally { $sr.Dispose(); $fs.Dispose() }
}

function Test-EtkFailedLogins {
    param([int]$Hours = 24, [int]$Cap = 20000, [int]$IisBudgetSec = 30)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Failed logins'
    $records = New-Object System.Collections.Generic.List[object]
    $notMeasured = New-Object System.Collections.Generic.List[string]
    $caveats = New-Object System.Collections.Generic.List[string]
    $extraRows = New-Object System.Collections.Generic.List[object]
    $read = 0
    $since = (Get-Date).AddHours(-$Hours)
    try {
        # 1. SMTP AUTH failures on the client receive connectors.
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MSExchangeFrontEndTransport'; Id = 1035; StartTime = $since } -MaxEvents $Cap -ErrorAction Stop)
            foreach ($e in $ev) {
                $p = ConvertFrom-EtkSmtpAuthMessage $e.Message
                $records.Add([pscustomobject]@{ when = $e.TimeCreated; ip = $p.ip; source = 'SMTP AUTH'; account = ''; detail = $(if ($p.connector) { $p.connector } else { '' }) })
            }
            if ($ev.Count -ge $Cap) { $caveats.Add(('SMTP AUTH: capped at {0:N0} events; there were more.' -f $Cap)) }
            $read++
        } catch {
            $m = $_.Exception.Message
            if ($m -match 'No events were found') { $read++ }
            elseif ($m -match 'There is not an event provider') { $extraRows.Add((New-EtkRow -Group $g -Check 'SMTP AUTH (1035)' -Result 'Not an Exchange server: the source is not registered here' -Basis 'not measured' -Status 'info')) }
            else { $notMeasured.Add(('SMTP AUTH failures (1035): {0}' -f $m)) }
        }
        # 2. Windows logon failures. The Security log needs elevation.
        try {
            $ev = @(Get-WinEvent -LogName 'Security' -FilterXPath (Get-EtkSecurityXPath -Id 4625 -Hours $Hours) -MaxEvents $Cap -ErrorAction Stop)
            foreach ($e in $ev) {
                $d = ConvertFrom-EtkEventXml $e.ToXml()
                $records.Add([pscustomobject]@{ when = $e.TimeCreated; ip = [string]$d['IpAddress']; source = 'Windows'; account = [string]$d['TargetUserName']; detail = ('Windows logon type {0}' -f $d['LogonType']) })
            }
            if ($ev.Count -ge $Cap) { $caveats.Add(('Windows logon failures: capped at the newest {0:N0} events; there were more.' -f $Cap)) }
            $read++
        } catch {
            $m = $_.Exception.Message
            if ($m -match 'No events were found') { $read++ }
            elseif (Test-EtkAccessDenied $m) { $notMeasured.Add('Windows logon failures (4625): reading the Security log needs an elevated session') }
            else { $notMeasured.Add(('Windows logon failures (4625): {0}' -f $m)) }
        }
        # 3. OWA / EWS / ActiveSync / MAPI password failures in the IIS logs.
        $root = 'C:\inetpub\logs\LogFiles'
        if (-not (Test-Path -LiteralPath $root)) {
            if (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue) { $notMeasured.Add(('IIS failures (401.1): no logs at {0} - the log folder may have been moved' -f $root)) }
            else { $extraRows.Add((New-EtkRow -Group $g -Check 'IIS (401.1)' -Result 'IIS is not installed here' -Basis 'not measured' -Status 'info')) }
        } else {
            try {
                $sinceUtc = $since.ToUniversalTime()
                $days = @(); $d = [datetime]::UtcNow.Date
                while ($d -ge $sinceUtc.Date) { $days += $d.ToString('yyMMdd'); $d = $d.AddDays(-1) }   # newest first
                $iisSw = [Diagnostics.Stopwatch]::StartNew(); $budgetHit = $false
                $sites = @(Get-ChildItem -LiteralPath $root -Directory -Filter 'W3SVC*' -ErrorAction Stop)
                foreach ($day in $days) {
                    foreach ($site in $sites) {
                        foreach ($f in @(Get-ChildItem -LiteralPath $site.FullName -Filter ('u_ex{0}*.log' -f $day) -File -ErrorAction Stop)) {
                            $ix = $null
                            foreach ($ln in (Read-EtkSharedLines -Path $f.FullName)) {
                                if ($ln.StartsWith('#Fields:')) { $ix = Get-EtkIisFieldIndex $ln; continue }
                                if ($null -eq $ix -or $ln.StartsWith('#') -or $ln.IndexOf(' 401 ') -lt 0) { continue }
                                $r = ConvertFrom-EtkIisFailure -Index $ix -Line $ln
                                if ($r -and $r.when -ge $since) { $records.Add($r) }
                            }
                            if ($iisSw.Elapsed.TotalSeconds -gt $IisBudgetSec) { $budgetHit = $true; break }
                        }
                        if ($budgetHit) { break }
                    }
                    if ($budgetHit) { break }
                }
                if ($budgetHit) { $caveats.Add(('IIS logs: stopped after {0} s (newest first), so the oldest part of the window may not have been read.' -f $IisBudgetSec)) }
                $read++
            } catch {
                $m = $_.Exception.Message
                if (Test-EtkAccessDenied $m) { $notMeasured.Add('IIS failures (401.1): the IIS log folder needs an elevated session') }
                else { $notMeasured.Add(('IIS failures (401.1): {0}' -f $m)) }
            }
        }
        $sw.Stop()
        if ($read -eq 0 -and $notMeasured.Count) {
            return Set-EtkSectionTiming (New-EtkSection -State unsupported -Reason ($notMeasured -join '; ') -Rows $extraRows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
        }
        $sum = Get-EtkFailedLoginSummary -Records $records.ToArray() -Hours $Hours -Group $g
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($r in $sum.rows) { $rows.Add($r) }
        foreach ($n in $notMeasured) {
            $parts = $n -split ':\s*', 2
            $rows.Add((New-EtkRow -Group $g -Check $parts[0] -Result 'Not read' -Basis 'not measured' -Status 'info' -Detail $(if ($parts.Count -gt 1) { $parts[1] } else { '' })))
        }
        foreach ($r in $extraRows) { $rows.Add($r) }
        $caveats.Add('Behind NAT or a reverse proxy, the source address recorded may be the router''s, not the attacker''s.')
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('Application 1035 (MSExchangeFrontEndTransport), Security 4625, IIS 401.1 - last {0} h' -f $Hours) `
            -Caveats $caveats.ToArray() -Rows $rows.ToArray() `
            -Data ([pscustomobject]@{ notMeasured = [object[]]$notMeasured.ToArray(); suspectIps = [object[]]$sum.suspectIps; publicIps = [object[]]$sum.publicIps; total = $sum.total; publicTotal = $sum.publicTotal; hours = $Hours })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkIgnoredAccount {
    # Pure. Logons that are Windows itself, not a person.
    param([string]$User)
    if ([string]::IsNullOrWhiteSpace($User) -or $User -eq '-') { return $true }
    if ($User -match '\$$' -or $User -match '^(DWM|UMFD)-\d+$') { return $true }
    return ($User -in @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON'))
}

function Get-EtkLogonRows {
    # Pure. 4624 records (when, account, type, ip) grouped by account, logon
    # type and source address.
    param($Records, [string[]]$SuspectIps = @(), [int]$Hours = 24, [int]$Max = 40, [string]$Group = 'Logons')
    $typeName = @{ '2' = 'console'; '10' = 'RDP'; '11' = 'cached (console)' }
    $by = @{}
    foreach ($r in @($Records | Where-Object { $_ })) {
        $ip = ([string]$r.ip).Trim(); if ($ip -eq '-' -or $ip -eq '127.0.0.1' -or $ip -eq '::1') { $ip = '' }
        $key = ('{0}|{1}|{2}' -f ([string]$r.account).ToLowerInvariant(), $r.type, $ip)
        if (-not $by.ContainsKey($key)) { $by[$key] = @{ account = [string]$r.account; type = [string]$r.type; ip = $ip; count = 0; last = $null } }
        $e = $by[$key]; $e.count++
        $w = [datetime]$r.when
        if ($null -eq $e.last -or $w -gt $e.last) { $e.last = $w }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $groups = @($by.Values | Sort-Object @{ Expression = { $_.last }; Descending = $true })
    if ($groups.Count -eq 0) {
        $rows.Add((New-EtkRow -Group $Group -Check 'Interactive and RDP logons' -Result ('None in the last {0} h' -f $Hours) -Basis 'server-reported' -Status 'ok'))
    }
    foreach ($e in @($groups | Select-Object -First $Max)) {
        $tn = $(if ($typeName.ContainsKey($e.type)) { $typeName[$e.type] } else { 'type ' + $e.type })
        $pub = Test-EtkPublicIp $e.ip
        $from = $(if ($e.ip) { ' from {0} ({1})' -f $e.ip, $(if ($pub) { 'public' } else { 'internal' }) } else { '' })
        $st = 'info'; $det = ''
        if ($pub -and $e.type -eq '10') {
            $st = 'fail'
            $det = 'RDP reached this server from the internet. Restrict it (VPN, RD Gateway, or an allow-list at the router): exposed RDP is the most common way ransomware gets in.'
        }
        if ($e.ip -and ($SuspectIps -contains $e.ip)) {
            $st = 'fail'
            $det = ('{0} This address also had repeated failed logins in the window - possibly a successful password guess. Check what the account did next and reset its password.' -f $det).Trim()
        }
        $rows.Add((New-EtkRow -Group $Group -Check $e.account -Result ('{0}{1}: {2} logon(s), last {3}' -f $tn, $from, $e.count, (ConvertTo-EtkLocalStamp $e.last)) `
            -Basis 'server-reported' -Status $st -Detail $det))
    }
    if ($groups.Count -gt $Max) {
        $rows.Add((New-EtkRow -Group $Group -Check ('{0} more' -f ($groups.Count - $Max)) -Result 'Older logons not listed' -Basis 'server-reported' -Status 'info'))
    }
    $pubIps = [string[]]@($groups | Where-Object { $_.ip -and (Test-EtkPublicIp $_.ip) } | ForEach-Object { $_.ip } | Sort-Object -Unique)
    [pscustomobject]@{ rows = [object[]]$rows.ToArray(); publicIps = $pubIps }
}

function Test-EtkLogons {
    param([int]$Hours = 24, [string[]]$SuspectIps = @(), [int]$Cap = 5000)
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Logons'
    $ev = @()
    try {
        $ev = @(Get-WinEvent -LogName 'Security' -FilterXPath (Get-EtkSecurityXPath -Id 4624 -Hours $Hours -LogonTypes @(2, 10, 11)) -MaxEvents $Cap -ErrorAction Stop)
    } catch {
        $m = $_.Exception.Message
        $sw.Stop()
        if (Test-EtkAccessDenied $m) { return Set-EtkSectionTiming (New-EtkSection -State unsupported -Reason 'Reading the Security log needs an elevated session.') $t0 $sw.Elapsed.TotalSeconds }
        if ($m -notmatch 'No events were found') { return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $m) $t0 $sw.Elapsed.TotalSeconds }
        $sw.Start()
    }
    try {
        $recs = foreach ($e in $ev) {
            $d = ConvertFrom-EtkEventXml $e.ToXml()
            $user = [string]$d['TargetUserName']
            if (Test-EtkIgnoredAccount $user) { continue }
            $dom = [string]$d['TargetDomainName']
            [pscustomobject]@{ when = $e.TimeCreated; account = $(if ($dom -and $dom -ne '-') { '{0}\{1}' -f $dom, $user } else { $user }); type = [string]$d['LogonType']; ip = [string]$d['IpAddress'] }
        }
        $res = Get-EtkLogonRows -Records @($recs) -SuspectIps $SuspectIps -Hours $Hours -Group $g
        $cav = @('Behind an RD Gateway or NAT, the source shown is the gateway''s address.')
        if ($ev.Count -ge $Cap) { $cav += ('Capped at the newest {0:N0} logons.' -f $Cap) }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method ('Security 4624, logon types 2 (console), 10 (RDP), 11 (cached) - last {0} h' -f $Hours) -Caveats $cav -Rows $res.rows `
            -Data ([pscustomobject]@{ publicIps = [object[]]$res.publicIps; hours = $Hours })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message) $t0 $sw.Elapsed.TotalSeconds
    }
}

function Test-EtkPortSpecMatch {
    # Pure. Does a firewall LocalPort spec cover this port? 'Any', '7777',
    # '7000-8000', or a list of those. Keywords such as RPC / RPCEPMap mean
    # dynamic RPC ports, which the exposure check skips anyway.
    param($Spec, [int]$Port)
    foreach ($s in @($Spec)) {
        foreach ($t in (([string]$s) -split ',')) {
            $t = $t.Trim()
            if ($t -eq 'Any') { return $true }
            if ($t -match '^\d+$' -and [int]$t -eq $Port) { return $true }
            if ($t -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
        }
    }
    return $false
}

function Test-EtkCoreListener {
    # Pure. Listeners that are Windows, AD or Exchange themselves - expected
    # on this kind of server, and not what the exposure check is looking for.
    param($Listener, [string]$ExchangePath = '')
    if ([int]$Listener.port -ge 49152) { return $true }       # dynamic RPC range
    if ([int]$Listener.pid -eq 4) { return $true }            # http.sys / SMB (IIS, WinRM, file sharing)
    $name = [string]$Listener.process
    $core = @('System', 'Idle', 'lsass', 'svchost', 'services', 'wininit', 'smss', 'csrss', 'dns', 'ismserv', 'dfsrs', 'Microsoft.ActiveDirectory.WebServices',
              'vmms', 'vmcompute', 'inetinfo', 'w3wp', 'spoolsv')
    if ($core -contains $name) { return $true }
    if ($name -match '^(MSExchange|Microsoft\.Exchange|EdgeTransport|noderunner|UMService|UMWorkerProcess|hostcontrollerservice)') { return $true }
    $path = [string]$Listener.path
    if ($ExchangePath -and $path -and $path.StartsWith($ExchangePath.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

function Get-EtkExposureRows {
    # Pure. Listening sockets vs inbound allow rules. Listeners (port, pid,
    # process, path, address) and rules (name, ports, protocol, remote,
    # program) come in as plain objects.
    param($Listeners, $Rules, [string]$ExchangePath = '', [string]$Group = 'Exposure')
    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($l in @($Listeners | Where-Object { $_ } | Sort-Object { [int]$_.port })) {
        if (Test-EtkCoreListener -Listener $l -ExchangePath $ExchangePath) { continue }
        $key = ('{0}|{1}' -f $l.port, $l.pid)
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $proc = $(if ($l.process) { [string]$l.process } else { 'PID ' + $l.pid })
        $leaf = $(if ($l.path) { Split-Path -Leaf ([string]$l.path) } else { $proc + '.exe' })
        $allow = @($Rules | Where-Object {
            $_ -and ([string]$_.protocol -in @('TCP', 'Any', '6')) -and (Test-EtkPortSpecMatch -Spec $_.ports -Port ([int]$l.port)) -and (
                [string]::IsNullOrWhiteSpace([string]$_.program) -or [string]$_.program -eq 'Any' -or
                ($l.path -and [Environment]::ExpandEnvironmentVariables([string]$_.program) -eq [string]$l.path) -or
                ((Split-Path -Leaf ([Environment]::ExpandEnvironmentVariables([string]$_.program))) -eq $leaf))
        })
        $fromAny = @($allow | Where-Object { @($_.remote) -contains 'Any' })
        if ($fromAny.Count) {
            $rows.Add((New-EtkRow -Group $Group -Check ('Port {0}' -f $l.port) -Result ('{0} listens; rule "{1}" allows it from any address' -f $proc, $fromAny[0].name) -Basis 'inference' -Status 'warn' `
                -Detail ('Not part of Windows or Exchange, and open to every address at the server''s firewall. If the router forwards this port, the internet can reach it. Close the rule (or scope it to the addresses that need it) unless something outside depends on it.{0}' -f $(if ($fromAny.Count -gt 1) { (' Other rules allowing it: {0}.' -f ((@($fromAny | Select-Object -Skip 1 | ForEach-Object { $_.name })) -join ', ')) } else { '' }))))
        } elseif ($allow.Count) {
            $rows.Add((New-EtkRow -Group $Group -Check ('Port {0}' -f $l.port) -Result ('{0} listens; rule "{1}" allows it from {2}' -f $proc, $allow[0].name, ((@($allow[0].remote)) -join ', ')) -Basis 'inference' -Status 'info'))
        } else {
            $rows.Add((New-EtkRow -Group $Group -Check ('Port {0}' -f $l.port) -Result ('{0} listens; no inbound rule allows it' -f $proc) -Basis 'inference' -Status 'info' `
                -Detail 'Blocked at the server''s firewall unless the firewall is off for the network it arrives on.'))
        }
    }
    return [object[]]$rows.ToArray()
}

function Get-EtkRdpState {
    # Pure. Policy values, when set, override the local ones.
    param($Deny, $PolicyDeny, $Nla, $PolicyNla, $Port)
    $d = $(if ($null -ne $PolicyDeny) { [int]$PolicyDeny } elseif ($null -ne $Deny) { [int]$Deny } else { 1 })
    $n = $(if ($null -ne $PolicyNla) { [int]$PolicyNla } elseif ($null -ne $Nla) { [int]$Nla } else { 1 })
    [pscustomobject]@{ enabled = ($d -eq 0); nla = ($n -eq 1); port = $(if ($null -ne $Port) { [int]$Port } else { 3389 }) }
}

function Test-EtkExposure {
    $t0 = [datetime]::UtcNow; $sw = [Diagnostics.Stopwatch]::StartNew()
    $g = 'Exposure'
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        # RDP
        $ts = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
        $pol = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        $rdp = Get-EtkRdpState -Deny (Get-EtkRegValue $ts 'fDenyTSConnections') -PolicyDeny (Get-EtkRegValue $pol 'fDenyTSConnections') `
            -Nla (Get-EtkRegValue ($ts + '\WinStations\RDP-Tcp') 'UserAuthentication') -PolicyNla (Get-EtkRegValue $pol 'UserAuthentication') -Port (Get-EtkRegValue ($ts + '\WinStations\RDP-Tcp') 'PortNumber')
        if (-not $rdp.enabled) {
            $rows.Add((New-EtkRow -Group $g -Check 'Remote Desktop' -Result 'Off' -Basis 'registry' -Status 'ok'))
        } elseif (-not $rdp.nla) {
            $rows.Add((New-EtkRow -Group $g -Check 'Remote Desktop' -Result ('On, port {0}, Network Level Authentication OFF' -f $rdp.port) -Basis 'registry' -Status 'fail' `
                -Detail 'Without NLA, anyone who can reach the port gets a Windows logon screen before proving who they are. Turn NLA on (System Properties > Remote).'))
        } else {
            $rows.Add((New-EtkRow -Group $g -Check 'Remote Desktop' -Result ('On, port {0}, NLA required' -f $rdp.port) -Basis 'registry' -Status 'info' `
                -Detail 'Fine on the inside. Make sure the router does not forward it; the Logons section shows whether RDP was reached from a public address.'))
        }
        # Firewall profiles
        try {
            $prof = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
            $off = @($prof | Where-Object { -not [bool]$_.Enabled } | ForEach-Object { [string]$_.Name })
            if ($off.Count) {
                $rows.Add((New-EtkRow -Group $g -Check 'Windows Firewall' -Result ('OFF for {0}' -f ($off -join ', ')) -Basis 'measured' -Status 'warn' `
                    -Detail 'With a profile off, every listening port below is open on networks of that type, whatever the rules say.'))
            } else {
                $rows.Add((New-EtkRow -Group $g -Check 'Windows Firewall' -Result ('On for {0}' -f ((@($prof | ForEach-Object { [string]$_.Name })) -join ', ')) -Basis 'measured' -Status 'ok'))
            }
        } catch { $rows.Add((New-EtkRow -Group $g -Check 'Windows Firewall' -Result 'Could not read' -Basis 'not measured' -Status 'info' -Detail $_.Exception.Message)) }
        # Listeners vs rules. The rules' port/address/program filters can only
        # be read elevated; without them this part is "not read", never "fine".
        $notMeasured = New-Object System.Collections.Generic.List[string]
        $listeners = @(); $rules = @()
        try {
            $procs = @{}
            foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $procs[[int]$p.ProcessId] = $p }
            $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') } | ForEach-Object {
                $pr = $procs[[int]$_.OwningProcess]
                [pscustomobject]@{ port = [int]$_.LocalPort; address = [string]$_.LocalAddress; pid = [int]$_.OwningProcess
                    process = $(if ($pr) { ([string]$pr.Name) -replace '\.exe$', '' } else { '' }); path = $(if ($pr) { [string]$pr.ExecutablePath } else { '' }) }
            })
            $pf = @{}; foreach ($f in @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore -ErrorAction Stop)) { $pf[[string]$f.InstanceID] = $f }
            $af = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore -ErrorAction Stop)) { $af[[string]$f.InstanceID] = $f }
            $apf = @{}; foreach ($f in @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction Stop)) { $apf[[string]$f.InstanceID] = $f }
            $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop | ForEach-Object {
                $id = [string]$_.InstanceID
                [pscustomobject]@{ name = [string]$_.DisplayName
                    ports = $(if ($pf.ContainsKey($id)) { [object[]]@($pf[$id].LocalPort) } else { @('Any') })
                    protocol = $(if ($pf.ContainsKey($id)) { [string]$pf[$id].Protocol } else { 'Any' })
                    remote = $(if ($af.ContainsKey($id)) { [object[]]@($af[$id].RemoteAddress) } else { @('Any') })
                    program = $(if ($apf.ContainsKey($id)) { [string]$apf[$id].Program } else { 'Any' }) }
            })
            $exPath = [string](Get-EtkRegValue 'SOFTWARE\Microsoft\ExchangeServer\v15\Setup' 'MsiInstallPath')
            $lr = @(Get-EtkExposureRows -Listeners $listeners -Rules $rules -ExchangePath $exPath -Group $g)
            if ($lr.Count) { foreach ($r in $lr) { $rows.Add($r) } }
            else { $rows.Add((New-EtkRow -Group $g -Check 'Other listening ports' -Result 'None outside Windows, AD and Exchange' -Basis 'inference' -Status 'ok')) }
        } catch {
            $m = $_.Exception.Message
            $why = $(if (Test-EtkAccessDenied $m) { 'reading the firewall rules'' port and address filters needs an elevated session' } else { $m })
            $notMeasured.Add(('Listening ports vs firewall rules: {0}' -f $why))
            $rows.Add((New-EtkRow -Group $g -Check 'Listening ports vs firewall rules' -Result 'Not read' -Basis 'not measured' -Status 'info' -Detail $why))
        }
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State measured -Method 'Terminal Server registry, Get-NetFirewallProfile, Get-NetTCPConnection vs enabled inbound allow rules (active policy store)' `
            -Caveats @('This is the server''s own firewall. Whether the router forwards a port cannot be seen from here - check its port forwards too (the 7777 forward in the case that prompted this tool was only visible on the router).',
                       'Windows, AD, IIS (http.sys), Exchange and the dynamic RPC range (49152 and up) are left out as expected; ports 25, 443 and 587 are covered by the Connectors and Failed logins sections.') `
            -Rows $rows.ToArray() -Data ([pscustomobject]@{ rdp = $rdp; rules = $rules.Count; listeners = $listeners.Count; notMeasured = [object[]]$notMeasured.ToArray() })) $t0 $sw.Elapsed.TotalSeconds
    } catch {
        $sw.Stop()
        return Set-EtkSectionTiming (New-EtkSection -State failed -Reason $_.Exception.Message -Rows $rows.ToArray()) $t0 $sw.Elapsed.TotalSeconds
    }
}

# ===========================================================================
#  ACTIONS
#
#  The only code in this tool that changes anything. Rules, all enforced
#  here rather than trusted to the UI:
#    * an action runs only with a confirmation token, which the UI creates
#      after the person has seen the exact command and said yes
#    * a 'high' risk action also needs the server name typed back
#    * arguments are validated against a pattern before they reach a native
#      command line
#    * nothing here is called by any check or by "Run all" (a test scans the
#      job code to prove it)
# ===========================================================================

function Get-EtkManagedServicePattern {
    # The only services the tool will start, stop or restart: Exchange's own,
    # the search host, the Exchange backup extension, IIS and WinRM. Enforced
    # in the engine, so a crafted call cannot point it at anything else.
    '^(MSExchange[A-Za-z0-9]+|MSComplianceAudit|HostControllerService|wsbexchange|W3SVC|WAS|IISADMIN|WinRM)$'
}

function Get-EtkStartOrder {
    # Pure. The order to start stopped services in: AD Topology first (nearly
    # every Exchange service waits on it), then Service Host, then the rest by
    # name. The service manager starts dependencies itself; this only avoids
    # a pile of timeouts while ADTopology is still coming up.
    param([string[]]$Names)
    $rank = @{ 'msexchangeadtopology' = 0; 'msexchangeservicehost' = 1 }
    return [string[]]@(@($Names | Where-Object { $_ }) | Sort-Object @{ Expression = { $k = ([string]$_).ToLowerInvariant(); if ($rank.ContainsKey($k)) { $rank[$k] } else { 2 } } }, @{ Expression = { [string]$_ } })
}

function Get-EtkManagedServices {
    # Read-only list for the Fix tab. Runs on the target through Invoke-EtkOs.
    $pat = Get-EtkManagedServicePattern
    @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -match $pat } | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ name = [string]$_.Name; displayName = [string]$_.DisplayName; state = [string]$_.State; startMode = [string]$_.StartMode }
    })
}

function Get-EtkActionCatalog {
    $svc = Get-EtkManagedServicePattern
    [ordered]@{
        'svc-start'        = @{ title = 'Start a service';                    risk = 'low';    where = 'os';       args = @{ Name = $svc } }
        'svc-stop'         = @{ title = 'Stop a service';                     risk = 'high';   where = 'os';       args = @{ Name = $svc } }
        'svc-restart'      = @{ title = 'Start / restart a service';          risk = 'medium'; where = 'os';       args = @{ Name = $svc } }
        'svc-start-auto'   = @{ title = 'Start every stopped automatic Exchange/IIS service'; risk = 'medium'; where = 'os'; args = @{ } }
        'iis-reset'        = @{ title = 'IIS reset (iisreset /noforce)';      risk = 'medium'; where = 'os';       args = @{ } }
        'apppool-recycle-all' = @{ title = 'Recycle every MSExchange app pool'; risk = 'medium'; where = 'os';     args = @{ } }
        'apppool-recycle'  = @{ title = 'Recycle an IIS application pool';    risk = 'medium'; where = 'os';       args = @{ Name = '^[A-Za-z0-9_\.\- ]+$' } }
        'eventlog-enlarge' = @{ title = 'Enlarge event logs';                 risk = 'low';    where = 'os';       args = @{ } }
        'task-disable'     = @{ title = 'Disable a scheduled task';           risk = 'low';    where = 'os';       args = @{ TaskName = '^[^"\r\n]+$'; TaskPath = '^\\[^"\r\n]*$' } }
        'task-enable'      = @{ title = 'Enable a scheduled task';            risk = 'low';    where = 'os';       args = @{ TaskName = '^[^"\r\n]+$'; TaskPath = '^\\[^"\r\n]*$' } }
        'shadow-delete'    = @{ title = 'Delete ONE shadow copy';             risk = 'high';   where = 'os';       args = @{ ShadowId = '^\{[0-9A-Fa-f\-]{36}\}$' } }
        'perf-start'       = @{ title = 'Start the performance capture';      risk = 'low';    where = 'os';       args = @{ } }
        'perf-stop'        = @{ title = 'Stop the performance capture';       risk = 'low';    where = 'os';       args = @{ } }
        'queue-retry'      = @{ title = 'Retry a queue';                      risk = 'low';    where = 'exchange'; args = @{ Identity = '^[^"\r\n]+$' } }
        'queue-suspend'    = @{ title = 'Suspend a queue';                    risk = 'low';    where = 'exchange'; args = @{ Identity = '^[^"\r\n]+$' } }
        'queue-resume'     = @{ title = 'Resume a queue';                     risk = 'low';    where = 'exchange'; args = @{ Identity = '^[^"\r\n]+$' } }
        'db-mount'         = @{ title = 'Mount a database';                   risk = 'medium'; where = 'exchange'; args = @{ Identity = '^[^"\r\n]+$' } }
        'component-active' = @{ title = 'Set a server component Active';      risk = 'medium'; where = 'exchange'; args = @{ Component = '^[A-Za-z0-9]+$'; Requester = '^(Functional|Maintenance|Sidelined|Deployment|HealthApi)$' } }
    }
}

function Get-EtkPerfCollector {
    @{
        Name = 'ExchangeToolkit'
        Folder = 'C:\PerfLogs\ExchangeToolkit'
        Counters = @(
            '\LogicalDisk(*)\Avg. Disk sec/Read', '\LogicalDisk(*)\Avg. Disk sec/Write', '\LogicalDisk(*)\Current Disk Queue Length',
            '\Process(*)\% Processor Time', '\Process(*)\IO Data Bytes/sec', '\Process(*)\Working Set',
            '\Memory\Available MBytes', '\Memory\% Committed Bytes In Use',
            '\MSExchange RpcClientAccess\RPC Averaged Latency',
            '\MSExchange Database(*)\Database Cache Size (MB)', '\MSExchange Database(*)\Database Cache % Hit'
        )
    }
}

function ConvertTo-EtkHashtable {
    param($Object)
    $h = @{}
    if ($null -eq $Object) { return $h }
    if ($Object -is [hashtable]) { foreach ($k in $Object.Keys) { $h[$k] = [string]$Object[$k] }; return $h }
    foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = [string]$p.Value }
    return $h
}

function Test-EtkActionArguments {
    param([string]$Id, [hashtable]$Arguments)
    $cat = Get-EtkActionCatalog
    if (-not $cat.Contains($Id)) { throw ('Unknown action "{0}".' -f $Id) }
    foreach ($k in $cat[$Id].args.Keys) {
        $v = [string]$Arguments[$k]
        if ([string]::IsNullOrWhiteSpace($v)) { throw ('Action "{0}" needs a value for {1}.' -f $Id, $k) }
        if ($v -notmatch $cat[$Id].args[$k]) { throw ('Action "{0}": the value "{1}" for {2} is not allowed.' -f $Id, $v, $k) }
    }
}

function Get-EtkActionCommand {
    # The exact command, as text, for the confirmation dialog and "Copy
    # command". Kept in step with Invoke-EtkOsAction / -ExchangeAction.
    param([string]$Id, $Arguments, [string]$Server)
    $a = ConvertTo-EtkHashtable $Arguments
    $pc = Get-EtkPerfCollector
    switch ($Id) {
        'svc-start'        { return ('Start-Service -Name {0}' -f $a.Name) }
        'svc-stop'         { return ('Stop-Service -Name {0} -Force   (-Force also stops every service that depends on it)' -f $a.Name) }
        'svc-start-auto'   { return 'Start-Service, for each Exchange/IIS service whose start mode is Automatic but is not running   (MSExchangeADTopology first, then MSExchangeServiceHost, then the rest)' }
        'iis-reset'        { return '%windir%\System32\iisreset.exe /noforce   (stops and restarts IIS; /noforce gives up rather than killing a worker that will not stop)' }
        'apppool-recycle-all' { return '%windir%\System32\inetsrv\appcmd.exe recycle apppool /apppool.name:"<name>"   (for each MSExchange* pool, one after another)' }
        'svc-restart'      { return ('Restart-Service -Name {0} -Force   (Start-Service if it is stopped)' -f $a.Name) }
        'apppool-recycle'  { return ('%windir%\System32\inetsrv\appcmd.exe recycle apppool /apppool.name:"{0}"' -f $a.Name) }
        'eventlog-enlarge' { return (((Get-EtkLogPreset).GetEnumerator() | ForEach-Object { 'wevtutil sl {0} /ms:{1}' -f $_.Key, [int64]$_.Value }) -join ' ; ') + '   (only logs smaller than this are changed)' }
        'task-disable'     { return ('Disable-ScheduledTask -TaskPath "{0}" -TaskName "{1}"' -f $a.TaskPath, $a.TaskName) }
        'task-enable'      { return ('Enable-ScheduledTask -TaskPath "{0}" -TaskName "{1}"' -f $a.TaskPath, $a.TaskName) }
        'shadow-delete'    { return ('vssadmin delete shadows /shadow={0} /quiet' -f $a.ShadowId) }
        'perf-start'       { return ('logman create counter {0} -f bincirc -max 1024 -si 15 -o "{1}\{0}" -c <{2} counters> ; logman start {0}' -f $pc.Name, $pc.Folder, $pc.Counters.Count) }
        'perf-stop'        { return ('logman stop {0}' -f $pc.Name) }
        'queue-retry'      { return ('Retry-Queue -Identity "{0}" -Confirm:$false' -f $a.Identity) }
        'queue-suspend'    { return ('Suspend-Queue -Identity "{0}" -Confirm:$false' -f $a.Identity) }
        'queue-resume'     { return ('Resume-Queue -Identity "{0}" -Confirm:$false' -f $a.Identity) }
        'db-mount'         { return ('Mount-Database -Identity "{0}" -Confirm:$false' -f $a.Identity) }
        'component-active' { return ('Set-ServerComponentState -Identity {0} -Component {1} -State Active -Requester {2}' -f $Server, $a.Component, $a.Requester) }
    }
    throw ('Unknown action "{0}".' -f $Id)
}

function Test-EtkSharedAccount {
    # Pure. True when the account running the tool does not identify a
    # person: SYSTEM (Backstage, an RMM), another NT AUTHORITY account, or a
    # domain/local built-in Administrator (RID 500, whatever it is renamed
    # to). An action log that says "SYSTEM" or "Administrator" cannot answer
    # "who did this" - on the server this tool was built for, working out who
    # was logged on as Administrator at 07:07 took a security-log trawl.
    param([string]$Name, [string]$Sid = '', [bool]$IsSystem = $false)
    if ($IsSystem) { return $true }
    if ($Sid -match '-500$') { return $true }
    if ($Name -match '^NT AUTHORITY\\') { return $true }
    if ($Name -match '(^|\\)Administrator$') { return $true }
    return $false
}

function Get-EtkCurrentAccount {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isSys = $false; try { $isSys = $id.IsSystem } catch { }
    [pscustomobject]@{ name = $id.Name; sid = [string]$id.User.Value; isSystem = $isSys
        shared = (Test-EtkSharedAccount -Name $id.Name -Sid ([string]$id.User.Value) -IsSystem $isSys) }
}

function New-EtkConfirmToken {
    param([string]$Id, [string]$Server)
    return ('CONFIRMED|{0}|{1}' -f $Id, $Server.ToLowerInvariant())
}

function Invoke-EtkOsAction {
    # OS-level actions. Runs on the target (directly or via Invoke-Command).
    param([string]$Id, [hashtable]$Arguments)
    Test-EtkActionArguments -Id $Id -Arguments $Arguments
    $a = $Arguments
    switch ($Id) {
        'svc-start' {
            Start-Service -Name $a.Name -ErrorAction Stop
            return ('{0} is now {1}.' -f $a.Name, (Get-Service -Name $a.Name).Status)
        }
        'svc-stop' {
            Stop-Service -Name $a.Name -Force -ErrorAction Stop
            return ('{0} is now {1}.' -f $a.Name, (Get-Service -Name $a.Name).Status)
        }
        'svc-start-auto' {
            $pat = Get-EtkManagedServicePattern
            $stopped = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -match $pat -and $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
            if ($stopped.Count -eq 0) { return 'Nothing to do: every automatic Exchange and IIS service is already running.' }
            $done = @(); $failed = @()
            foreach ($n in (Get-EtkStartOrder -Names ([string[]]@($stopped | ForEach-Object { $_.Name })))) {
                try { Start-Service -Name $n -ErrorAction Stop; $done += $n }
                catch { $failed += ('{0} ({1})' -f $n, $_.Exception.Message) }
            }
            $msg = ('Started {0}: {1}.' -f $done.Count, $(if ($done.Count) { $done -join ', ' } else { 'none' }))
            if ($failed.Count) { throw ('{0} Could not start {1}: {2}' -f $msg, $failed.Count, ($failed -join '; ')) }
            return $msg
        }
        'iis-reset' {
            $exe = Get-EtkSystemTool 'iisreset.exe'
            if (-not $exe) { throw 'iisreset.exe was not found - IIS does not look installed here.' }
            $r = Invoke-EtkNative -FilePath $exe -ArgumentList @('/noforce')
            $text = (@($r.lines | Where-Object { ([string]$_).Trim() }) -join ' ')
            if ($r.exitCode -ne 0) { throw ('iisreset exit {0}: {1}' -f $r.exitCode, $text) }
            return $text
        }
        'apppool-recycle-all' {
            $dll = Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll'
            if (-not (Test-Path -LiteralPath $dll)) { throw 'IIS is not installed here (Microsoft.Web.Administration.dll not found).' }
            [void][Reflection.Assembly]::LoadFrom($dll)
            $sm = New-Object Microsoft.Web.Administration.ServerManager
            try { $names = @($sm.ApplicationPools | Where-Object { $_.Name -like 'MSExchange*' } | ForEach-Object { [string]$_.Name }) } finally { $sm.Dispose() }
            if ($names.Count -eq 0) { return 'No MSExchange app pools found.' }
            $exe = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
            $done = @(); $failed = @()
            foreach ($n in $names) {
                $r = Invoke-EtkNative -FilePath $exe -ArgumentList @('recycle', 'apppool', ('/apppool.name:{0}' -f $n))
                if ($r.exitCode -eq 0) { $done += $n } else { $failed += ('{0} (exit {1}: {2})' -f $n, $r.exitCode, $r.output) }
            }
            $msg = ('Recycled {0} of {1}: {2}.' -f $done.Count, $names.Count, $(if ($done.Count) { $done -join ', ' } else { 'none' }))
            if ($failed.Count) { throw ('{0} Failed: {1}' -f $msg, ($failed -join '; ')) }
            return $msg
        }
        'svc-restart' {
            $s = Get-Service -Name $a.Name -ErrorAction Stop
            if ($s.Status -eq 'Running') { Restart-Service -Name $a.Name -Force -ErrorAction Stop } else { Start-Service -Name $a.Name -ErrorAction Stop }
            return ('{0} is now {1}.' -f $a.Name, (Get-Service -Name $a.Name).Status)
        }
        'apppool-recycle' {
            $exe = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
            $r = Invoke-EtkNative -FilePath $exe -ArgumentList @('recycle', 'apppool', ('/apppool.name:{0}' -f $a.Name))
            if ($r.exitCode -ne 0) { throw ('appcmd exit {0}: {1}' -f $r.exitCode, $r.output) }
            return $r.output
        }
        'eventlog-enlarge' {
            $wev = Get-EtkSystemTool 'wevtutil.exe'
            $done = @()
            foreach ($kv in (Get-EtkLogPreset).GetEnumerator()) {
                $l = Get-WinEvent -ListLog $kv.Key -ErrorAction Stop
                if ([int64]$l.MaximumSizeInBytes -ge [int64]$kv.Value) { $done += ('{0} already {1}' -f $kv.Key, (Format-EtkBytes $l.MaximumSizeInBytes)); continue }
                $r = Invoke-EtkNative -FilePath $wev -ArgumentList @('sl', $kv.Key, ('/ms:{0}' -f [int64]$kv.Value))
                if ($r.exitCode -ne 0) { throw ('wevtutil {0} exit {1}: {2}' -f $kv.Key, $r.exitCode, $r.output) }
                $done += ('{0} {1} -> {2}' -f $kv.Key, (Format-EtkBytes $l.MaximumSizeInBytes), (Format-EtkBytes $kv.Value))
            }
            return ($done -join '; ')
        }
        'task-disable' { [void](Disable-ScheduledTask -TaskPath $a.TaskPath -TaskName $a.TaskName -ErrorAction Stop); return ('{0} disabled.' -f $a.TaskName) }
        'task-enable'  { [void](Enable-ScheduledTask -TaskPath $a.TaskPath -TaskName $a.TaskName -ErrorAction Stop); return ('{0} enabled.' -f $a.TaskName) }
        'shadow-delete' {
            $r = Invoke-EtkNative -FilePath (Get-EtkSystemTool 'vssadmin.exe') -ArgumentList @('delete', 'shadows', ('/shadow={0}' -f $a.ShadowId), '/quiet')
            if ($r.exitCode -ne 0) { throw ('vssadmin exit {0}: {1} (an EDR product protecting its own snapshots can block this)' -f $r.exitCode, $r.output) }
            return $r.output
        }
        'perf-start' {
            $pc = Get-EtkPerfCollector
            $logman = Get-EtkSystemTool 'logman.exe'
            if (-not (Test-Path -LiteralPath $pc.Folder)) { [void](New-Item -ItemType Directory -Path $pc.Folder -Force) }
            $q = Invoke-EtkNative -FilePath $logman -ArgumentList @('query', $pc.Name)
            if ($q.exitCode -ne 0) {
                $argsList = @('create', 'counter', $pc.Name, '-f', 'bincirc', '-max', '1024', '-si', '15', '-o', (Join-Path $pc.Folder $pc.Name), '-c') + $pc.Counters
                $c = Invoke-EtkNative -FilePath $logman -ArgumentList $argsList
                if ($c.exitCode -ne 0) { throw ('logman create exit {0}: {1}' -f $c.exitCode, $c.output) }
            }
            $s = Invoke-EtkNative -FilePath $logman -ArgumentList @('start', $pc.Name)
            if ($s.exitCode -ne 0 -and $s.output -notmatch 'already') { throw ('logman start exit {0}: {1}' -f $s.exitCode, $s.output) }
            return ('Capturing every 15 s to {0} (circular, 1 GB max). Stop it after the problem window and open the .blg in Performance Monitor.' -f $pc.Folder)
        }
        'perf-stop' {
            $pc = Get-EtkPerfCollector
            $s = Invoke-EtkNative -FilePath (Get-EtkSystemTool 'logman.exe') -ArgumentList @('stop', $pc.Name)
            if ($s.exitCode -ne 0) { throw ('logman stop exit {0}: {1}' -f $s.exitCode, $s.output) }
            return ('Stopped. Files are in {0}.' -f $pc.Folder)
        }
    }
    throw ('Action "{0}" is not an OS action.' -f $Id)
}

function Invoke-EtkExchangeAction {
    param([string]$Id, [hashtable]$Arguments, [string]$Server)
    Test-EtkActionArguments -Id $Id -Arguments $Arguments
    if (-not (Test-EtkExchangeAvailable)) { throw 'Exchange cmdlets are not loaded - press Connect first.' }
    $a = $Arguments
    switch ($Id) {
        'queue-retry'      { Retry-Queue   -Identity $a.Identity -Confirm:$false -ErrorAction Stop; return 'Retry requested.' }
        'queue-suspend'    { Suspend-Queue -Identity $a.Identity -Confirm:$false -ErrorAction Stop; return 'Queue suspended.' }
        'queue-resume'     { Resume-Queue  -Identity $a.Identity -Confirm:$false -ErrorAction Stop; return 'Queue resumed.' }
        'db-mount'         { Mount-Database -Identity $a.Identity -Confirm:$false -ErrorAction Stop; return 'Mount requested.' }
        'component-active' { Set-ServerComponentState -Identity $Server -Component $a.Component -State Active -Requester $a.Requester -ErrorAction Stop; return ('{0} set Active by {1}.' -f $a.Component, $a.Requester) }
    }
    throw ('Action "{0}" is not an Exchange action.' -f $Id)
}

function Invoke-EtkAction {
    param([string]$Id, $Arguments, [string]$Server, [string]$ConfirmToken, [string]$TypedServer = '', [string]$Technician = '', $Account = $null)
    $t0 = [datetime]::UtcNow
    $cat = Get-EtkActionCatalog
    $a = ConvertTo-EtkHashtable $Arguments
    if (-not $Account) { $Account = Get-EtkCurrentAccount }
    $tech = $(if ($Technician) { $Technician.Trim() } else { '' })
    $cmd = ''
    try { $cmd = Get-EtkActionCommand -Id $Id -Arguments $a -Server $Server } catch { }
    $result = [pscustomobject]@{ id = $Id; server = $Server; command = $cmd; ok = $false; output = ''; startedUtc = (ConvertTo-EtkIso8601 $t0)
        by = [string]$Account.name; technician = $tech }
    try {
        if (-not $cat.Contains($Id)) { throw ('Unknown action "{0}".' -f $Id) }
        if ($ConfirmToken -ne (New-EtkConfirmToken -Id $Id -Server $Server)) { throw 'Refused: no confirmation for this action on this server.' }
        if ($Account.shared -and -not $tech) { throw ('Refused: the tool is running as {0}, which does not identify a person. Enter your name so the action log says who did this.' -f $Account.name) }
        if ($cat[$Id].risk -eq 'high' -and ($TypedServer.Trim().ToLowerInvariant() -ne $Server.ToLowerInvariant())) { throw 'Refused: a high-risk action needs the server name typed in to confirm.' }
        Test-EtkActionArguments -Id $Id -Arguments $a
        if ($cat[$Id].where -eq 'exchange') { $out = Invoke-EtkExchangeAction -Id $Id -Arguments $a -Server $Server }
        else { $out = Invoke-EtkOs -Name 'Invoke-EtkOsAction' -Parameters @{ Id = $Id; Arguments = $a } }
        $result.ok = $true
        $result.output = (@($out) | ForEach-Object { [string]$_ }) -join ' '
    } catch {
        $result.output = $_.Exception.Message
    }
    return $result
}

# ===========================================================================
#  MICROSOFT CSS-EXCHANGE HEALTHCHECKER
#
#  Downloaded fresh for every run from the official GitHub release, and run
#  only if Windows says the file carries a VALID Authenticode signature from
#  Microsoft Corporation. The repo source is unsigned (it says "unsigned test
#  build" when run), and a copy from anywhere else is not something this tool
#  will launch as an administrator.
# ===========================================================================

function Get-EtkHealthCheckerUrl { 'https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1' }

function Test-EtkCssSignature {
    # Pure. The rule for running a downloaded CSS-Exchange script.
    param([string]$Status, [string]$Subject)
    if ($Status -ne 'Valid') {
        return [pscustomobject]@{ ok = $false; reason = ('Windows reports the signature as "{0}", not Valid. Only the signed release build is run.' -f $(if ($Status) { $Status } else { 'missing' })) }
    }
    if ($Subject -notmatch '(^|,\s*)O=Microsoft Corporation(\s*,|$)') {
        return [pscustomobject]@{ ok = $false; reason = ('The file is signed, but not by Microsoft Corporation ({0}).' -f $Subject) }
    }
    return [pscustomobject]@{ ok = $true; reason = '' }
}

function ConvertTo-EtkPsLiteral {
    # Pure. A single-quoted PowerShell string literal for any text.
    param([string]$Text)
    return ("'" + ($Text -replace "'", "''") + "'")
}

function Save-EtkHealthChecker {
    # Downloads HealthChecker.ps1 into its own run folder and checks the
    # signature. Throws (and deletes the file) if it is not Microsoft's.
    param([string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { [void](New-Item -ItemType Directory -Path $Folder -Force) }
    $path = Join-Path $Folder 'HealthChecker.ps1'
    $url = Get-EtkHealthCheckerUrl
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    $pp = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'    # PS 5.1's download progress bar slows it to a crawl
    try {
        Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing -ErrorAction Stop
    } catch {
        throw ('Could not download HealthChecker from GitHub: {0} This server needs to reach github.com and objects.githubusercontent.com over HTTPS.' -f $_.Exception.Message)
    } finally { $ProgressPreference = $pp }
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $subject = ''
    if ($sig.SignerCertificate) { $subject = [string]$sig.SignerCertificate.Subject }
    $chk = Test-EtkCssSignature -Status ([string]$sig.Status) -Subject $subject
    if (-not $chk.ok) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw ('Refused to run the download: {0}' -f $chk.reason)
    }
    $ver = ''
    try {
        $m = Select-String -LiteralPath $path -Pattern '\$BuildVersion\s*=\s*"([^"]+)"' -List
        if ($m) { $ver = $m.Matches[0].Groups[1].Value }
    } catch { }
    [pscustomobject]@{ path = $path; folder = $Folder; url = $url; version = $ver; signer = $subject; bytes = (Get-Item -LiteralPath $path).Length }
}

function Get-EtkHealthCheckerCommand {
    # Pure. The script the new console runs: load the Exchange Management
    # Shell (or the snap-in under SYSTEM), run HealthChecker, then build its
    # HTML report. Paths go in as quoted literals; the caller passes the
    # whole text as -EncodedCommand, so nothing is re-parsed on a command line.
    # -SkipVersionCheck because the file was just downloaded and its
    # signature checked: a self-update would replace it after that check.
    param([string]$ScriptPath, [string]$OutDir, [string]$ExchangeBin, [string]$Server, [bool]$AsSystem = $false)
    $q = { param($t) ConvertTo-EtkPsLiteral $t }
    $html = Join-Path $OutDir ('HealthChecker_{0}.html' -f ($Server -replace '[^\w\.\-]', '_'))
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('$ErrorActionPreference = ''Continue''')
    $lines.Add(('try {{ $Host.UI.RawUI.WindowTitle = {0} }} catch {{ }}' -f (& $q ('CSS-Exchange HealthChecker - ' + $Server))))
    $lines.Add(('Set-Location -LiteralPath {0}' -f (& $q $OutDir)))
    $lines.Add('$loaded = $false')
    if (-not $AsSystem) {
        $lines.Add('Write-Host ''Loading the Exchange Management Shell...''')
        $lines.Add(('try {{ . (Join-Path {0} ''RemoteExchange.ps1''); Connect-ExchangeServer -auto -ClientApplication:ManagementShell; $loaded = [bool](Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue) }} catch {{ Write-Warning $_.Exception.Message }}' -f (& $q $ExchangeBin)))
    } else {
        $lines.Add('Write-Host ''Running as SYSTEM: using the Exchange management snap-in (remote PowerShell would sign in as the computer account).''')
    }
    $lines.Add('if (-not $loaded) { try { Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop; $loaded = $true; Write-Host ''Using the Exchange management snap-in.'' } catch { Write-Warning $_.Exception.Message } }')
    $lines.Add('if (-not $loaded) {')
    $lines.Add('    Write-Host ''The Exchange cmdlets could not be loaded, so HealthChecker cannot run.'' -ForegroundColor Red')
    $lines.Add('} else {')
    $lines.Add(('    & {0} -OutputFilePath {1} -SkipVersionCheck' -f (& $q $ScriptPath), (& $q $OutDir)))
    $lines.Add('    Write-Host ''''; Write-Host ''Building the HTML report...''')
    $lines.Add(('    & {0} -BuildHtmlServersReport -XMLDirectoryPath {1} -HtmlReportFile {2} -SkipVersionCheck' -f (& $q $ScriptPath), (& $q $OutDir), (& $q $html)))
    $lines.Add('    Write-Host ''''')
    $lines.Add(('    Write-Host (''Results: '' + {0}) -ForegroundColor Green' -f (& $q $OutDir)))
    $lines.Add(('    if (Test-Path -LiteralPath {0}) {{ Write-Host (''HTML report: '' + {0}) -ForegroundColor Green }}' -f (& $q $html)))
    $lines.Add('}')
    return [pscustomobject]@{ text = ($lines -join [Environment]::NewLine); html = $html }
}

function Get-EtkIpLocation {
    # The ONLY code in this tool that sends data to a third party: public
    # addresses to ipapi.co, from the "Look up locations..." button after a
    # confirmation that lists them. Never called by a check or job (a test
    # scans for it). -Fetch exists so tests never touch the network.
    param([string[]]$Ips, [int]$Max = 50, [int]$PauseMs = 600, [scriptblock]$Fetch = $null)
    if (-not $Fetch) { $Fetch = { param($u) Invoke-RestMethod -Uri $u -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop } }
    $g = 'IP locations'
    # De-duplicated in the order given (busiest first), not sorted.
    $clean = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($Ips | ForEach-Object { ([string]$_).Trim() } | Where-Object { Test-EtkPublicIp $_ })) { if (-not $clean.Contains($i)) { $clean.Add($i) } }
    $refused = @(@($Ips | Where-Object { -not (Test-EtkPublicIp ([string]$_)) })).Count
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    $rows = New-Object System.Collections.Generic.List[object]
    $sent = 0; $stopped = ''
    $batch = @($clean | Select-Object -First $Max)
    foreach ($ip in $batch) {
        if ($sent -gt 0 -and $PauseMs -gt 0) { Start-Sleep -Milliseconds $PauseMs }
        $url = ('https://ipapi.co/{0}/json/' -f [uri]::EscapeDataString($ip))
        $sent++
        $j = $null
        try { $j = & $Fetch $url }
        catch {
            $m = $_.Exception.Message
            # The refused request still carried its address, so it stays counted as sent.
            if ($m -match '429|Too Many Requests') { $stopped = ('ipapi.co''s rate limit was reached after {0} address(es); try the rest later.' -f ($sent - 1)); break }
            $rows.Add((New-EtkRow -Group $g -Check $ip -Result 'Lookup failed' -Basis 'not measured' -Status 'info' -Detail $m)); continue
        }
        if ($j.error) {
            if ([string]$j.reason -match 'RateLimited') { $stopped = ('ipapi.co''s rate limit was reached after {0} address(es); try the rest later.' -f ($sent - 1)); break }
            $rows.Add((New-EtkRow -Group $g -Check $ip -Result ('No location: {0}' -f $j.reason) -Basis 'not measured' -Status 'info')); continue
        }
        $place = (@($j.country_name, $j.region, $j.city | Where-Object { $_ })) -join ', '
        $rows.Add((New-EtkRow -Group $g -Check $ip -Result $(if ($place) { $place } else { 'Unknown' }) -Basis 'inference' -Status 'info' `
            -Detail ('Network: {0}{1}. A third-party estimate - often right only to the country.' -f $(if ($j.org) { $j.org } else { 'unknown' }), $(if ($j.asn) { ' (' + $j.asn + ')' } else { '' }))))
    }
    $cav = @('Locations come from ipapi.co, a third-party service, and are estimates.')
    if ($clean.Count -gt $Max) { $cav += ('Only the first {0} of {1} public addresses were looked up.' -f $Max, $clean.Count) }
    if ($stopped) { $cav += $stopped }
    if ($refused) { $cav += ('{0} private or invalid address(es) were not sent.' -f $refused) }
    $section = New-EtkSection -State measured -Method ('ipapi.co, one HTTPS request per public address, sent from {0}' -f $env:COMPUTERNAME) -Caveats $cav -Rows $rows.ToArray() `
        -Data ([pscustomobject]@{ service = 'ipapi.co'; sent = $sent; requested = $clean.Count })
    [pscustomobject]@{ section = $section; sent = $sent; requested = $clean.Count; stopped = $stopped }
}

function ConvertTo-EtkEncodedCommand {
    # Pure. What powershell.exe -EncodedCommand expects: UTF-16LE, base64.
    param([string]$Text)
    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Text))
}

# ===========================================================================
#  VERDICT AND REPORT
# ===========================================================================

function Get-EtkAreaMap {
    [ordered]@{
        'Server & support'       = @('server')
        'Services & components'  = @('services', 'serviceHealth', 'components', 'appPools')
        'Databases'              = @('databases')
        'Mail flow'              = @('queues', 'backPressure', 'throughput')
        'Disk & memory'          = @('disks', 'memory', 'diskLatency')
        'Certificates'           = @('certificates')
        'Events & restarts'      = @('eventSignals', 'restarts', 'logNoise', 'eventLogs')
        'Backup & snapshots'     = @('exBackup', 'vssWriters', 'shadowCopies', 'filters', 'agents', 'sentinel', 'crashplan', 'schedule')
        'Security'               = @('failedLogins', 'logons', 'exposure')
    }
}

function Test-EtkSectionPartial {
    # Pure. A section that ran but could not read every source it needs
    # (data.notMeasured) - for example failed logins without the Security
    # log. Counts like an unsupported section for the "clear" rule.
    param($Section)
    if (-not $Section -or $Section.state -ne 'measured' -or -not $Section.data) { return $false }
    $nm = $null
    try { $nm = $Section.data.notMeasured } catch { }
    return (@($nm | Where-Object { $_ }).Count -gt 0)
}

function Get-EtkSectionTitle {
    # Display names for section keys, for verdict text a person reads.
    param([string]$Key)
    $t = @{
        server = 'Server facts'; restarts = 'Restarts'; services = 'Services'; serviceHealth = 'Service health'
        components = 'Component state'; appPools = 'IIS app pools'; databases = 'Databases'; certificates = 'Certificates'
        disks = 'Disk space'; memory = 'Memory'; diskLatency = 'Disk latency'; eventLogs = 'Event log retention'
        eventSignals = 'Event signals'; logNoise = 'Log noise'; queues = 'Queues'; backPressure = 'Back pressure'
        throughput = 'Throughput'; exBackup = 'Exchange backups'; vssWriters = 'VSS writers'; shadowCopies = 'Shadow copies'
        filters = 'Volume filter drivers'; agents = 'Backup software'; sentinel = 'SentinelOne snapshots'
        crashplan = 'CrashPlan'; schedule = 'Schedule'
        failedLogins = 'Failed logins'; logons = 'Logons'; exposure = 'Exposure'; ipLookup = 'IP locations'
    }
    if ($t.ContainsKey($Key)) { return $t[$Key] }
    return $Key
}

function Get-EtkVerdict {
    # One subscore per area: the worst row status among the area's MEASURED
    # sections. An area where nothing was measured is 'notmeasured', never
    # green.
    param([hashtable]$Sections)
    $subs = @()
    $map = Get-EtkAreaMap
    foreach ($area in $map.Keys) {
        $measured = @($map[$area] | ForEach-Object { $Sections[$_] } | Where-Object { $_ -and $_.state -eq 'measured' })
        $failedSecs = @($map[$area] | ForEach-Object { $Sections[$_] } | Where-Object { $_ -and $_.state -eq 'failed' })
        if ($measured.Count -eq 0) {
            $why = 'Not run yet.'
            if ($failedSecs.Count) { $why = 'A check failed to run: ' + [string]$failedSecs[0].reason }
            $subs += New-EtkSubscore -Name $area -Level 'notmeasured' -Summary $why
            continue
        }
        $rows = @($measured | ForEach-Object { @($_.rows) } | Where-Object { $_ })
        $fail = @($rows | Where-Object { $_.status -eq 'fail' })
        $warn = @($rows | Where-Object { $_.status -eq 'warn' })
        # Sections that could not run here (no elevation, no Exchange). A
        # problem found elsewhere in the area still counts; but "clean" is
        # only claimed when everything in the area actually ran - otherwise
        # green would be a match reported by omission.
        $missing = @($map[$area] | Where-Object { $Sections[$_] -and ($Sections[$_].state -in @('unsupported', 'failed') -or (Test-EtkSectionPartial $Sections[$_])) })
        if ($fail.Count) {
            $subs += New-EtkSubscore -Name $area -Level 'red' -Summary ('{0}: {1}' -f $fail[0].check, $fail[0].result) -Remedy ('{0} problem(s), {1} warning(s).' -f $fail.Count, $warn.Count)
        } elseif ($warn.Count) {
            $subs += New-EtkSubscore -Name $area -Level 'amber' -Summary ('{0}: {1}' -f $warn[0].check, $warn[0].result) -Remedy ('{0} warning(s).' -f $warn.Count)
        } elseif ($missing.Count) {
            $subs += New-EtkSubscore -Name $area -Level 'notmeasured' -Summary ('Partly measured: nothing flagged in what ran, but {0} could not run.' -f ((@($missing | ForEach-Object { $(if (Test-EtkSectionPartial $Sections[$_]) { (Get-EtkSectionTitle $_) + ' (in part)' } else { Get-EtkSectionTitle $_ }) })) -join ', ')) `
                -Remedy 'Not counted as clear.'
        } else {
            $subs += New-EtkSubscore -Name $area -Level 'green' -Summary 'Nothing flagged.'
        }
    }
    return Get-EtkHealth -Subscores $subs
}

function Get-EtkVerdictCounts {
    # Pure. How many areas are red / amber / green / not measured - the
    # numbers behind the overall indicator. Deliberately counts, not a score.
    param($Verdict)
    $c = [ordered]@{ red = 0; amber = 0; green = 0; notmeasured = 0 }
    foreach ($s in @($Verdict.subscores)) { if ($s -and $c.Contains([string]$s.level)) { $c[[string]$s.level]++ } }
    $parts = @()
    if ($c.red)   { $parts += ('{0} with problems' -f $c.red) }
    if ($c.amber) { $parts += ('{0} with warnings' -f $c.amber) }
    if ($c.green) { $parts += ('{0} clear' -f $c.green) }
    if ($c.notmeasured) { $parts += ('{0} not measured' -f $c.notmeasured) }
    [pscustomobject]@{ red = $c.red; amber = $c.amber; green = $c.green; notmeasured = $c.notmeasured
        text = $(if ($parts.Count) { 'Areas: ' + ($parts -join ', ') } else { 'Nothing run yet.' }) }
}

function Get-EtkWorstStatus {
    # Pure. Worst status across some sections: 'fail', 'warn', 'ok', or
    # 'none' when nothing in them was measured. A section that could not run
    # counts as 'fail' - an area that broke is not a healthy one.
    param($Sections)
    $list = @($Sections | Where-Object { $_ })
    if ($list.Count -eq 0) { return 'none' }
    $rank = @{ none = 0; ok = 1; warn = 2; fail = 3 }
    $worst = 'none'
    $couldNotRun = $false
    foreach ($s in $list) {
        if ($s.state -eq 'failed') { $st = 'fail' }
        elseif ($s.state -eq 'unsupported') { $couldNotRun = $true; continue }
        elseif ($s.state -ne 'measured') { continue }
        else {
            if (Test-EtkSectionPartial $s) { $couldNotRun = $true }
            $st = 'ok'
            foreach ($r in @($s.rows)) {
                if ($r.status -eq 'fail') { $st = 'fail'; break }
                if ($r.status -eq 'warn') { $st = 'warn' }
            }
        }
        if ($rank[$st] -gt $rank[$worst]) { $worst = $st }
    }
    # Same rule as the verdict: never show "ok" when part of it did not run.
    if ($worst -eq 'ok' -and $couldNotRun) { return 'none' }
    return $worst
}

function New-EtkReport {
    param($Sections, $Verdict, $Target, $Context, $Actions, [datetime]$StartedUtc = [datetime]::MinValue)
    [pscustomobject]@{
        schema        = 'exchange-toolkit-report'
        schemaVersion = 1
        tool          = [pscustomobject]@{ name = 'Exchange Toolkit'; version = (Get-EtkVersion) }
        collectedUtc  = (ConvertTo-EtkIso8601 ([datetime]::UtcNow))
        startedUtc    = (ConvertTo-EtkIso8601 $StartedUtc)
        host          = $Context
        target        = $Target
        verdict       = $Verdict
        sections      = $Sections
        actions       = [object[]]@($Actions)
        knownLimits   = (Get-EtkKnownLimits)
    }
}

function ConvertTo-EtkJson {
    param($Report, [switch]$Compress)
    if ($Compress) { return ($Report | ConvertTo-Json -Depth 14 -Compress) }
    return ($Report | ConvertTo-Json -Depth 14)
}

function Get-EtkMarkedJson {
    param($Report)
    $m = Get-EtkJsonMarkers
    return ($m.Begin + [Environment]::NewLine + (ConvertTo-EtkJson $Report) + [Environment]::NewLine + $m.End)
}

# ===========================================================================
#  EVIDENCE - export a time window (read-only)
# ===========================================================================

function Get-EtkEventsWindow {
    # OS-level. Application + System events in a window, as plain records.
    param([string]$StartIso, [string]$EndIso, [int]$Cap = 50000)
    $s = [datetime]::Parse($StartIso).ToLocalTime(); $e = [datetime]::Parse($EndIso).ToLocalTime()
    $out = @()
    foreach ($log in @('Application', 'System')) {
        try {
            foreach ($x in @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $s; EndTime = $e } -MaxEvents $Cap -ErrorAction Stop)) {
                $out += [pscustomobject]@{ TimeCreated = $x.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); LogName = $log; ProviderName = [string]$x.ProviderName
                    Id = [int]$x.Id; Level = [int]$x.Level; LevelDisplayName = [string]$x.LevelDisplayName; Message = [string]$x.Message }
            }
        } catch { if ($_.Exception.Message -notmatch 'No events were found') { throw } }
    }
    return $out
}

function Get-EtkIisWindow {
    # OS-level. IIS log lines inside a window. IIS writes UTC timestamps, so
    # the window is converted to UTC here - forgetting that is the classic
    # way to read the wrong two hours.
    param([string]$StartIso, [string]$EndIso, [int]$MaxLines = 200000)
    $s = [datetime]::Parse($StartIso).ToUniversalTime(); $e = [datetime]::Parse($EndIso).ToUniversalTime()
    $root = 'C:\inetpub\logs\LogFiles'
    $out = @()
    if (-not (Test-Path -LiteralPath $root)) { return $out }
    $days = @(); $d = $s.Date; while ($d -le $e.Date) { $days += $d.ToString('yyMMdd'); $d = $d.AddDays(1) }
    foreach ($site in @(Get-ChildItem -LiteralPath $root -Directory -Filter 'W3SVC*' -ErrorAction SilentlyContinue)) {
        $fields = ''; $lines = New-Object System.Collections.Generic.List[string]
        foreach ($day in $days) {
            foreach ($f in @(Get-ChildItem -LiteralPath $site.FullName -Filter ('u_ex{0}*.log' -f $day) -File -ErrorAction SilentlyContinue)) {
                foreach ($ln in [System.IO.File]::ReadLines($f.FullName)) {
                    if ($ln.StartsWith('#Fields:')) { $fields = $ln; continue }
                    if ($ln.StartsWith('#') -or $ln.Length -lt 20) { continue }
                    $ts = [datetime]::MinValue
                    if (-not [datetime]::TryParseExact($ln.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$ts)) { continue }
                    if ($ts -ge $s -and $ts -lt $e) { $lines.Add($ln); if ($lines.Count -ge $MaxLines) { break } }
                }
            }
        }
        $out += [pscustomobject]@{ site = $site.Name; fields = $fields; lines = [object[]]$lines.ToArray(); capped = ($lines.Count -ge $MaxLines) }
    }
    return $out
}

function Get-EtkIisStatusSummary {
    # Pure. Status codes counted using the #Fields header to find the column,
    # rather than assuming the default layout.
    param([string]$Fields, [string[]]$Lines)
    $names = @(($Fields -replace '^#Fields:\s*', '') -split '\s+' | Where-Object { $_ })
    $idx = [array]::IndexOf($names, 'sc-status')
    if ($idx -lt 0) { return $null }
    $counts = @{}
    foreach ($ln in $Lines) {
        $p = $ln -split ' '
        if ($p.Count -le $idx) { continue }
        $k = $p[$idx]
        if ($counts.ContainsKey($k)) { $counts[$k]++ } else { $counts[$k] = 1 }
    }
    return $counts
}

function Export-EtkEvidence {
    # Runs in the worker. Writes everything to OutDir on THIS machine.
    param([datetime]$Start, [datetime]$End, [string]$OutDir, [bool]$Events = $true, [bool]$Tracking = $true, [bool]$Iis = $true, [bool]$HttpProxy = $true, $Shared = $null)
    $note = { param($m) if ($Shared) { [void]$Shared.Log.Add($m) } }
    [void](New-Item -ItemType Directory -Path $OutDir -Force)
    $sIso = ConvertTo-EtkIso8601 $Start; $eIso = ConvertTo-EtkIso8601 $End
    $summary = New-Object System.Collections.Generic.List[string]
    $summary.Add(('Exchange Toolkit {0} evidence pack' -f (Get-EtkVersion)))
    $summary.Add(('Target: {0}   Window (local): {1} to {2}   (UTC {3} to {4})' -f (Get-EtkTarget).name, $Start.ToString('yyyy-MM-dd HH:mm'), $End.ToString('yyyy-MM-dd HH:mm'), $sIso, $eIso))
    $enc = New-Object System.Text.UTF8Encoding $false

    if ($Events) {
        & $note 'Evidence: reading Application and System events...'
        try {
            $ev = @(Invoke-EtkOs -Name 'Get-EtkEventsWindow' -Parameters @{ StartIso = $sIso; EndIso = $eIso })
            foreach ($log in @('Application', 'System')) {
                $ev | Where-Object { $_.LogName -eq $log } | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
                    Export-Csv -LiteralPath (Join-Path $OutDir ($log + '.csv')) -NoTypeInformation -Encoding UTF8
            }
            $counts = @{}; foreach ($x in $ev) { $p = [string]$x.ProviderName; if ($counts.ContainsKey($p)) { $counts[$p]++ } else { $counts[$p] = 1 } }
            $noise = Get-EtkLogNoise -ProviderCounts $counts -Threshold 0.3
            $skip = $(if ($noise -and $noise.noisy) { $noise.provider } else { '' })
            $tl = New-Object System.Collections.Generic.List[string]
            if ($skip) { $tl.Add(('(left out: {0}, which wrote {1:N0}% of all events in the window)' -f $skip, (100 * $noise.share))) }
            foreach ($x in @($ev | Where-Object { $_.Level -ge 1 -and $_.Level -le 3 -and $_.ProviderName -ne $skip } | Sort-Object TimeCreated)) {
                $tl.Add(('{0}  {1,-8} {2,-40} {3,6}  {4}' -f $x.TimeCreated, $x.LogName, $x.ProviderName, $x.Id, (Get-EtkFirstLine $x.Message 300)))
            }
            [System.IO.File]::WriteAllLines((Join-Path $OutDir 'Timeline.txt'), $tl.ToArray(), $enc)
            $summary.Add(('Events: {0:N0} (Application.csv, System.csv); {1:N0} errors/warnings in Timeline.txt' -f $ev.Count, ($tl.Count)))
        } catch { $summary.Add(('Events: FAILED - {0}' -f $_.Exception.Message)) }
    }

    if ($Tracking) {
        & $note 'Evidence: reading message tracking...'
        if (Test-EtkExchangeAvailable) {
            try {
                $mt = @(Get-MessageTrackingLog -Server (Get-EtkExchangeServerName) -Start $Start -End $End -ResultSize 100000 -ErrorAction Stop |
                    Select-Object Timestamp, EventId, Source, Sender, @{ n = 'Recipients'; e = { (@($_.Recipients) -join ';') } }, MessageSubject, MessageId)
                $mt | Export-Csv -LiteralPath (Join-Path $OutDir 'MessageTracking.csv') -NoTypeInformation -Encoding UTF8
                $s = Get-EtkTrackingSummary -Entries $mt
                $bl = @('bucket            RECEIVE DELIVER SEND SENDEXT FAIL  msgs  p90s  maxs')
                foreach ($b in $s.buckets) {
                    $bl += ('{0}  {1,7} {2,7} {3,4} {4,7} {5,4} {6,5} {7,5} {8,5}' -f $b.bucket, $b.counts.RECEIVE, $b.counts.DELIVER, $b.counts.SEND, $b.counts.SENDEXTERNAL, $b.counts.FAIL, $b.messages,
                        $(if ($null -ne $b.p90Sec) { [int]$b.p90Sec } else { '' }), $(if ($null -ne $b.maxSec) { [int]$b.maxSec } else { '' }))
                }
                [System.IO.File]::WriteAllLines((Join-Path $OutDir 'MessageTracking_Buckets.txt'), [string[]]$bl, $enc)
                $summary.Add(('Message tracking: {0:N0} events, {1:N0} distinct messages (MessageTracking.csv, MessageTracking_Buckets.txt)' -f $mt.Count, $s.distinctMessages))
            } catch { $summary.Add(('Message tracking: FAILED - {0}' -f $_.Exception.Message)) }
        } else { $summary.Add('Message tracking: skipped - Exchange cmdlets are not loaded (press Connect).') }
    }

    if ($Iis) {
        & $note 'Evidence: reading IIS logs (UTC)...'
        try {
            $sites = @(Invoke-EtkOs -Name 'Get-EtkIisWindow' -Parameters @{ StartIso = $sIso; EndIso = $eIso })
            if ($sites.Count -eq 0) { $summary.Add('IIS: no W3SVC* log folders under C:\inetpub\logs\LogFiles (IIS not installed, or logging moved).') }
            foreach ($site in $sites) {
                $file = Join-Path $OutDir ('IIS_{0}.log' -f $site.site)
                $content = @(); if ($site.fields) { $content += $site.fields }; $content += @($site.lines)
                [System.IO.File]::WriteAllLines($file, [string[]]$content, $enc)
                $sc = Get-EtkIisStatusSummary -Fields $site.fields -Lines ([string[]]@($site.lines))
                $scText = $(if ($sc) { (($sc.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join ', ') } else { 'no #Fields header' })
                $summary.Add(('IIS {0}: {1:N0} lines{2}; status codes {3}' -f $site.site, @($site.lines).Count, $(if ($site.capped) { ' (CAPPED)' } else { '' }), $scText))
            }
        } catch { $summary.Add(('IIS: FAILED - {0}' -f $_.Exception.Message)) }
    }

    if ($HttpProxy) {
        $t = Get-EtkTarget
        if (-not $t.isLocal) { $summary.Add('HttpProxy logs: skipped for a remote target - copy them from the server.') }
        else {
            $exPath = Get-EtkRegValue 'SOFTWARE\Microsoft\ExchangeServer\v15\Setup' 'MsiInstallPath'
            $hp = $(if ($exPath) { Join-Path $exPath 'Logging\HttpProxy' } else { $null })
            if ($hp -and (Test-Path -LiteralPath $hp)) {
                & $note 'Evidence: copying HttpProxy logs for the window...'
                $n = 0
                foreach ($f in @(Get-ChildItem -LiteralPath $hp -Recurse -File -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $Start -and $_.CreationTime -le $End.AddHours(1) })) {
                    $rel = $f.FullName.Substring($hp.Length).TrimStart('\')
                    $dest = Join-Path (Join-Path $OutDir 'HttpProxy') $rel
                    [void](New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force)
                    Copy-Item -LiteralPath $f.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                    $n++
                }
                $summary.Add(('HttpProxy logs: {0} files copied to HttpProxy\' -f $n))
            } else { $summary.Add('HttpProxy logs: folder not found.') }
        }
    }
    [System.IO.File]::WriteAllLines((Join-Path $OutDir 'Summary.txt'), $summary.ToArray(), $enc)
    return [pscustomobject]@{ folder = $OutDir; summary = [object[]]$summary.ToArray() }
}

# ===========================================================================
#  JOBS - what each button runs. Checks only; actions are a separate job.
# ===========================================================================

function Get-EtkExchangeData {
    # Databases and transport paths, read once per job. Failures are kept
    # quiet here because the sections that need the data report them.
    $d = @(); $t = $null
    if (Test-EtkExchangeAvailable) {
        try { $d = @(Get-EtkDatabaseInfo) } catch { }
        try { $t = Get-EtkTransportInfo } catch { }
        if ($t -and [string]::IsNullOrWhiteSpace($t.queuePath)) {
            try {
                $qp = Invoke-EtkOs -Name 'Get-EtkQueuePath'
                if ($qp) {
                    $t.queuePath = [string]$qp.queuePath; $t.queueLogPath = [string]$qp.queueLogPath
                    $t | Add-Member -NotePropertyName queuePathSource -NotePropertyValue ([string]$qp.source) -Force
                }
            } catch { }
        }
    }
    [pscustomobject]@{ databases = $d; transport = $t; volumes = (Get-EtkExchangeVolumes -Databases $d -Transport $t) }
}

function Invoke-EtkJob {
    param([string]$Job, $Opt, $Shared)
    $publish = {
        param($key, $section)
        $Shared.Sections[$key] = $section
        $Shared.Version = [int]$Shared.Version + 1
    }
    $step = {
        param([string]$text, [int]$pct)
        $Shared.Status = $text; $Shared.Progress = $pct
    }
    $plan = @()
    switch ($Job) {
        'overview' { $plan = @('overview') }
        'health'   { $plan = @('health') }
        'mailflow' { $plan = @('mailflow') }
        'storage'  { $plan = @('storage') }
        'security' { $plan = @('security') }
        'all'      { $plan = @('overview', 'health', 'mailflow', 'storage', 'security') }
        default    { throw ('Unknown job "{0}".' -f $Job) }
    }
    $ex = Get-EtkExchangeData
    $volKeys = [string[]]@($ex.volumes.Keys)
    $hours = [int]$Opt.Hours; if ($hours -le 0) { $hours = 24 }
    $trackH = [int]$Opt.TrackingHours; if ($trackH -le 0) { $trackH = 2 }
    $n = 0
    foreach ($p in $plan) {
        if ($Shared.Cancel) { break }
        $base = [int](100 * $n / $plan.Count); $span = [int](100 / $plan.Count); $n++
        switch ($p) {
            'overview' {
                & $step 'Server facts...' ($base)
                & $publish 'server' (Invoke-EtkOsSection -Name 'Test-EtkServerFacts' -Group 'Server')
                & $step 'Restarts...' ($base + $span / 2)
                & $publish 'restarts' (Invoke-EtkOsSection -Name 'Test-EtkRestarts' -Group 'Restarts')
            }
            'health' {
                $steps = @(
                    @{ k = 'services';      t = 'Services';           os = 'Test-EtkServices';     p = @{} }
                    @{ k = 'serviceHealth'; t = 'Test-ServiceHealth'; ex = { Test-EtkServiceHealth } }
                    @{ k = 'components';    t = 'Component state';    ex = { Test-EtkComponents } }
                    @{ k = 'appPools';      t = 'IIS app pools';      os = 'Test-EtkAppPools';     p = @{} }
                    @{ k = 'databases';     t = 'Databases';          ex = {
                            $lf = @()
                            $paths = @($ex.databases | ForEach-Object { $_.logPath } | Where-Object { $_ })
                            if ($paths.Count) { try { $lf = @(Invoke-EtkOs -Name 'Get-EtkFolderStats' -Parameters @{ Paths = [string[]]$paths }) } catch { } }
                            Test-EtkDatabases -Databases $ex.databases -LogFolders $lf } }
                    @{ k = 'certificates';  t = 'Certificates';       ex = {
                            $ib = @(); try { $ib = @(Invoke-EtkOs -Name 'Get-EtkIisCertBindings') } catch { }
                            Test-EtkCertificates -IisBindings $ib } }
                    @{ k = 'disks';         t = 'Disk space';         os = 'Test-EtkDisks';        p = @{ ExchangeVolumes = $volKeys } }
                    @{ k = 'memory';        t = 'Memory';             os = 'Test-EtkMemoryCache';  p = @{} }
                    @{ k = 'eventLogs';     t = 'Event log retention';os = 'Test-EtkEventLogs';    p = @{} }
                    @{ k = 'eventSignals';  t = 'Event signals';      os = 'Test-EtkEventSignals'; p = @{ Hours = $hours } }
                    @{ k = 'logNoise';      t = 'Log noise';          os = 'Test-EtkLogNoise';     p = @{} }
                    @{ k = 'diskLatency';   t = 'Disk latency (10 s)';os = 'Test-EtkDiskLatency';  p = @{} }
                )
                $i = 0
                foreach ($s in $steps) {
                    if ($Shared.Cancel) { break }
                    & $step ('Health: {0}...' -f $s.t) ($base + [int]($span * $i / $steps.Count)); $i++
                    if ($s.os) { & $publish $s.k (Invoke-EtkOsSection -Name $s.os -Parameters $s.p -Group $s.t) }
                    else { & $publish $s.k (& $s.ex) }
                }
            }
            'mailflow' {
                $steps = @(
                    @{ k = 'queues';          t = 'Queues';             ex = { Test-EtkQueues } }
                    @{ k = 'backPressure';    t = 'Back pressure';      ex = { Test-EtkBackPressure } }
                    @{ k = 'throughput';      t = 'Message tracking';   ex = { Test-EtkThroughput -Hours $trackH } }
                    @{ k = 'transportConfig'; t = 'Transport settings'; ex = { if ($ex.transport) { Test-EtkTransportConfig -Transport $ex.transport } else { Get-EtkExchangeUnavailableSection 'Transport settings' } } }
                    @{ k = 'connectors';      t = 'Connectors';         ex = { Test-EtkConnectors } }
                )
                $i = 0
                foreach ($s in $steps) {
                    if ($Shared.Cancel) { break }
                    & $step ('Mail flow: {0}...' -f $s.t) ($base + [int]($span * $i / $steps.Count)); $i++
                    & $publish $s.k (& $s.ex)
                }
            }
            'storage' {
                $steps = @(
                    @{ k = 'exBackup';     t = 'Exchange backups';     ex = { Test-EtkExchangeBackup -Databases $ex.databases } }
                    @{ k = 'vssWriters';   t = 'VSS writers';          os = 'Test-EtkVssWriters';    p = @{} }
                    @{ k = 'shadowCopies'; t = 'Shadow copies';        os = 'Test-EtkShadowCopies';  p = @{ ExchangeVolumes = $ex.volumes } }
                    @{ k = 'filters';      t = 'Volume filters';       os = 'Test-EtkVolumeFilters'; p = @{} }
                    @{ k = 'agents';       t = 'Backup software';      os = 'Test-EtkAgents';        p = @{} }
                    @{ k = 'sentinel';     t = 'SentinelOne snapshots'; os = 'Test-EtkSentinelSnapshots'; p = @{} }
                    @{ k = 'crashplan';    t = 'CrashPlan';            os = 'Test-EtkCrashPlan';     p = @{} }
                    @{ k = 'schedule';     t = 'Schedule';             os = 'Test-EtkSchedule';      p = @{ WindowStart = [string]$Opt.WindowStart; WindowEnd = [string]$Opt.WindowEnd; ExchangeVolumes = $ex.volumes } }
                )
                $i = 0
                foreach ($s in $steps) {
                    if ($Shared.Cancel) { break }
                    & $step ('Storage: {0}...' -f $s.t) ($base + [int]($span * $i / $steps.Count)); $i++
                    if ($s.os) { & $publish $s.k (Invoke-EtkOsSection -Name $s.os -Parameters $s.p -Group $s.t) }
                    else { & $publish $s.k (& $s.ex) }
                }
            }
            'security' {
                & $step 'Security: failed logins...' ($base)
                $fl = Invoke-EtkOsSection -Name 'Test-EtkFailedLogins' -Parameters @{ Hours = $hours } -Group 'Failed logins'
                & $publish 'failedLogins' $fl
                # Addresses with repeated failures, so a later SUCCESS from one
                # of them is flagged in the logons section.
                $sus = [string[]]@()
                try { if ($fl.data -and $fl.data.suspectIps) { $sus = [string[]]@($fl.data.suspectIps) } } catch { }
                if (-not $Shared.Cancel) {
                    & $step 'Security: logons...' ($base + [int]($span / 3))
                    & $publish 'logons' (Invoke-EtkOsSection -Name 'Test-EtkLogons' -Parameters @{ Hours = $hours; SuspectIps = $sus } -Group 'Logons')
                }
                if (-not $Shared.Cancel) {
                    & $step 'Security: exposure...' ($base + [int](2 * $span / 3))
                    & $publish 'exposure' (Invoke-EtkOsSection -Name 'Test-EtkExposure' -Group 'Exposure')
                }
            }
        }
    }
    & $step 'Done.' 100
}

#endregion ENGINE

if ($EngineOnly) { return }

# ===========================================================================
#  From here down is the user interface. Nothing below this line may be
#  referenced by the engine.
# ===========================================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

if (-not $NoHideConsole) {
    try {
        if (-not ('EtkNative.Win' -as [type])) {
            Add-Type -Namespace 'EtkNative' -Name 'Win' -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[DllImport("user32.dll")]   public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
'@
        }
        $h = [EtkNative.Win]::GetConsoleWindow()
        if ($h -ne [System.IntPtr]::Zero) { [void][EtkNative.Win]::ShowWindow($h, 0) }
    } catch { }
}

# ---------------------------------------------------------------------------
#  Engine source, extracted from this very file. The worker runspace and any
#  remote Invoke-Command rebuild the engine from this text, which is what
#  keeps the tool a single file and guarantees one set of code everywhere.
# ---------------------------------------------------------------------------
$SelfSource = ''
try { $SelfSource = $MyInvocation.MyCommand.ScriptBlock.ToString() } catch { }
if ([string]::IsNullOrWhiteSpace($SelfSource)) {
    $selfPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($selfPath)) { $selfPath = $MyInvocation.MyCommand.Path }
    if ($selfPath -and (Test-Path -LiteralPath $selfPath)) { $SelfSource = [System.IO.File]::ReadAllText($selfPath) }
}
$EngineSource = ''
$m = [regex]::Match($SelfSource, '(?s)#region ENGINE(.*?)#endregion ENGINE')
if ($m.Success) { $EngineSource = $m.Groups[1].Value }
if ([string]::IsNullOrWhiteSpace($EngineSource)) {
    [void][System.Windows.Forms.MessageBox]::Show('The engine section of this script could not be read. The "#region ENGINE" / "#endregion ENGINE" markers must be intact.', 'Exchange Toolkit', 'OK', 'Error')
    return
}

# ---------------------------------------------------------------------------
#  UI state
# ---------------------------------------------------------------------------
$script:ScriptDir   = $(if ($PSScriptRoot) { $PSScriptRoot } else { [Environment]::GetFolderPath('Desktop') })
$script:OutputDir   = Join-Path $script:ScriptDir 'Output'
$script:Context     = Get-EtkHostContext
$script:Shared      = $null
$script:ps          = $null
$script:async       = $null
$script:engineRs    = $null
$script:busy        = $false
$script:logIndex    = 0
$script:lastVersion = -1
$script:currentJob  = ''
$script:Sections    = @{}
$script:Verdict     = $null
$script:Actions     = New-Object System.Collections.Generic.List[object]
$script:Target      = $null
$script:connectedTo = ''
$script:startedUtc  = [datetime]::UtcNow
$script:lastEvidence = ''
$script:tips        = New-Object System.Windows.Forms.ToolTip
$script:Account     = Get-EtkCurrentAccount
$script:Technician  = ''

# ---------------------------------------------------------------------------
#  Control factories (from the SMTP Toolkit)
# ---------------------------------------------------------------------------
function New-EtkButton {
    param([string]$Text, [int]$W = 150, [int]$H = 30, [string]$Tip = '')
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Width = $W; $b.Height = $H
    $b.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    if ($Tip) { $script:tips.SetToolTip($b, $Tip) }
    return $b
}

function New-EtkLabel {
    param([string]$Text, [bool]$Bold = $false, [int]$Size = 9)
    $l = New-Object System.Windows.Forms.Label
    $l.UseMnemonic = $false      # otherwise "Disk & memory" renders as "Disk  memory"
    $l.Text = $Text
    $l.AutoSize = $true
    $style = [System.Drawing.FontStyle]::Regular
    if ($Bold) { $style = [System.Drawing.FontStyle]::Bold }
    $l.Font = New-Object System.Drawing.Font('Segoe UI', $Size, $style)
    return $l
}

function New-EtkTextBox {
    param([int]$W = 220, [string]$Text = '')
    $t = New-Object System.Windows.Forms.TextBox
    $t.Width = $W; $t.Text = $Text
    $t.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    return $t
}

function New-EtkResultGrid {
    # Colours are set explicitly: an unthemed Server Core-ish session renders
    # a default DataGridView white-on-white until a row is selected.
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $false
    $g.AutoSizeColumnsMode = 'Fill'
    $g.BorderStyle = 'None'
    $g.BackgroundColor = [System.Drawing.Color]::White
    $g.DefaultCellStyle.BackColor = [System.Drawing.Color]::White
    $g.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
    $g.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $g.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $g.EnableHeadersVisualStyles = $false
    $g.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $g.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
    $g.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(214, 228, 245)
    $g.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Black
    foreach ($c in @(
        @{ n = 'group';  h = 'Area';   w = 13 },
        @{ n = 'check';  h = 'Check';  w = 22 },
        @{ n = 'result'; h = 'Result'; w = 27 },
        @{ n = 'basis';  h = 'Basis';  w = 9 },
        @{ n = 'act';    h = 'Act';    w = 4 },
        @{ n = 'detail'; h = 'What it means'; w = 30 }
    )) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $c.n; $col.HeaderText = $c.h; $col.FillWeight = $c.w
        [void]$g.Columns.Add($col)
    }
    $g.Columns['act'].ToolTipText = 'A dot means this row offers an action (right-click the row, or use the Actions button).'
    return $g
}

function Add-EtkGridRow {
    param($Grid, $Row)
    $hasAct = (@($Row.actions | Where-Object { $_ }).Count -gt 0)
    $i = $Grid.Rows.Add(@($Row.group, $Row.check, $Row.result, $Row.basis, $(if ($hasAct) { [char]0x25CF } else { '' }), $Row.detail))
    $r = $Grid.Rows[$i]
    $r.Tag = $Row
    switch ($Row.status) {
        'ok'   { $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(233, 247, 234) }
        'warn' { $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 246, 224) }
        'fail' { $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(253, 232, 232) }
        default { }
    }
    return $i
}

function New-EtkMonoBox {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Multiline = $true; $t.ReadOnly = $true; $t.Dock = 'Fill'
    $t.ScrollBars = 'Both'; $t.WordWrap = $false
    $t.BackColor = [System.Drawing.Color]::White
    $t.Font = New-Object System.Drawing.Font('Consolas', 9)
    return $t
}

function New-EtkToolbar {
    $p = New-Object System.Windows.Forms.FlowLayoutPanel
    $p.Dock = 'Top'; $p.Height = 40; $p.Padding = New-Object System.Windows.Forms.Padding(4, 4, 4, 0)
    $p.WrapContents = $false
    return $p
}

# ---------------------------------------------------------------------------
#  Worker. One persistent runspace serves every job, because the Exchange
#  session belongs to the runspace that opened it. It is created WITHOUT a
#  host, so anything that tries to prompt throws instead of waiting forever
#  behind a hidden console.
# ---------------------------------------------------------------------------
$WorkerScript = {
    param($Shared, $EngineSource, $Job, $Opt)
    . ([scriptblock]::Create($EngineSource))
    $global:EtkEngineSource = $EngineSource
    try {
        if ($Opt.ConnectFirst -or $Job -eq 'connect') {
            $Shared.Status = ('Connecting to {0}...' -f $Opt.Server)
            [void]$Shared.Log.Add(('Connecting to {0}...' -f $Opt.Server))
            $c = Connect-EtkExchange -Server $Opt.Server -AllowSnapin:([bool]$Opt.AllowSnapin)
            $Shared.Connection = $c
            foreach ($nt in @($c.notes)) { [void]$Shared.Log.Add($nt) }
        }
        switch ($Job) {
            'connect'    { }
            'disconnect' { Disconnect-EtkExchange }
            'action'     { $Shared.Result = Invoke-EtkAction -Id $Opt.Id -Arguments $Opt.Arguments -Server $Opt.ActionServer -ConfirmToken $Opt.Token -TypedServer $Opt.Typed -Technician $Opt.Technician }
            'evidence'   { $Shared.Result = Export-EtkEvidence -Start $Opt.Start -End $Opt.End -OutDir $Opt.OutDir -Events $Opt.Events -Tracking $Opt.Tracking -Iis $Opt.Iis -HttpProxy $Opt.HttpProxy -Shared $Shared }
            'services'   { $Shared.Status = 'Reading services...'; $Shared.Result = @(Invoke-EtkOs -Name 'Get-EtkManagedServices') }
            'healthchecker' { $Shared.Status = 'Downloading HealthChecker...'; $Shared.Result = Save-EtkHealthChecker -Folder $Opt.Folder }
            'iplookup'   {
                $Shared.Status = 'Looking up IP locations (ipapi.co)...'
                $r = Get-EtkIpLocation -Ips ([string[]]$Opt.Ips)
                $Shared.Sections['ipLookup'] = $r.section
                $Shared.Result = $r
                $Shared.Version = [int]$Shared.Version + 1
            }
            default      { Invoke-EtkJob -Job $Job -Opt $Opt -Shared $Shared }
        }
        if ($Job -in @('overview', 'health', 'mailflow', 'storage', 'security', 'all')) {
            $snap = @{}; foreach ($k in @($Shared.Sections.Keys)) { $snap[$k] = $Shared.Sections[$k] }
            $Shared.Verdict = Get-EtkVerdict -Sections $snap
            $Shared.Version = [int]$Shared.Version + 1
        }
    } catch {
        $Shared.Error = ('{0}{1}{2}' -f $_.Exception.Message, [Environment]::NewLine, $_.ScriptStackTrace)
    } finally {
        $Shared.Done = $true
    }
}

function Start-EtkEngine {
    $script:engineRs = [runspacefactory]::CreateRunspace()
    $script:engineRs.ApartmentState = 'STA'
    $script:engineRs.ThreadOptions = 'ReuseThread'
    $script:engineRs.Open()
}

function Write-EtkLog {
    param([string]$Message)
    $stamp = (Get-Date).ToString('HH:mm:ss')
    $script:txtLog.AppendText(('[{0}] {1}{2}' -f $stamp, $Message, [Environment]::NewLine))
}

function Set-EtkBusy {
    param([bool]$On)
    $script:busy = $On
    foreach ($b in $script:runButtons) { $b.Enabled = (-not $On) }
    $script:btnCancel.Enabled = $On
    if ($On) { $script:form.Cursor = [System.Windows.Forms.Cursors]::AppStarting }
    else     { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default; $script:progress.Value = 0 }
}

function Get-EtkUiOptions {
    $ws = $script:txtWinStart.Text.Trim(); $we = $script:txtWinEnd.Text.Trim()
    foreach ($v in @($ws, $we)) {
        if ($v -notmatch '^\d{1,2}:\d{2}$') {
            [void][System.Windows.Forms.MessageBox]::Show(('"{0}" is not a time. Use HH:mm, for example 05:00.' -f $v), 'Exchange Toolkit', 'OK', 'Warning')
            return $null
        }
    }
    $server = $script:txtServer.Text.Trim()
    if (-not $server) { $server = $env:COMPUTERNAME }
    @{
        Server = $server; AllowSnapin = $script:chkSnapin.Checked
        Hours = [int]$script:numHours.Value; TrackingHours = [int]$script:numTrack.Value
        WindowStart = $ws; WindowEnd = $we
        ConnectFirst = ($server.ToLowerInvariant() -ne $script:connectedTo.ToLowerInvariant())
    }
}

function Start-EtkJob {
    param([string]$Job, [hashtable]$Opt)
    if ($script:busy) { return }
    if (-not $Opt) { return }
    $sh = [hashtable]::Synchronized(@{})
    $sh.Log      = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $sh.Sections = [hashtable]::Synchronized(@{})
    foreach ($k in $script:Sections.Keys) { $sh.Sections[$k] = $script:Sections[$k] }
    $sh.Status = 'Starting...'; $sh.Progress = 0; $sh.Done = $false; $sh.Cancel = $false; $sh.Error = $null
    $sh.Version = 0; $sh.Verdict = $null; $sh.Result = $null; $sh.Connection = $null
    $script:Shared = $sh; $script:logIndex = 0; $script:lastVersion = -1; $script:currentJob = $Job
    if (-not $script:engineRs -or $script:engineRs.RunspaceStateInfo.State -ne 'Opened') { Start-EtkEngine }
    $script:ps = [powershell]::Create()
    $script:ps.Runspace = $script:engineRs
    [void]$script:ps.AddScript($WorkerScript.ToString()).AddParameter('Shared', $sh).AddParameter('EngineSource', $EngineSource).AddParameter('Job', $Job).AddParameter('Opt', $Opt)
    $script:async = $script:ps.BeginInvoke()
    Set-EtkBusy $true
    $script:timer.Start()
}

function Complete-EtkWorker {
    try { if ($script:ps -and $script:async) { [void]$script:ps.EndInvoke($script:async) } } catch { }
    try { if ($script:ps) { $script:ps.Dispose() } } catch { }
    $script:ps = $null; $script:async = $null
}

function Get-EtkSectionOrder {
    return @(
        @{ key = 'server';          title = 'Server';                 grid = 'overview' }
        @{ key = 'restarts';        title = 'Restarts';               grid = 'overview' }
        @{ key = 'services';        title = 'Services';               grid = 'health' }
        @{ key = 'serviceHealth';   title = 'Service health';         grid = 'health' }
        @{ key = 'components';      title = 'Component state';        grid = 'health' }
        @{ key = 'appPools';        title = 'IIS app pools';          grid = 'health' }
        @{ key = 'databases';       title = 'Databases';              grid = 'health' }
        @{ key = 'certificates';    title = 'Certificates';           grid = 'health' }
        @{ key = 'disks';           title = 'Disk space';             grid = 'health' }
        @{ key = 'memory';          title = 'Memory';                 grid = 'health' }
        @{ key = 'eventLogs';       title = 'Event log retention';    grid = 'health' }
        @{ key = 'eventSignals';    title = 'Event signals';          grid = 'health' }
        @{ key = 'logNoise';        title = 'Log noise';              grid = 'health' }
        @{ key = 'diskLatency';     title = 'Disk latency';           grid = 'health' }
        @{ key = 'queues';          title = 'Queues';                 grid = 'mailflow' }
        @{ key = 'backPressure';    title = 'Back pressure';          grid = 'mailflow' }
        @{ key = 'throughput';      title = 'Throughput';             grid = 'mailflow' }
        @{ key = 'transportConfig'; title = 'Transport settings';     grid = 'mailflow' }
        @{ key = 'connectors';      title = 'Connectors';             grid = 'mailflow' }
        @{ key = 'exBackup';        title = 'Exchange backups';       grid = 'storage' }
        @{ key = 'vssWriters';      title = 'VSS writers';            grid = 'storage' }
        @{ key = 'shadowCopies';    title = 'Shadow copies';          grid = 'storage' }
        @{ key = 'filters';         title = 'Volume filter drivers';  grid = 'storage' }
        @{ key = 'agents';          title = 'Backup & snapshot software'; grid = 'storage' }
        @{ key = 'sentinel';        title = 'SentinelOne snapshots';  grid = 'storage' }
        @{ key = 'crashplan';       title = 'CrashPlan';              grid = 'storage' }
        @{ key = 'schedule';        title = 'Schedule';               grid = 'storage' }
        @{ key = 'failedLogins';    title = 'Failed logins';          grid = 'security' }
        @{ key = 'logons';          title = 'Logons';                 grid = 'security' }
        @{ key = 'exposure';        title = 'Exposure';               grid = 'security' }
        @{ key = 'ipLookup';        title = 'IP locations';           grid = 'security' }
    )
}

function Get-EtkGrids {
    @{ overview = $script:gridOverview; health = $script:gridHealth; mailflow = $script:gridMail; storage = $script:gridStorage; security = $script:gridSecurity }
}

function Update-EtkGrids {
    $grids = Get-EtkGrids
    foreach ($g in $grids.Values) { $g.SuspendLayout(); $g.Rows.Clear() }
    foreach ($entry in (Get-EtkSectionOrder)) {
        $sec = $script:Sections[$entry.key]
        if (-not $sec) { continue }
        $grid = $grids[$entry.grid]
        if ($sec.state -ne 'measured') {
            # A section that did not run is shown, with its reason - hiding it
            # would let an untested area read as a healthy one.
            [void](Add-EtkGridRow -Grid $grid -Row (New-EtkRow -Group $entry.title -Check ('({0})' -f $sec.state) `
                -Result $(if ($sec.state -eq 'failed') { 'Could not run' } else { 'Not run' }) -Basis 'not measured' `
                -Status $(if ($sec.state -eq 'failed') { 'fail' } else { 'info' }) -Detail ([string]$sec.reason)))
        }
        foreach ($row in @($sec.rows)) { if ($row) { [void](Add-EtkGridRow -Grid $grid -Row $row) } }
    }
    foreach ($g in $grids.Values) {
        $g.ClearSelection()
        try { $g.CurrentCell = $null } catch { }
        $g.ResumeLayout()
    }
    # Each check tab's header is coloured by its worst result.
    foreach ($key in @('health', 'mailflow', 'storage', 'security')) {
        $secs = @(Get-EtkSectionOrder | Where-Object { $_.grid -eq $key } | ForEach-Object { $script:Sections[$_.key] })
        $script:TabStatus[$key] = Get-EtkWorstStatus -Sections $secs
    }
    $script:tabs.Invalidate()
}

function Get-EtkStatusColours {
    param([string]$Status)
    switch ($Status) {
        'fail' { return @{ back = [System.Drawing.Color]::FromArgb(246, 205, 205); fore = [System.Drawing.Color]::FromArgb(150, 20, 20) } }
        'warn' { return @{ back = [System.Drawing.Color]::FromArgb(252, 230, 180); fore = [System.Drawing.Color]::FromArgb(120, 75, 0) } }
        'ok'   { return @{ back = [System.Drawing.Color]::FromArgb(212, 238, 214); fore = [System.Drawing.Color]::FromArgb(20, 100, 35) } }
        default { return @{ back = [System.Drawing.SystemColors]::Control; fore = [System.Drawing.SystemColors]::ControlText } }
    }
}

function Set-EtkVerdictGridHeight {
    # Exactly the header plus the rows (plus a couple of pixels so no scroll
    # bar appears). Row heights follow the font/DPI, so they are measured,
    # not assumed.
    $g = $script:gridVerdict
    if (-not $g -or -not $script:ovLayout) { return }
    $rowsH = 0
    foreach ($r in $g.Rows) { $rowsH += $r.Height }
    if ($g.Rows.Count -eq 0) { $rowsH = $g.RowTemplate.Height * @((Get-EtkAreaMap).Keys).Count }
    # + the grid's own top/bottom margin inside the TableLayoutPanel cell.
    $h = $g.ColumnHeadersHeight + $rowsH + $g.Margin.Vertical + 3
    $script:ovLayout.RowStyles[1].Height = $h
}

function Update-EtkVerdictUi {
    $v = $script:Verdict
    if (-not $v) { Set-EtkVerdictGridHeight; return }
    $text = switch ($v.overall) { 'green' { 'NO PROBLEMS FOUND' } 'amber' { 'WARNINGS' } 'red' { 'PROBLEMS FOUND' } default { 'NOT MEASURED' } }
    $colour = switch ($v.overall) {
        'green' { [System.Drawing.Color]::FromArgb(20, 120, 40) }
        'amber' { [System.Drawing.Color]::FromArgb(170, 110, 0) }
        'red'   { [System.Drawing.Color]::FromArgb(180, 30, 30) }
        default { [System.Drawing.Color]::FromArgb(90, 90, 90) }
    }
    $script:lblOverall.Text = $text
    $script:lblOverall.ForeColor = $colour
    $script:lblHeadline.Text = [string]$v.headline
    $counts = Get-EtkVerdictCounts -Verdict $v
    $script:lblCounts.Text = $counts.text
    $script:lblCounts.Location = New-Object System.Drawing.Point(($script:lblOverall.Right + 16), 14)
    $script:lblBadge.Text = $text
    $script:lblBadge.BackColor = $colour
    $script:tips.SetToolTip($script:lblBadge, ('{0}{1}{2}{1}Click to open the Overview.' -f $counts.text, [Environment]::NewLine, [string]$v.headline))
    $script:TabStatus['overview'] = $(switch ($v.overall) { 'red' { 'fail' } 'amber' { 'warn' } 'green' { 'ok' } default { 'none' } })
    $script:tabs.Invalidate()
    $g = $script:gridVerdict
    $g.Rows.Clear()
    foreach ($s in @($v.subscores)) {
        $i = $g.Rows.Add(@($s.name, $s.level, $s.summary, $s.remedy))
        $r = $g.Rows[$i]
        switch ($s.level) {
            'green' { $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(233, 247, 234) }
            'amber' { $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 246, 224) }
            'red'   { $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(253, 232, 232) }
        }
    }
    $g.ClearSelection()
    Set-EtkVerdictGridHeight
}

function Update-EtkTargetUi {
    $t = $script:Target
    if (-not $t) { $script:lblConn.Text = 'Not connected.'; return }
    $where = $(if ($t.isLocal) { 'this server' } else { 'remote' })
    switch ($t.exchange) {
        'session' { $script:lblConn.Text = ('{0} ({1}) - Exchange {2} via remote PowerShell' -f $t.target, $where, $t.version); $script:lblConn.ForeColor = [System.Drawing.Color]::FromArgb(20, 120, 40) }
        'snapin'  { $script:lblConn.Text = ('{0} ({1}) - Exchange {2} via snap-in (fallback)' -f $t.target, $where, $t.version); $script:lblConn.ForeColor = [System.Drawing.Color]::FromArgb(170, 110, 0) }
        default   { $script:lblConn.Text = ('{0} ({1}) - Exchange cmdlets NOT available; OS checks only' -f $t.target, $where); $script:lblConn.ForeColor = [System.Drawing.Color]::FromArgb(180, 30, 30) }
    }
}

function New-EtkUiReport {
    $acts = $script:Actions.ToArray()
    $ctx = $script:Context | Select-Object *
    $ctx | Add-Member -NotePropertyName sharedAccount -NotePropertyValue ([bool]$script:Account.shared) -Force
    $ctx | Add-Member -NotePropertyName technician -NotePropertyValue $(if ($script:Technician) { $script:Technician } else { $null }) -Force
    return New-EtkReport -Sections $script:Sections -Verdict $script:Verdict -Target $script:Target -Context $ctx -Actions $acts -StartedUtc $script:startedUtc
}

function Update-EtkJsonTab {
    try {
        $r = New-EtkUiReport
        if ($script:chkJsonCompress.Checked) { $script:txtJson.Text = ConvertTo-EtkJson -Report $r -Compress }
        else { $script:txtJson.Text = Get-EtkMarkedJson -Report $r }
    } catch { $script:txtJson.Text = ('Could not build the report: {0}' -f $_.Exception.Message) }
}

function Write-EtkActionAudit {
    param($Result)
    try {
        if (-not (Test-Path -LiteralPath $script:OutputDir)) { [void](New-Item -ItemType Directory -Path $script:OutputDir -Force) }
        $file = Join-Path $script:OutputDir ('Actions_{0}.log' -f ($Result.server -replace '[^\w\.\-]', '_'))
        $who = $(if ($Result.technician) { '{0} (technician: {1})' -f $Result.by, $Result.technician } else { $Result.by })
        $line = ('{0} | {1} | {2} | {3} | {4} | {5} | {6}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $who, $Result.server, $Result.id,
            $(if ($Result.ok) { 'OK' } else { 'FAILED' }), $Result.command, (([string]$Result.output) -replace '\r?\n', ' '))
        [System.IO.File]::AppendAllText($file, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding $false))
        return $file
    } catch { Write-EtkLog ('Could not write the action log: {0}' -f $_.Exception.Message); return $null }
}

function Get-EtkActionServer {
    # Exchange actions address the Exchange server object; OS actions the
    # machine. They are normally the same name.
    $t = $script:Target
    if ($t -and $t.exchangeServer) { return [string]$t.exchangeServer }
    if ($t -and $t.target) { return ([string]$t.target).Split('.')[0] }
    return $env:COMPUTERNAME
}

function Show-EtkTechnicianDialog {
    # Asked once per session, only when the tool runs as an account that does
    # not identify a person (SYSTEM, built-in Administrator).
    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Who is running this? - Exchange Toolkit'
    $f.Size = New-Object System.Drawing.Size(560, 210)
    $f.StartPosition = 'CenterParent'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $l = New-EtkLabel ('This tool is running as {0}, which does not say who you are.' -f $script:Account.name)
    $l.Location = New-Object System.Drawing.Point(14, 14); $f.Controls.Add($l)
    $l2 = New-EtkLabel 'Your name goes into the action log next to every action you run. Asked once per session.'
    $l2.Location = New-Object System.Drawing.Point(14, 38); $f.Controls.Add($l2)
    $box = New-EtkTextBox 320 $script:Technician
    $box.Location = New-Object System.Drawing.Point(14, 70); $f.Controls.Add($box)
    $ok = New-EtkButton 'OK' 100; $ok.Location = New-Object System.Drawing.Point(318, 120); $ok.DialogResult = 'OK'
    $cancel = New-EtkButton 'Cancel' 100; $cancel.Location = New-Object System.Drawing.Point(426, 120); $cancel.DialogResult = 'Cancel'
    $f.Controls.Add($ok); $f.Controls.Add($cancel); $f.AcceptButton = $ok; $f.CancelButton = $cancel
    $res = $f.ShowDialog($script:form)
    $name = $box.Text.Trim()
    $f.Dispose()
    if ($res -ne [System.Windows.Forms.DialogResult]::OK -or -not $name) { return $null }
    return $name
}

function Confirm-EtkTechnician {
    # True when the action log will say who ran it: a named account, or a
    # shared one (SYSTEM, Administrator) with a technician name given.
    if (-not $script:Account.shared -or $script:Technician) { return $true }
    $name = Show-EtkTechnicianDialog
    if (-not $name) { Write-EtkLog 'Action cancelled: a name is needed when running as a shared account.'; return $false }
    $script:Technician = $name
    Write-EtkLog ('Actions this session are logged as {0} (technician: {1}).' -f $script:Account.name, $script:Technician)
    return $true
}

function Show-EtkConfirmDialog {
    param([string]$Title, [string]$Risk, [string]$Server, [string]$Command, [string]$Intro = '')
    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Confirm action - Exchange Toolkit'
    $f.Size = New-Object System.Drawing.Size(720, 360)
    $f.StartPosition = 'CenterParent'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $lbl = New-EtkLabel ('{0}   (risk: {1})' -f $Title, $Risk) $true 10
    $lbl.Location = New-Object System.Drawing.Point(14, 12)
    $f.Controls.Add($lbl)
    $who = $(if ($script:Technician) { '{0} (technician: {1})' -f $script:Account.name, $script:Technician } else { $script:Account.name })
    if (-not $Intro) { $Intro = 'This changes server {0}, logged as {1}. The exact command:' }
    $lbl2 = New-EtkLabel ($Intro -f $Server, $who)
    $lbl2.Location = New-Object System.Drawing.Point(14, 42)
    $f.Controls.Add($lbl2)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true; $box.ReadOnly = $true; $box.WordWrap = $true; $box.ScrollBars = 'Vertical'
    $box.Font = New-Object System.Drawing.Font('Consolas', 9); $box.BackColor = [System.Drawing.Color]::White
    $box.Location = New-Object System.Drawing.Point(14, 66); $box.Size = New-Object System.Drawing.Size(676, 110)
    $box.Text = $Command
    $f.Controls.Add($box)
    $typed = $null
    $y = 190
    if ($Risk -eq 'high') {
        $lbl3 = New-EtkLabel ('High risk and cannot be undone. Type the server name ({0}) to confirm:' -f $Server)
        $lbl3.Location = New-Object System.Drawing.Point(14, $y); $f.Controls.Add($lbl3)
        $typed = New-EtkTextBox 300
        $typed.Location = New-Object System.Drawing.Point(14, ($y + 24)); $f.Controls.Add($typed)
        $y += 60
    } else {
        $lbl3 = New-EtkLabel 'Nothing else will run afterwards. Re-run the tab to see the effect.'
        $lbl3.Location = New-Object System.Drawing.Point(14, $y); $f.Controls.Add($lbl3)
        $y += 40
    }
    $ok = New-EtkButton 'Run it' 120
    $ok.Location = New-Object System.Drawing.Point(450, ($y + 10)); $ok.DialogResult = 'OK'
    $cancel = New-EtkButton 'Cancel' 120
    $cancel.Location = New-Object System.Drawing.Point(576, ($y + 10)); $cancel.DialogResult = 'Cancel'
    $f.Controls.Add($ok); $f.Controls.Add($cancel)
    $f.AcceptButton = $cancel; $f.CancelButton = $cancel   # Enter does NOT run it
    $res = $f.ShowDialog($script:form)
    $out = [pscustomobject]@{ ok = ($res -eq [System.Windows.Forms.DialogResult]::OK); typed = $(if ($typed) { $typed.Text } else { '' }) }
    $f.Dispose()
    return $out
}

function Invoke-EtkUiAction {
    param($Ref)
    if ($script:busy) { return }
    $cat = Get-EtkActionCatalog
    if (-not $cat.Contains([string]$Ref.id)) { Write-EtkLog ('Unknown action {0}.' -f $Ref.id); return }
    $def = $cat[[string]$Ref.id]
    $server = Get-EtkActionServer
    $cmd = Get-EtkActionCommand -Id $Ref.id -Arguments $Ref.args -Server $server
    if ($def.where -eq 'exchange' -and -not ($script:Target -and $script:Target.exchange -ne 'none')) {
        [void][System.Windows.Forms.MessageBox]::Show('Connect to Exchange first - this action uses the Exchange cmdlets.', 'Exchange Toolkit', 'OK', 'Information')
        return
    }
    if (-not (Confirm-EtkTechnician)) { return }
    $c = Show-EtkConfirmDialog -Title $(if ($Ref.label) { $Ref.label } else { $def.title }) -Risk $def.risk -Server $server -Command $cmd
    if (-not $c.ok) { Write-EtkLog 'Action cancelled.'; return }
    $opt = Get-EtkUiOptions
    if (-not $opt) { return }
    if ($opt.ConnectFirst -and $script:connectedTo) {
        # The box names a different server from the one the rows came from.
        # Running the action now would aim it at a server nobody looked at.
        [void][System.Windows.Forms.MessageBox]::Show(('The server box now says "{0}", but these results are from "{1}". Connect and re-run the tab first.' -f $opt.Server, $script:connectedTo), 'Exchange Toolkit', 'OK', 'Warning')
        return
    }
    $opt.Id = [string]$Ref.id
    $opt.Arguments = (ConvertTo-EtkHashtable $Ref.args)
    $opt.Token = New-EtkConfirmToken -Id $Ref.id -Server $server
    $opt.Typed = $c.typed
    $opt.ActionServer = $server
    $opt.Technician = $script:Technician
    Write-EtkLog ('Running action on {0}: {1}' -f $server, $cmd)
    Start-EtkJob -Job 'action' -Opt $opt
}

function Show-EtkRowActions {
    param($Grid, [System.Drawing.Point]$At)
    $row = $null
    if ($Grid.SelectedRows.Count -gt 0) { $row = $Grid.SelectedRows[0].Tag }
    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $acts = @(); if ($row) { $acts = @($row.actions | Where-Object { $_ }) }
    if ($acts.Count -eq 0) {
        $it = $menu.Items.Add('No action for this row (rows with a dot in the Act column have one)')
        $it.Enabled = $false
    }
    $server = Get-EtkActionServer
    foreach ($a in $acts) {
        $label = $(if ($a.label) { [string]$a.label } else { (Get-EtkActionCatalog)[[string]$a.id].title })
        $run = $menu.Items.Add(('{0}...' -f $label))
        $run.Tag = $a
        $run.Add_Click({ Invoke-EtkUiAction -Ref $this.Tag })
        $copy = $menu.Items.Add(('Copy command: {0}' -f $label))
        $copy.Tag = (Get-EtkActionCommand -Id $a.id -Arguments $a.args -Server $server)
        $copy.Add_Click({ try { [System.Windows.Forms.Clipboard]::SetText([string]$this.Tag); Write-EtkLog 'Command copied to the clipboard.' } catch { } })
    }
    if ($row) {
        [void]$menu.Items.Add('-')
        $cr = $menu.Items.Add('Copy row text')
        $cr.Tag = ('{0} | {1} | {2} | {3}' -f $row.group, $row.check, $row.result, $row.detail)
        $cr.Add_Click({ try { [System.Windows.Forms.Clipboard]::SetText([string]$this.Tag) } catch { } })
    }
    $menu.Show($Grid, $At)
}

function Add-EtkGridMenu {
    param($Grid)
    $Grid.Add_CellMouseDown({
        param($s, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $e.RowIndex -ge 0) {
            $s.ClearSelection(); $s.Rows[$e.RowIndex].Selected = $true
            $pt = $s.PointToClient([System.Windows.Forms.Cursor]::Position)
            Show-EtkRowActions -Grid $s -At $pt
        }
    })
}

# ---------------------------------------------------------------------------
#  Fix tab
# ---------------------------------------------------------------------------
function Get-EtkServiceImpact {
    # What stopping (or restarting) a service does to users, for the
    # confirmation dialog. Only the ones whose impact is not obvious.
    param([string]$Name)
    switch -Regex ($Name) {
        '^MSExchangeIS$'                 { return 'every mailbox database dismounts; Outlook and OWA lose their mailboxes' }
        '^MSExchangeTransport$'          { return 'mail stops flowing in and out until it is running again' }
        '^MSExchangeFrontEndTransport$'  { return 'inbound SMTP from the internet stops' }
        '^MSExchangeADTopology$'         { return 'nearly every other Exchange service depends on it and stops with it' }
        '^(W3SVC|WAS|IISADMIN)$'         { return 'OWA, ActiveSync, Outlook (MAPI/HTTP) and EWS go down' }
        '^MSExchangeRepl$'               { return 'database copies and backups stop' }
        '^WinRM$'                        { return 'remote PowerShell (and this tool from a workstation) stops working' }
    }
    return ''
}

function New-EtkServiceGrid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'; $g.ReadOnly = $true; $g.AllowUserToAddRows = $false; $g.AllowUserToDeleteRows = $false; $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false; $g.SelectionMode = 'FullRowSelect'; $g.MultiSelect = $false; $g.AutoSizeColumnsMode = 'Fill'
    $g.BorderStyle = 'None'; $g.BackgroundColor = [System.Drawing.Color]::White
    $g.DefaultCellStyle.BackColor = [System.Drawing.Color]::White; $g.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
    $g.EnableHeadersVisualStyles = $false
    $g.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $g.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $g.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(214, 228, 245)
    $g.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Black
    foreach ($c in @(@{ n = 'name'; h = 'Service'; w = 26 }, @{ n = 'display'; h = 'Display name'; w = 44 }, @{ n = 'state'; h = 'Status'; w = 14 }, @{ n = 'mode'; h = 'Start mode'; w = 14 })) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $c.n; $col.HeaderText = $c.h; $col.FillWeight = $c.w
        [void]$g.Columns.Add($col)
    }
    return $g
}

function Update-EtkServiceGrid {
    param($Services)
    $g = $script:gridServices
    $g.Rows.Clear()
    $list = @($Services | Where-Object { $_ })
    $bad = 0
    foreach ($s in $list) {
        $i = $g.Rows.Add(@($s.name, $s.displayName, $s.state, $s.startMode))
        $r = $g.Rows[$i]; $r.Tag = $s
        if ($s.startMode -eq 'Auto' -and $s.state -ne 'Running') { $bad++; $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(253, 232, 232) }
        elseif ($s.state -eq 'Running') { $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(233, 247, 234) }
    }
    $g.ClearSelection()
    if ($list.Count -eq 0) { $script:lblSvcState.Text = ('{0}: no Exchange or IIS services found.' -f (Get-Date).ToString('HH:mm:ss')) }
    else { $script:lblSvcState.Text = ('{0}: {1} services, {2} automatic but not running.' -f (Get-Date).ToString('HH:mm:ss'), $list.Count, $bad) }
    $script:svcLoaded = $true
}

function Invoke-EtkServiceAction {
    param([string]$Id, [string]$Verb)
    if ($script:gridServices.SelectedRows.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('Select a service in the list first.', 'Exchange Toolkit', 'OK', 'Information')
        return
    }
    $s = $script:gridServices.SelectedRows[0].Tag
    $label = ('{0} {1}' -f $Verb, $s.name)
    $impact = $(if ($Id -ne 'svc-start') { Get-EtkServiceImpact $s.name } else { '' })
    if ($impact) { $label = ('{0} - {1}' -f $label, $impact) }
    Invoke-EtkUiAction -Ref (New-EtkActionRef -Id $Id -Arguments @{ Name = [string]$s.name } -Label $label)
}

function Start-EtkServiceRefresh {
    $o = Get-EtkUiOptions
    if ($o) { Start-EtkJob -Job 'services' -Opt $o }
}

function Invoke-EtkUiHealthChecker {
    if ($script:busy) { return }
    $opt = Get-EtkUiOptions
    if (-not $opt) { return }
    $title = 'Microsoft CSS-Exchange HealthChecker'
    if (-not (Test-EtkIsLocalTarget $opt.Server)) {
        [void][System.Windows.Forms.MessageBox]::Show(('HealthChecker runs on the Exchange server itself. Run this tool on {0} and use the button there.' -f $opt.Server), $title, 'OK', 'Information'); return
    }
    if (-not $script:Context.exchangeInstalled) {
        [void][System.Windows.Forms.MessageBox]::Show('Exchange is not installed on this machine, and HealthChecker needs the Exchange Management Shell. Run this tool on the Exchange server.', $title, 'OK', 'Information'); return
    }
    if (-not $script:Context.elevated) {
        [void][System.Windows.Forms.MessageBox]::Show('HealthChecker needs an elevated session. Press "Restart as administrator" first.', $title, 'OK', 'Information'); return
    }
    if (-not (Confirm-EtkTechnician)) { return }
    $server = $env:COMPUTERNAME
    $folder = Join-Path $script:OutputDir ('HealthChecker_{0}_{1}' -f $server, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $nl = [Environment]::NewLine
    $cmd = ('1. Download {0}{1}   to {2}\HealthChecker.ps1{1}2. Run it only if Windows reports a Valid signature from Microsoft Corporation{1}3. In a new window: load the Exchange Management Shell{4}, then{1}   HealthChecker.ps1 -OutputFilePath "{2}" -SkipVersionCheck{1}   HealthChecker.ps1 -BuildHtmlServersReport -XMLDirectoryPath "{2}" -SkipVersionCheck{1}{1}HealthChecker reads; it changes nothing. It takes a few minutes. {3}' -f `
        (Get-EtkHealthCheckerUrl), $nl, $folder, 'The window stays open when it finishes.', $(if ($script:Context.isSystem) { ' (snap-in, as SYSTEM)' } else { '' }))
    $c = Show-EtkConfirmDialog -Title $title -Risk 'low' -Server $server -Command $cmd -Intro 'Downloads and runs Microsoft''s checker on {0}, logged as {1}. What happens:'
    if (-not $c.ok) { Write-EtkLog 'HealthChecker cancelled.'; return }
    $opt.ConnectFirst = $false     # HealthChecker loads Exchange itself
    $opt.Folder = $folder
    $script:pendingHc = @{ server = $server; folder = $folder; startedUtc = [datetime]::UtcNow }
    Write-EtkLog ('Downloading HealthChecker to {0}' -f $folder)
    Start-EtkJob -Job 'healthchecker' -Opt $opt
}

function Complete-EtkHealthChecker {
    # Called when the download job ends: launch the window, log the action.
    param($Download, [string]$ErrorText)
    $p = $script:pendingHc
    if (-not $p) { return }
    $script:pendingHc = $null
    $res = [pscustomobject]@{ id = 'css-healthchecker'; server = $p.server; command = ('HealthChecker.ps1 from {0}' -f (Get-EtkHealthCheckerUrl)); ok = $false; output = ''
        startedUtc = (ConvertTo-EtkIso8601 $p.startedUtc); by = [string]$script:Account.name; technician = $script:Technician }
    if ($Download) {
        try {
            $bin = Join-Path $script:Context.exchangeInstallPath 'bin'
            $hc = Get-EtkHealthCheckerCommand -ScriptPath $Download.path -OutDir $Download.folder -ExchangeBin $bin -Server $p.server -AsSystem ([bool]$script:Context.isSystem)
            $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $argLine = '-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand ' + (ConvertTo-EtkEncodedCommand $hc.text)
            Start-Process -FilePath $psExe -ArgumentList $argLine -WorkingDirectory $Download.folder
            $script:lastHealthChecker = [string]$Download.folder
            $res.ok = $true
            $res.output = ('HealthChecker {0} downloaded and signature-checked ({1}); running in a new window. Results and HTML in {2}' -f $(if ($Download.version) { $Download.version } else { '(version not read)' }), $Download.signer, $Download.folder)
            Write-EtkLog $res.output
        } catch { $res.output = ('Downloaded, but the window could not be started: {0}' -f $_.Exception.Message) }
    } else {
        $res.output = $(if ($ErrorText) { ($ErrorText -split "`n")[0].Trim() } else { 'The download did not complete.' })
    }
    $script:Actions.Add($res)
    $file = Write-EtkActionAudit -Result $res
    if ($file) { Write-EtkLog ('Logged to {0}' -f $file) }
    if (-not $res.ok) { [void][System.Windows.Forms.MessageBox]::Show(('HealthChecker did not run: {0}' -f $res.output), 'Exchange Toolkit', 'OK', 'Warning') }
}

# ---------------------------------------------------------------------------
#  Security tab: public addresses, and the opt-in location lookup
# ---------------------------------------------------------------------------
function Get-EtkUiPublicIps {
    # Ordered: address -> where it was seen.
    $out = [ordered]@{}
    foreach ($src in @(@{ k = 'failedLogins'; n = 'failed logins' }, @{ k = 'logons'; n = 'logons' })) {
        $s = $script:Sections[$src.k]
        if (-not $s -or -not $s.data) { continue }
        foreach ($ip in @($s.data.publicIps | Where-Object { $_ })) {
            $ip = [string]$ip
            if ($out.Contains($ip)) { if ($out[$ip] -notmatch $src.n) { $out[$ip] = $out[$ip] + ', ' + $src.n } }
            else { $out[$ip] = $src.n }
        }
    }
    return $out
}

function Invoke-EtkUiIpLookup {
    if ($script:busy) { return }
    $ips = Get-EtkUiPublicIps
    if ($ips.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('There are no public addresses in the Security results. Run the Security checks first.', 'Exchange Toolkit', 'OK', 'Information')
        return
    }
    if (-not (Confirm-EtkTechnician)) { return }
    $nl = [Environment]::NewLine
    $list = @($ips.Keys)
    $shown = @($list | Select-Object -First 50 | ForEach-Object { '  {0,-40} ({1})' -f $_, $ips[$_] })
    $more = $(if ($list.Count -gt 50) { ('{0}  ...and {1} more, which are NOT sent (50 per run).' -f $nl, ($list.Count - 50)) } else { '' })
    $text = ('Sends these {0} public IP address(es) to ipapi.co, a third-party location service - one HTTPS request each, from this PC ({1}):{2}{2}{3}{4}{2}{2}A logon address may be the client''s own or a technician''s. Nothing else is sent. The answers are estimates, often right only to the country.' -f `
        [math]::Min(50, $list.Count), $env:COMPUTERNAME, $nl, ($shown -join $nl), $more)
    $c = Show-EtkConfirmDialog -Title 'Look up IP locations (third party)' -Risk 'low' -Server $env:COMPUTERNAME -Command $text -Intro 'Sends data to a third party, logged as {1}. Exactly what is sent, and where:'
    if (-not $c.ok) { Write-EtkLog 'IP lookup cancelled. Nothing was sent.'; return }
    $opt = Get-EtkUiOptions
    if (-not $opt) { return }
    $opt.ConnectFirst = $false
    $opt.Ips = [string[]]$list
    $script:pendingLookup = @{ startedUtc = [datetime]::UtcNow; count = [math]::Min(50, $list.Count) }
    Write-EtkLog ('Looking up {0} address(es) at ipapi.co...' -f $script:pendingLookup.count)
    Start-EtkJob -Job 'iplookup' -Opt $opt
}

function Complete-EtkIpLookup {
    param($Result, [string]$ErrorText)
    $p = $script:pendingLookup
    if (-not $p) { return }
    $script:pendingLookup = $null
    $res = [pscustomobject]@{ id = 'ip-lookup'; server = $env:COMPUTERNAME; command = 'https://ipapi.co/<ip>/json/ for each public address'; ok = $false; output = ''
        startedUtc = (ConvertTo-EtkIso8601 $p.startedUtc); by = [string]$script:Account.name; technician = $script:Technician }
    if ($Result) {
        $res.ok = $true
        $res.output = ('Sent {0} public address(es) to ipapi.co.{1}' -f $Result.sent, $(if ($Result.stopped) { ' ' + $Result.stopped } else { '' }))
    } else {
        $res.output = ('The lookup did not complete: {0}' -f $(if ($ErrorText) { ($ErrorText -split "`n")[0].Trim() } else { 'unknown error' }))
    }
    $script:Actions.Add($res)
    $file = Write-EtkActionAudit -Result $res
    Write-EtkLog $res.output
    if ($file) { Write-EtkLog ('Logged to {0}' -f $file) }
}

function New-EtkTabPage {
    param([string]$Title)
    $tp = New-Object System.Windows.Forms.TabPage
    $tp.Text = $Title
    $tp.BackColor = [System.Drawing.Color]::White
    return $tp
}

function New-EtkCheckTab {
    # A check tab: toolbar (Run, Actions) above a result grid.
    param([string]$Title, [string]$Job, [string]$RunText, [string]$Tip)
    $tp = New-EtkTabPage $Title
    $tp.Tag = $(switch ($Job) { 'health' { 'health' } 'mailflow' { 'mailflow' } 'storage' { 'storage' } 'security' { 'security' } default { $null } })
    $grid = New-EtkResultGrid
    Add-EtkGridMenu $grid
    $bar = New-EtkToolbar
    $run = New-EtkButton $RunText 170 30 $Tip
    $run.Tag = $Job
    $run.Add_Click({ Start-EtkJob -Job ([string]$this.Tag) -Opt (Get-EtkUiOptions) })
    $act = New-EtkButton 'Actions for selected row...' 190 30 'Offers the actions that fit the selected row. Nothing runs without a confirmation.'
    $act.Tag = $grid
    $act.Add_Click({ Show-EtkRowActions -Grid $this.Tag -At (New-Object System.Drawing.Point(20, 20)) })
    $bar.Controls.Add($run); $bar.Controls.Add($act)
    $tp.Controls.Add($grid)
    $tp.Controls.Add($bar)
    $script:runButtons += $run
    return @{ page = $tp; grid = $grid; bar = $bar }
}

# ---------------------------------------------------------------------------
#  Form
# ---------------------------------------------------------------------------
$script:runButtons = @()
$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = ('Exchange Toolkit {0}' -f (Get-EtkVersion))
$script:form.Size = New-Object System.Drawing.Size(1280, 900)
$script:form.MinimumSize = New-Object System.Drawing.Size(1280, 700)   # the right-anchored badge would overlap the progress bar below this
$script:form.StartPosition = 'CenterScreen'
$script:form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$root = New-Object System.Windows.Forms.TableLayoutPanel
$root.Dock = 'Fill'; $root.ColumnCount = 1; $root.RowCount = 3
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 112)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 140)))
$script:form.Controls.Add($root)

# --- Target bar ---
$grpTarget = New-Object System.Windows.Forms.GroupBox
$grpTarget.Text = 'Target (Exchange Server)'; $grpTarget.Dock = 'Fill'
$root.Controls.Add($grpTarget, 0, 0)

$script:txtServer = New-EtkTextBox 200 $env:COMPUTERNAME
$script:txtServer.Location = New-Object System.Drawing.Point(14, 22); $grpTarget.Controls.Add($script:txtServer)
$script:tips.SetToolTip($script:txtServer, 'This computer by default. Another name runs the OS checks through Invoke-Command (WinRM) and the Exchange checks through http://<server>/PowerShell.')
$script:btnConnect = New-EtkButton 'Connect' 90 28 'Opens the Exchange PowerShell session for this server.'
$script:btnConnect.Location = New-Object System.Drawing.Point(222, 20); $grpTarget.Controls.Add($script:btnConnect)
$script:chkSnapin = New-Object System.Windows.Forms.CheckBox
$script:chkSnapin.Text = 'Allow snap-in fallback'; $script:chkSnapin.AutoSize = $true; $script:chkSnapin.Checked = $true
$script:chkSnapin.Location = New-Object System.Drawing.Point(322, 25); $grpTarget.Controls.Add($script:chkSnapin)
$script:tips.SetToolTip($script:chkSnapin, 'On the Exchange server only: if remote PowerShell fails, load the management snap-in instead (unsupported for changes, fine for reading).')
$script:lblConn = New-EtkLabel 'Not connected.'
$script:lblConn.Location = New-Object System.Drawing.Point(486, 26); $grpTarget.Controls.Add($script:lblConn)

$lblLookBack = New-EtkLabel 'Look back (h):'
$script:numHours = New-Object System.Windows.Forms.NumericUpDown
$script:numHours.Minimum = 1; $script:numHours.Maximum = 720; $script:numHours.Value = 24; $script:numHours.Width = 56
$script:tips.SetToolTip($script:numHours, 'How far back the event-signal checks look.')
$lblTracking = New-EtkLabel 'Tracking (h):'
$script:numTrack = New-Object System.Windows.Forms.NumericUpDown
$script:numTrack.Minimum = 1; $script:numTrack.Maximum = 48; $script:numTrack.Value = 2; $script:numTrack.Width = 48
$script:tips.SetToolTip($script:numTrack, 'Message-tracking window for the Throughput check.')
$lblBusy = New-EtkLabel 'Busy window:'
$script:txtWinStart = New-EtkTextBox 46 '05:00'
$lblTo = New-EtkLabel 'to'
$script:txtWinEnd = New-EtkTextBox 46 '09:00'
$script:tips.SetToolTip($script:txtWinStart, 'When users report the problem. Scheduled tasks and snapshots inside this window are flagged.')
$script:btnRunAll = New-EtkButton 'Run all checks' 104 28 'Runs every check tab. Never runs an action.'
$script:btnCancel = New-EtkButton 'Cancel' 64 28
$script:btnCancel.Enabled = $false
$script:progress = New-Object System.Windows.Forms.ProgressBar
$script:progress.Size = New-Object System.Drawing.Size(150, 20)
$script:lblStatus = New-EtkLabel 'Ready.'
$script:lblStatus.MaximumSize = New-Object System.Drawing.Size(130, 18)   # never runs under the badge

# Second row laid out left to right from each control's real width, so a
# label is followed by its field with no dead space (fixed positions left a
# gap after "Look back (h):" sized for the old, longer first-row label).
# Gap after a label is small (it belongs to the next field); between
# groups it is larger. Labels sit 4 px lower than the fields to line up.
$x = 12
foreach ($item in @(
    @{ c = $lblLookBack;        gap = 3 }, @{ c = $script:numHours;  gap = 14 },
    @{ c = $lblTracking;        gap = 3 }, @{ c = $script:numTrack;  gap = 14 },
    @{ c = $lblBusy;            gap = 3 }, @{ c = $script:txtWinStart; gap = 4 },
    @{ c = $lblTo;              gap = 4 }, @{ c = $script:txtWinEnd; gap = 18 },
    @{ c = $script:btnRunAll;   gap = 6 }, @{ c = $script:btnCancel; gap = 12 },
    @{ c = $script:progress;    gap = 8 }, @{ c = $script:lblStatus; gap = 0 }
)) {
    $c = $item.c
    $y = 58
    if ($c -is [System.Windows.Forms.Label]) { $y = 62 }
    elseif ($c -is [System.Windows.Forms.Button]) { $y = 56 }
    elseif ($c -is [System.Windows.Forms.ProgressBar]) { $y = 60 }
    $c.Location = New-Object System.Drawing.Point($x, $y)
    $grpTarget.Controls.Add($c)
    $w = $(if ($c -is [System.Windows.Forms.Label]) { $c.PreferredWidth } else { $c.Width })
    $x += $w + $item.gap
}
$script:btnElevate = New-EtkButton 'Restart as administrator' 170 28 'VSS, shadow copies, the Security log and IIS need an elevated session.'
$script:btnElevate.Location = New-Object System.Drawing.Point(1080, 20); $script:btnElevate.Anchor = 'Top,Right'
$script:btnElevate.Visible = (-not $script:Context.elevated)
$grpTarget.Controls.Add($script:btnElevate)
# Overall indicator, visible from every tab. Colour = worst MEASURED area;
# the tooltip carries the counts. Deliberately not a 0-100 score.
$script:lblBadge = New-Object System.Windows.Forms.Label
$script:lblBadge.UseMnemonic = $false
$script:lblBadge.AutoSize = $false
$script:lblBadge.Size = New-Object System.Drawing.Size(170, 28)
$script:lblBadge.Location = New-Object System.Drawing.Point(1080, 56)
$script:lblBadge.Anchor = 'Top,Right'
$script:lblBadge.TextAlign = 'MiddleCenter'
$script:lblBadge.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$script:lblBadge.ForeColor = [System.Drawing.Color]::White
$script:lblBadge.BackColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$script:lblBadge.Text = 'NOT RUN'
$script:tips.SetToolTip($script:lblBadge, 'Overall result of the last checks. Click to open the Overview.')
$script:lblBadge.Cursor = [System.Windows.Forms.Cursors]::Hand
$grpTarget.Controls.Add($script:lblBadge)
$script:runButtons += $script:btnRunAll
$script:runButtons += $script:btnConnect

# --- Tabs ---
$script:tabs = New-Object System.Windows.Forms.TabControl
$script:tabs.Dock = 'Fill'
$root.Controls.Add($script:tabs, 0, 1)
# Owner-drawn headers so each check tab can carry its worst result's colour.
$script:TabStatus = @{}
$script:tabs.DrawMode = 'OwnerDrawFixed'
$script:tabs.SizeMode = 'Fixed'
$script:tabs.ItemSize = New-Object System.Drawing.Size(132, 26)
$script:tabs.Add_DrawItem({
    param($s, $e)
    try {
        $tp = $s.TabPages[$e.Index]
        $key = [string]$tp.Tag
        $st = $(if ($key -and $script:TabStatus.ContainsKey($key)) { [string]$script:TabStatus[$key] } else { 'none' })
        $c = Get-EtkStatusColours $st
        $selected = ($e.Index -eq $s.SelectedIndex)
        $back = $(if ($selected -and $st -eq 'none') { [System.Drawing.Color]::White } else { $c.back })
        $br = New-Object System.Drawing.SolidBrush($back)
        $e.Graphics.FillRectangle($br, $e.Bounds); $br.Dispose()
        $style = $(if ($selected) { [System.Drawing.FontStyle]::Bold } else { [System.Drawing.FontStyle]::Regular })
        $f = New-Object System.Drawing.Font('Segoe UI', 9, $style)
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $tp.Text, $f, $e.Bounds, $c.fore,
            ([System.Windows.Forms.TextFormatFlags]::HorizontalCenter -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter -bor [System.Windows.Forms.TextFormatFlags]::NoPrefix))
        $f.Dispose()
    } catch { }
})

# Overview
$tpOverview = New-EtkTabPage 'Overview'
$tpOverview.Tag = 'overview'
$ov = New-Object System.Windows.Forms.TableLayoutPanel
$ov.Dock = 'Fill'; $ov.ColumnCount = 1; $ov.RowCount = 3
[void]$ov.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 62)))
# Placeholder height; Set-EtkVerdictGridHeight fits it to the rows, so the
# results grid below starts right under the last area instead of after a gap.
[void]$ov.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 200)))
$script:ovLayout = $ov
[void]$ov.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
$head = New-Object System.Windows.Forms.Panel; $head.Dock = 'Fill'
$script:lblOverall = New-EtkLabel 'NOT MEASURED' $true 14
$script:lblOverall.Location = New-Object System.Drawing.Point(8, 6); $head.Controls.Add($script:lblOverall)
$script:lblHeadline = New-EtkLabel 'Press Run all checks, or run one tab at a time.'
$script:lblHeadline.Location = New-Object System.Drawing.Point(10, 40); $head.Controls.Add($script:lblHeadline)
$script:lblCounts = New-EtkLabel ''
$script:lblCounts.Location = New-Object System.Drawing.Point(260, 14); $head.Controls.Add($script:lblCounts)
$ov.Controls.Add($head, 0, 0)
$script:gridVerdict = New-Object System.Windows.Forms.DataGridView
$script:gridVerdict.Dock = 'Fill'; $script:gridVerdict.ReadOnly = $true; $script:gridVerdict.AllowUserToAddRows = $false
$script:gridVerdict.RowHeadersVisible = $false; $script:gridVerdict.AutoSizeColumnsMode = 'Fill'; $script:gridVerdict.SelectionMode = 'FullRowSelect'
$script:gridVerdict.BackgroundColor = [System.Drawing.Color]::White; $script:gridVerdict.BorderStyle = 'None'
$script:gridVerdict.DefaultCellStyle.BackColor = [System.Drawing.Color]::White; $script:gridVerdict.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
$script:gridVerdict.EnableHeadersVisualStyles = $false
$script:gridVerdict.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$script:gridVerdict.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:gridVerdict.ScrollBars = 'None'          # sized to its rows by Set-EtkVerdictGridHeight
$script:gridVerdict.AllowUserToResizeRows = $false
$script:gridVerdict.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(214, 228, 245)
$script:gridVerdict.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Black
foreach ($c in @(@{ n = 'area'; h = 'Area'; w = 18 }, @{ n = 'state'; h = 'State'; w = 9 }, @{ n = 'found'; h = 'First thing found'; w = 50 }, @{ n = 'count'; h = 'Count'; w = 23 })) {
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.Name = $c.n; $col.HeaderText = $c.h; $col.FillWeight = $c.w
    [void]$script:gridVerdict.Columns.Add($col)
}
$ov.Controls.Add($script:gridVerdict, 0, 1)
$script:gridOverview = New-EtkResultGrid
Add-EtkGridMenu $script:gridOverview
$ov.Controls.Add($script:gridOverview, 0, 2)
$tpOverview.Controls.Add($ov)
[void]$script:tabs.TabPages.Add($tpOverview)

$t = New-EtkCheckTab -Title 'Health' -Job 'health' -RunText 'Run Health checks' -Tip 'Services, components, databases, certificates, disks, memory, event signals, disk latency (10 s).'
$script:gridHealth = $t.grid; [void]$script:tabs.TabPages.Add($t.page)
$t = New-EtkCheckTab -Title 'Mail flow' -Job 'mailflow' -RunText 'Run Mail flow checks' -Tip 'Queues, back pressure, message-tracking throughput and latency, transport settings, connectors.'
$script:gridMail = $t.grid; [void]$script:tabs.TabPages.Add($t.page)
$t = New-EtkCheckTab -Title 'Storage & backup' -Job 'storage' -RunText 'Run Storage checks' -Tip 'Exchange backups, VSS writers, shadow copies, filter drivers, backup software, CrashPlan, the schedule timeline.'
$script:gridStorage = $t.grid; [void]$script:tabs.TabPages.Add($t.page)
$t = New-EtkCheckTab -Title 'Security' -Job 'security' -RunText 'Run Security checks' -Tip 'Failed logins by source address (SMTP AUTH, Windows, IIS), interactive and RDP logons, and what this server''s firewall lets in. Read-only; nothing is sent anywhere.'
$script:gridSecurity = $t.grid; [void]$script:tabs.TabPages.Add($t.page)
$script:btnCopyIps = New-EtkButton 'Copy public IPs' 130 30 'Copies the public addresses from Failed logins and Logons, one per line - for the router or a lookup of your own.'
$script:btnIpLookup = New-EtkButton 'Look up locations...' 150 30 'Optional. Sends the public addresses to ipapi.co (a third party) for a country/ISP estimate - only after you confirm the list.'
$t.bar.Controls.AddRange(@($script:btnCopyIps, $script:btnIpLookup))
$script:runButtons += $script:btnIpLookup
$script:pendingLookup = $null

# Fix: remediation that is always reachable, not only from a flagged row.
# Every button goes through the same confirm / technician / audit path as the
# row actions.
$script:svcLoaded = $false
$script:pendingHc = $null
$script:lastHealthChecker = ''
$script:refreshServices = $false
$script:tpFix = New-EtkTabPage 'Fix'
$grpSvc = New-Object System.Windows.Forms.GroupBox
$grpSvc.Text = 'Exchange and IIS services'; $grpSvc.Dock = 'Fill'
$svcBar = New-EtkToolbar
$script:btnSvcRefresh = New-EtkButton 'Refresh' 90 30 'Reads the service list again. Read-only.'
$script:btnSvcStart = New-EtkButton 'Start...' 90 30 'Starts the selected service. Low risk.'
$script:btnSvcStop = New-EtkButton 'Stop...' 90 30 'Stops the selected service (and anything that depends on it). High risk: asks for the server name.'
$script:btnSvcRestart = New-EtkButton 'Restart...' 90 30 'Restarts the selected service, or starts it if it is stopped.'
$script:lblSvcState = New-EtkLabel 'Not read yet.'
$script:lblSvcState.Padding = New-Object System.Windows.Forms.Padding(8, 8, 0, 0)
$svcBar.Controls.AddRange(@($script:btnSvcRefresh, $script:btnSvcStart, $script:btnSvcStop, $script:btnSvcRestart, $script:lblSvcState))
$script:gridServices = New-EtkServiceGrid
$grpSvc.Controls.Add($script:gridServices)
$grpSvc.Controls.Add($svcBar)

$fixRight = New-Object System.Windows.Forms.Panel
$fixRight.Dock = 'Right'; $fixRight.Width = 390
$grpQuick = New-Object System.Windows.Forms.GroupBox
$grpQuick.Text = 'Quick fixes'; $grpQuick.Dock = 'Top'; $grpQuick.Height = 236
$y = 22
foreach ($q in @(
    @{ v = 'btnStartAuto'; t = 'Start stopped automatic services...'; n = 'The usual fix after a reboot that left Exchange half up. AD Topology first.' }
    @{ v = 'btnRecycleAll'; t = 'Recycle Exchange app pools...'; n = 'Gentler than an IIS reset: each MSExchange pool restarts in turn.' }
    @{ v = 'btnIisReset'; t = 'IIS reset...'; n = 'OWA, ActiveSync, Outlook and EWS drop for about a minute.' }
)) {
    $b = New-EtkButton $q.t 250 30
    $b.Location = New-Object System.Drawing.Point(12, $y); $grpQuick.Controls.Add($b)
    $n = New-EtkLabel $q.n
    $n.MaximumSize = New-Object System.Drawing.Size(360, 0)
    $n.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
    $n.Location = New-Object System.Drawing.Point(14, ($y + 33)); $grpQuick.Controls.Add($n)
    Set-Variable -Scope Script -Name $q.v -Value $b
    $y += 70
}
$grpCss = New-Object System.Windows.Forms.GroupBox
$grpCss.Text = 'Microsoft CSS-Exchange'; $grpCss.Dock = 'Fill'
$script:btnHealthChecker = New-EtkButton 'Run HealthChecker...' 170 30 'Downloads the latest signed HealthChecker.ps1 from github.com/microsoft/CSS-Exchange and runs it in its own window.'
$script:btnHealthChecker.Location = New-Object System.Drawing.Point(12, 22); $grpCss.Controls.Add($script:btnHealthChecker)
$script:btnHcOpen = New-EtkButton 'Open results folder' 150 30
$script:btnHcOpen.Location = New-Object System.Drawing.Point(188, 22); $grpCss.Controls.Add($script:btnHcOpen)
$n = New-EtkLabel 'Downloaded fresh from the official GitHub release each time, and run only if Windows reports a valid Microsoft signature. Runs on the Exchange server itself, elevated. Writes its text, XML and HTML report to Output\HealthChecker_<server>_<time>\.'
$n.MaximumSize = New-Object System.Drawing.Size(360, 0)
$n.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
$n.Location = New-Object System.Drawing.Point(14, 60); $grpCss.Controls.Add($n)
$fixRight.Controls.Add($grpCss)
$fixRight.Controls.Add($grpQuick)

$script:tpFix.Controls.Add($grpSvc)
$script:tpFix.Controls.Add($fixRight)
[void]$script:tabs.TabPages.Add($script:tpFix)
$script:runButtons += @($script:btnSvcRefresh, $script:btnSvcStart, $script:btnSvcStop, $script:btnSvcRestart, $script:btnStartAuto, $script:btnRecycleAll, $script:btnIisReset, $script:btnHealthChecker)

# Evidence
$tpEv = New-EtkTabPage 'Evidence'
$evTop = New-Object System.Windows.Forms.Panel; $evTop.Dock = 'Top'; $evTop.Height = 150
$l = New-EtkLabel 'Export everything logged in a time window - for example the hour users complained about. Read-only.' $true
$l.Location = New-Object System.Drawing.Point(10, 10); $evTop.Controls.Add($l)
$l = New-EtkLabel 'From:'; $l.Location = New-Object System.Drawing.Point(10, 44); $evTop.Controls.Add($l)
$script:dtFrom = New-Object System.Windows.Forms.DateTimePicker
$script:dtFrom.Format = 'Custom'; $script:dtFrom.CustomFormat = 'yyyy-MM-dd HH:mm'; $script:dtFrom.Width = 150
$script:dtFrom.Location = New-Object System.Drawing.Point(54, 40); $evTop.Controls.Add($script:dtFrom)
$l = New-EtkLabel 'To:'; $l.Location = New-Object System.Drawing.Point(214, 44); $evTop.Controls.Add($l)
$script:dtTo = New-Object System.Windows.Forms.DateTimePicker
$script:dtTo.Format = 'Custom'; $script:dtTo.CustomFormat = 'yyyy-MM-dd HH:mm'; $script:dtTo.Width = 150
$script:dtTo.Location = New-Object System.Drawing.Point(240, 40); $evTop.Controls.Add($script:dtTo)
$now = Get-Date
$script:dtTo.Value = $now
$script:dtFrom.Value = $now.AddHours(-2)
$script:chkEvEvents = New-Object System.Windows.Forms.CheckBox; $script:chkEvEvents.Text = 'Events + timeline'; $script:chkEvEvents.Checked = $true; $script:chkEvEvents.AutoSize = $true
$script:chkEvEvents.Location = New-Object System.Drawing.Point(10, 74); $evTop.Controls.Add($script:chkEvEvents)
$script:chkEvTracking = New-Object System.Windows.Forms.CheckBox; $script:chkEvTracking.Text = 'Message tracking'; $script:chkEvTracking.Checked = $true; $script:chkEvTracking.AutoSize = $true
$script:chkEvTracking.Location = New-Object System.Drawing.Point(140, 74); $evTop.Controls.Add($script:chkEvTracking)
$script:chkEvIis = New-Object System.Windows.Forms.CheckBox; $script:chkEvIis.Text = 'IIS logs (UTC handled)'; $script:chkEvIis.Checked = $true; $script:chkEvIis.AutoSize = $true
$script:chkEvIis.Location = New-Object System.Drawing.Point(270, 74); $evTop.Controls.Add($script:chkEvIis)
$script:chkEvHttp = New-Object System.Windows.Forms.CheckBox; $script:chkEvHttp.Text = 'HttpProxy logs'; $script:chkEvHttp.Checked = $true; $script:chkEvHttp.AutoSize = $true
$script:chkEvHttp.Location = New-Object System.Drawing.Point(430, 74); $evTop.Controls.Add($script:chkEvHttp)
$script:btnEvidence = New-EtkButton 'Export window' 140 30 'Writes CSVs, a timeline and log extracts to Output\Evidence_<server>_<time>\.'
$script:btnEvidence.Location = New-Object System.Drawing.Point(10, 104); $evTop.Controls.Add($script:btnEvidence)
$script:btnEvOpen = New-EtkButton 'Open last folder' 140 30
$script:btnEvOpen.Location = New-Object System.Drawing.Point(156, 104); $evTop.Controls.Add($script:btnEvOpen)
$l = New-EtkLabel 'Performance capture (15 s samples, runs until stopped):'; $l.Location = New-Object System.Drawing.Point(620, 44); $evTop.Controls.Add($l)
$script:btnPerfStart = New-EtkButton 'Start capture...' 140 30 'Creates/starts a logman collector: disk latency and queue, process CPU and I/O, memory, RPC latency, DB cache.'
$script:btnPerfStart.Location = New-Object System.Drawing.Point(620, 70); $evTop.Controls.Add($script:btnPerfStart)
$script:btnPerfStop = New-EtkButton 'Stop capture...' 140 30
$script:btnPerfStop.Location = New-Object System.Drawing.Point(766, 70); $evTop.Controls.Add($script:btnPerfStop)
$script:txtEvidence = New-EtkMonoBox
$tpEv.Controls.Add($script:txtEvidence)
$tpEv.Controls.Add($evTop)
[void]$script:tabs.TabPages.Add($tpEv)
$script:runButtons += $script:btnEvidence
$script:runButtons += $script:btnPerfStart
$script:runButtons += $script:btnPerfStop

# JSON
$tpJson = New-EtkTabPage 'JSON report'
$jBar = New-EtkToolbar
$script:btnJsonRefresh = New-EtkButton 'Rebuild' 100
$script:btnJsonCopy = New-EtkButton 'Copy to clipboard' 140
$script:btnSaveJson = New-EtkButton 'Save...' 100
$script:chkJsonCompress = New-Object System.Windows.Forms.CheckBox; $script:chkJsonCompress.Text = 'Compact'; $script:chkJsonCompress.AutoSize = $true
$script:chkJsonCompress.Padding = New-Object System.Windows.Forms.Padding(6, 6, 0, 0)
$script:btnHtml = New-EtkButton 'HTML report...' 120 30 'Builds a self-contained HTML report from these results with Generate-ExchangeReport.ps1 (kept next to this tool).'
$jBar.Controls.AddRange(@($script:btnJsonRefresh, $script:btnJsonCopy, $script:btnSaveJson, $script:btnHtml, $script:chkJsonCompress))
$script:txtJson = New-EtkMonoBox
$tpJson.Controls.Add($script:txtJson)
$tpJson.Controls.Add($jBar)
[void]$script:tabs.TabPages.Add($tpJson)

# --- Activity log ---
$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = 'Activity'; $grpLog.Dock = 'Fill'
$script:txtLog = New-EtkMonoBox
$script:txtLog.ScrollBars = 'Vertical'; $script:txtLog.WordWrap = $true
$grpLog.Controls.Add($script:txtLog)
$root.Controls.Add($grpLog, 0, 2)

# ---------------------------------------------------------------------------
#  Timer - the only place the UI reads worker state
# ---------------------------------------------------------------------------
$script:timer = New-Object System.Windows.Forms.Timer
$script:timer.Interval = 300
$script:timer.Add_Tick({
    $sh = $script:Shared
    if (-not $sh) { $script:timer.Stop(); return }
    try {
        while ($script:logIndex -lt $sh.Log.Count) { Write-EtkLog ([string]$sh.Log[$script:logIndex]); $script:logIndex++ }
    } catch { }
    $script:lblStatus.Text = [string]$sh.Status
    $p = [int]$sh.Progress; if ($p -lt 0) { $p = 0 }; if ($p -gt 100) { $p = 100 }
    $script:progress.Value = $p
    if ($sh.Version -ne $script:lastVersion) {
        $script:lastVersion = $sh.Version
        foreach ($k in @($sh.Sections.Keys)) { $script:Sections[$k] = $sh.Sections[$k] }
        if ($sh.Verdict) { $script:Verdict = $sh.Verdict }
        Update-EtkGrids
        Update-EtkVerdictUi
    }
    if ($sh.Done) {
        $script:timer.Stop()
        Complete-EtkWorker
        Set-EtkBusy $false
        foreach ($k in @($sh.Sections.Keys)) { $script:Sections[$k] = $sh.Sections[$k] }
        if ($sh.Verdict) { $script:Verdict = $sh.Verdict }
        if ($sh.Connection) {
            $script:Target = $sh.Connection
            $script:connectedTo = [string]$sh.Connection.target
            Update-EtkTargetUi
            Write-EtkLog ('Target: {0}' -f $script:lblConn.Text)
        }
        Update-EtkGrids
        Update-EtkVerdictUi
        switch ($script:currentJob) {
            'action' {
                $r = $sh.Result
                if ($r) {
                    $script:Actions.Add($r)
                    $file = Write-EtkActionAudit -Result $r
                    if ($r.ok) { Write-EtkLog ('Action OK: {0}' -f $r.output) } else { Write-EtkLog ('Action FAILED: {0}' -f $r.output) }
                    if ($file) { Write-EtkLog ('Logged to {0}' -f $file) }
                    [void][System.Windows.Forms.MessageBox]::Show($(if ($r.ok) { 'Done: ' + $r.output + [Environment]::NewLine + [Environment]::NewLine + 'Re-run the tab to see the effect.' } else { 'The action failed: ' + $r.output }), 'Exchange Toolkit', 'OK', $(if ($r.ok) { 'Information' } else { 'Warning' }))
                    # The Fix tab's list is a read-only view; keep it current.
                    if ($script:svcLoaded -and [string]$r.id -like 'svc-*') { $script:refreshServices = $true }
                }
            }
            'services' {
                if ($sh.Error) { $script:lblSvcState.Text = ('Could not read the services: {0}' -f ($sh.Error -split "`n")[0].Trim()) }
                else { Update-EtkServiceGrid -Services $sh.Result }
            }
            'healthchecker' { Complete-EtkHealthChecker -Download $sh.Result -ErrorText ([string]$sh.Error) }
            'iplookup' { Complete-EtkIpLookup -Result $sh.Result -ErrorText ([string]$sh.Error) }
            'evidence' {
                $r = $sh.Result
                if ($r) {
                    $script:lastEvidence = [string]$r.folder
                    $script:txtEvidence.Text = (@($r.summary) -join [Environment]::NewLine)
                    Write-EtkLog ('Evidence written to {0}' -f $r.folder)
                }
            }
        }
        Update-EtkJsonTab
        if ($sh.Error) { Write-EtkLog ('Error: {0}' -f ($sh.Error -split "`n")[0]) }
        if ($sh.Cancel) { Write-EtkLog 'Stopped after the step that was running.' } else { Write-EtkLog 'Finished.' }
        $script:lblStatus.Text = 'Ready.'
        if ($script:refreshServices) { $script:refreshServices = $false; Start-EtkServiceRefresh }
    }
})

# ---------------------------------------------------------------------------
#  Events
# ---------------------------------------------------------------------------
$script:btnConnect.Add_Click({
    $o = Get-EtkUiOptions
    if ($o) { $o.ConnectFirst = $false; Start-EtkJob -Job 'connect' -Opt $o }
})
$script:btnRunAll.Add_Click({ Start-EtkJob -Job 'all' -Opt (Get-EtkUiOptions) })
$script:lblBadge.Add_Click({ $script:tabs.SelectedIndex = 0 })
$script:btnCancel.Add_Click({
    if ($script:Shared) {
        $script:Shared.Cancel = $true
        Write-EtkLog 'Cancelling. The check already running finishes first.'
        $script:btnCancel.Enabled = $false
    }
})
$script:btnElevate.Add_Click({
    try {
        $self = $PSCommandPath
        if (-not $self) { $self = Join-Path $script:ScriptDir 'Exchange-Toolkit.ps1' }
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        Start-Process -FilePath $psExe -Verb RunAs -ArgumentList ('-NoProfile -STA -ExecutionPolicy Bypass -File "{0}"' -f $self)
        $script:form.Close()
    } catch { Write-EtkLog ('Elevation was cancelled or failed: {0}' -f $_.Exception.Message) }
})

$script:btnEvidence.Add_Click({
    $o = Get-EtkUiOptions
    if (-not $o) { return }
    if ($script:dtTo.Value -le $script:dtFrom.Value) { [void][System.Windows.Forms.MessageBox]::Show('"To" must be after "From".', 'Exchange Toolkit', 'OK', 'Warning'); return }
    $o.Start = $script:dtFrom.Value; $o.End = $script:dtTo.Value
    $o.OutDir = Join-Path $script:OutputDir ('Evidence_{0}_{1}' -f ($o.Server -replace '[^\w\.\-]', '_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $o.Events = $script:chkEvEvents.Checked; $o.Tracking = $script:chkEvTracking.Checked; $o.Iis = $script:chkEvIis.Checked; $o.HttpProxy = $script:chkEvHttp.Checked
    Start-EtkJob -Job 'evidence' -Opt $o
})
$script:btnEvOpen.Add_Click({
    if ($script:lastEvidence -and (Test-Path -LiteralPath $script:lastEvidence)) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:lastEvidence) }
    elseif (Test-Path -LiteralPath $script:OutputDir) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:OutputDir) }
})
$script:btnCopyIps.Add_Click({
    $ips = Get-EtkUiPublicIps
    if ($ips.Count -eq 0) { Write-EtkLog 'No public addresses in the Security results yet.'; return }
    try { [System.Windows.Forms.Clipboard]::SetText((@($ips.Keys) -join [Environment]::NewLine)); Write-EtkLog ('{0} public address(es) copied to the clipboard.' -f $ips.Count) }
    catch { Write-EtkLog ('Could not reach the clipboard: {0}' -f $_.Exception.Message) }
})
$script:btnIpLookup.Add_Click({ Invoke-EtkUiIpLookup })
$script:btnSvcRefresh.Add_Click({ Start-EtkServiceRefresh })
$script:btnSvcStart.Add_Click({ Invoke-EtkServiceAction -Id 'svc-start' -Verb 'Start' })
$script:btnSvcStop.Add_Click({ Invoke-EtkServiceAction -Id 'svc-stop' -Verb 'Stop' })
$script:btnSvcRestart.Add_Click({ Invoke-EtkServiceAction -Id 'svc-restart' -Verb 'Restart' })
$script:btnStartAuto.Add_Click({ Invoke-EtkUiAction -Ref (New-EtkActionRef -Id 'svc-start-auto' -Label 'Start every stopped automatic Exchange/IIS service') })
$script:btnRecycleAll.Add_Click({ Invoke-EtkUiAction -Ref (New-EtkActionRef -Id 'apppool-recycle-all' -Label 'Recycle every MSExchange app pool - each pool''s users reconnect') })
$script:btnIisReset.Add_Click({ Invoke-EtkUiAction -Ref (New-EtkActionRef -Id 'iis-reset' -Label 'IIS reset - OWA, ActiveSync, Outlook and EWS drop for about a minute') })
$script:btnHealthChecker.Add_Click({ Invoke-EtkUiHealthChecker })
$script:btnHcOpen.Add_Click({
    if ($script:lastHealthChecker -and (Test-Path -LiteralPath $script:lastHealthChecker)) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:lastHealthChecker) }
    elseif (Test-Path -LiteralPath $script:OutputDir) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:OutputDir) }
})
# The service list loads the first time the Fix tab is opened.
$script:tabs.Add_SelectedIndexChanged({
    if ($script:tabs.SelectedTab -eq $script:tpFix -and -not $script:svcLoaded -and -not $script:busy) { Start-EtkServiceRefresh }
})
$script:btnPerfStart.Add_Click({ Invoke-EtkUiAction -Ref (New-EtkActionRef -Id 'perf-start' -Label 'Start the performance capture') })
$script:btnPerfStop.Add_Click({ Invoke-EtkUiAction -Ref (New-EtkActionRef -Id 'perf-stop' -Label 'Stop the performance capture') })

$script:btnJsonRefresh.Add_Click({ Update-EtkJsonTab })
$script:chkJsonCompress.Add_CheckedChanged({ Update-EtkJsonTab })
$script:btnJsonCopy.Add_Click({
    try {
        if (-not $script:txtJson.Text) { Update-EtkJsonTab }
        [System.Windows.Forms.Clipboard]::SetText($script:txtJson.Text)
        Write-EtkLog 'The JSON report is on the clipboard.'
    } catch { Write-EtkLog ('Could not reach the clipboard: {0}' -f $_.Exception.Message) }
})
function Invoke-EtkHtmlReport {
    # Saves the current results as JSON, then builds the HTML with the
    # generator - the same code the standalone report GUI uses, so both
    # produce the same file.
    param([bool]$IncludeDetail, [bool]$Redact)
    $gen = Join-Path $script:ScriptDir 'Generate-ExchangeReport.ps1'
    if (-not (Test-Path -LiteralPath $gen)) {
        [void][System.Windows.Forms.MessageBox]::Show(('Generate-ExchangeReport.ps1 was not found next to this tool ({0}). Copy it into the same folder, or save the JSON and use the generator on another PC.' -f $script:ScriptDir), 'Exchange Toolkit', 'OK', 'Warning')
        return
    }
    try {
        if (-not (Test-Path -LiteralPath $script:OutputDir)) { [void](New-Item -ItemType Directory -Path $script:OutputDir -Force) }
        $srv = $(if ($script:Target) { [string]$script:Target.target } else { $env:COMPUTERNAME })
        $json = Get-EtkMarkedJson -Report (New-EtkUiReport)
        $jsonPath = Join-Path $script:OutputDir ('ExchangeToolkit_{0}_{1}.json' -f ($srv -replace '[^\w\.\-]', '_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
        [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding $false))
        . $gen -NoGui
        $title = $(if ($Redact) { '' } else { $srv })
        $path = Save-EtrReport -Text $json -Title $title -IncludeDetail $IncludeDetail -Redact $Redact -OutDir $script:OutputDir
        Write-EtkLog ('HTML report written to {0} (JSON saved alongside).' -f $path)
        if ([System.Windows.Forms.MessageBox]::Show(("Report saved to:`n$path`n`nOpen it now?"), 'Exchange Toolkit', 'YesNo', 'Information') -eq 'Yes') { Start-Process $path }
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show(('The HTML report could not be built: {0}' -f $_.Exception.Message), 'Exchange Toolkit', 'OK', 'Error')
    }
}

$script:btnHtml.Add_Click({
    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $i1 = $menu.Items.Add('Full report (summary + technical detail)'); $i1.Add_Click({ Invoke-EtkHtmlReport -IncludeDetail $true -Redact $false })
    $i2 = $menu.Items.Add('Full report, client details hidden'); $i2.Add_Click({ Invoke-EtkHtmlReport -IncludeDetail $true -Redact $true })
    $i3 = $menu.Items.Add('Summary only (for the client)'); $i3.Add_Click({ Invoke-EtkHtmlReport -IncludeDetail $false -Redact $false })
    $menu.Show($script:btnHtml, (New-Object System.Drawing.Point(0, $script:btnHtml.Height)))
})

$script:btnSaveJson.Add_Click({
    try {
        if (-not (Test-Path -LiteralPath $script:OutputDir)) { [void](New-Item -ItemType Directory -Path $script:OutputDir -Force) }
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter = 'JSON report (*.json)|*.json|All files (*.*)|*.*'
        $srv = $(if ($script:Target) { [string]$script:Target.target } else { $env:COMPUTERNAME })
        $dlg.FileName = ('ExchangeToolkit_{0}_{1}.json' -f ($srv -replace '[^\w\.\-]', '_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $dlg.InitialDirectory = $script:OutputDir
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            [System.IO.File]::WriteAllText($dlg.FileName, (Get-EtkMarkedJson -Report (New-EtkUiReport)), (New-Object System.Text.UTF8Encoding $false))
            Write-EtkLog ('Report written to {0}' -f $dlg.FileName)
        }
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show(('The report could not be saved: {0}' -f $_.Exception.Message), 'Exchange Toolkit', 'OK', 'Error')
    }
})

$script:form.Add_Shown({
    # On an Exchange server, connect straight away - every Exchange check
    # needs it, and it takes a few seconds.
    if ($script:Context.exchangeInstalled) {
        $o = Get-EtkUiOptions
        if ($o) { $o.ConnectFirst = $false; Start-EtkJob -Job 'connect' -Opt $o }
    }
})

$script:form.Add_FormClosing({
    if ($script:Shared) { $script:Shared.Cancel = $true }
    try { $script:timer.Stop() } catch { }
    if ($script:ps -and $script:async -and -not $script:async.IsCompleted) {
        [void]$script:async.AsyncWaitHandle.WaitOne(3000, $false)
    }
    Complete-EtkWorker
    # Remove the Exchange session explicitly: an abandoned one keeps
    # long-polling /PowerShell and logs RBAC "connection leak" events.
    if ($script:engineRs -and $script:engineRs.RunspaceStateInfo.State -eq 'Opened') {
        try {
            $p = [powershell]::Create(); $p.Runspace = $script:engineRs
            [void]$p.AddScript('if ($global:EtkExchangeSession) { Remove-PSSession -Session $global:EtkExchangeSession -ErrorAction SilentlyContinue; $global:EtkExchangeSession = $null }')
            $a = $p.BeginInvoke()
            [void]$a.AsyncWaitHandle.WaitOne(5000, $false)
            $p.Dispose()
        } catch { }
        try { $script:engineRs.Close(); $script:engineRs.Dispose() } catch { }
    }
})

# ---------------------------------------------------------------------------
#  Start
# ---------------------------------------------------------------------------
$tag = ''
if ($script:Context.isSystem) { $tag = '  [SYSTEM]' } elseif ($script:Context.elevated) { $tag = '  [elevated]' } else { $tag = '  [NOT elevated - VSS, shadow copies, Security log and IIS checks will say so]' }
Write-EtkLog ('Exchange Toolkit {0} on {1}, running as {2}{3}, PowerShell {4}.' -f (Get-EtkVersion), $script:Context.computerName, $script:Context.runAs, $tag, $script:Context.psVersion)
if ($script:Account.shared) { Write-EtkLog ('Running as {0}, a shared account: you will be asked for your name before the first action, so the action log says who ran it.' -f $script:Account.name) }
if ($script:Context.isSystem) { Write-EtkLog 'Running as SYSTEM: Exchange is reached through the local management snap-in (remote PowerShell would sign in as the computer account). Remote targets are not available.' }
if ($script:Context.exchangeInstalled) { Write-EtkLog 'Exchange is installed here - connecting.' }
else { Write-EtkLog 'Exchange is not installed on this machine. Type the Exchange server name and press Connect, or run the OS checks against this machine.' }
Write-EtkLog 'Checks never change anything. Rows marked with a dot in the Act column offer an action, and the Fix tab holds service controls and quick fixes - each one shows its command and asks first.'

[void]$script:form.ShowDialog()
$script:form.Dispose()
