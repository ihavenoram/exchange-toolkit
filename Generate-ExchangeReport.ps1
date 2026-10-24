<#
.SYNOPSIS
    HTML report generator for the Exchange Toolkit.
.DESCRIPTION
    Paste the JSON report the Exchange Toolkit saved or copied (with or without
    the <<<ETK_JSON_BEGIN>>> / <<<ETK_JSON_END>>> markers), or browse to the
    saved .json. Produces one self-contained HTML file in the Output folder
    next to this script:
      * a plain-English summary for the client at the top
      * the full technical detail below it, for technicians
    Optionally hides client details (names, addresses, thumbprints) so the
    report can be shared outside the client.
.NOTES
    Windows PowerShell 5.1, WinForms, no dependencies. Same pattern as
    3CX_CHECKER\Generate-3cxReport.ps1.
    Keep this file pure ASCII: PS 5.1 reads BOM-less files as cp1252, so any
    other glyph must be an HTML entity.
    The generator never recomputes a verdict - it renders the one the toolkit
    recorded, so the HTML cannot disagree with the tool.
    -NoGui loads the functions only (for tests and for the toolkit's own
    "HTML report" button).
#>
[CmdletBinding()]
param([switch]$NoGui, [switch]$NoHideConsole)

$script:EtrVersion = '1.1.0'
$script:EtrSchema  = 'exchange-toolkit-report'
$script:EtrRedactor = $null

# -----------------------------------------------------------------------------
# What the toolkit's tabs contain, mirrored here so the generator does not
# depend on the toolkit file being present. A section the toolkit adds later
# still appears (under "Other checks") - nothing in the JSON is dropped.
# -----------------------------------------------------------------------------
function Get-EtrLayout {
    @(
        [pscustomobject]@{ tab = 'Overview'; sections = @('server', 'restarts') }
        [pscustomobject]@{ tab = 'Health'; sections = @('services', 'serviceHealth', 'components', 'appPools', 'databases', 'certificates', 'disks', 'memory', 'eventLogs', 'eventSignals', 'logNoise', 'diskLatency') }
        [pscustomobject]@{ tab = 'Mail flow'; sections = @('queues', 'backPressure', 'throughput', 'transportConfig', 'connectors') }
        [pscustomobject]@{ tab = 'Storage & backup'; sections = @('exBackup', 'vssWriters', 'shadowCopies', 'filters', 'agents', 'sentinel', 'crashplan', 'schedule') }
        [pscustomobject]@{ tab = 'Security'; sections = @('failedLogins', 'logons', 'exposure', 'ipLookup') }
    )
}

function Get-EtrSectionTitle {
    param([string]$Key)
    $t = @{
        server = 'Server facts'; restarts = 'Restarts'; services = 'Services'; serviceHealth = 'Service health'
        components = 'Component state'; appPools = 'IIS app pools'; databases = 'Databases'; certificates = 'Certificates'
        disks = 'Disk space'; memory = 'Memory'; diskLatency = 'Disk latency'; eventLogs = 'Event log retention'
        eventSignals = 'Event signals'; logNoise = 'Log noise'; queues = 'Queues'; backPressure = 'Back pressure'
        throughput = 'Throughput'; transportConfig = 'Transport settings'; connectors = 'Connectors'
        exBackup = 'Exchange backups'; vssWriters = 'VSS writers'; shadowCopies = 'Shadow copies'
        filters = 'Volume filter drivers'; agents = 'Backup & snapshot software'; sentinel = 'SentinelOne snapshots'
        crashplan = 'CrashPlan'; schedule = 'Schedule'
        failedLogins = 'Failed logins'; logons = 'Logons'; exposure = 'Exposure'; ipLookup = 'IP locations'
    }
    if ($t.ContainsKey($Key)) { return $t[$Key] }
    return $Key
}

function Get-EtrCollapsedSections {
    # Long tables that sit in a collapsible block (opened automatically when
    # printing).
    @('schedule', 'appPools', 'shadowCopies', 'connectors', 'throughput', 'logons', 'ipLookup')
}

# -----------------------------------------------------------------------------
# Input
# -----------------------------------------------------------------------------
function Get-EtrReportJson {
    # The report, from a paste (markers or bare JSON) or a file's text. Refuses
    # anything that is not an Exchange Toolkit report, and names truncation -
    # the usual failure with a long paste - instead of a bare parse error.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { throw 'Nothing to read - paste the report or browse to the .json file.' }
    $hasBegin = $Text -match '<<<ETK_JSON_BEGIN>>>'
    $hasEnd   = $Text -match '<<<ETK_JSON_END>>>'
    if ($hasBegin -and -not $hasEnd) {
        throw ("The report is truncated: the <<<ETK_JSON_BEGIN>>> marker is there but <<<ETK_JSON_END>>> is missing ({0:N0} characters).`n`n" -f $Text.Length +
               "The text was cut off before it was copied. Use 'Browse JSON...' to load the saved .json file instead - the toolkit saves one in its Output folder.")
    }
    $json = $Text.Trim()
    $m = [regex]::Match($Text, '(?s)<<<ETK_JSON_BEGIN>>>\s*(.*?)\s*<<<ETK_JSON_END>>>')
    if ($m.Success) { $json = $m.Groups[1].Value.Trim() }
    try { $obj = $json | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $hint = ''
        if ($json -and -not $json.TrimEnd().EndsWith('}')) {
            $hint = ("`n`nIt does not end with '}}', so it looks truncated ({0:N0} characters). Try 'Browse JSON...' to load the saved file." -f $json.Length)
        }
        throw ('Could not read the JSON: ' + $_.Exception.Message + $hint)
    }
    if ([string]$obj.schema -ne $script:EtrSchema) {
        throw ("This is not an Exchange Toolkit report (schema: '{0}'). Save or copy the report from the toolkit's JSON report tab." -f [string]$obj.schema)
    }
    $major = ([string]$obj.schemaVersion).Split('.')[0]
    if ($major -ne '1') {
        throw ("This report uses schema version {0}, made by a newer Exchange Toolkit. Update Generate-ExchangeReport.ps1 to match." -f [string]$obj.schemaVersion)
    }
    return $obj
}

# -----------------------------------------------------------------------------
# Redaction. Every piece of text reaches the page through Out-EtrText, which
# applies the redactor first - so no field can bypass it.
# -----------------------------------------------------------------------------
function Get-EtrStrings {
    # Every string value in the report, for the redaction map to scan.
    param($Node, [System.Collections.Generic.List[string]]$Into, [int]$Depth = 0)
    if ($null -eq $Node -or $Depth -gt 20) { return }
    if ($Node -is [string]) { $Into.Add($Node); return }
    if ($Node -is [System.ValueType]) { return }
    if ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [System.Management.Automation.PSCustomObject])) {
        foreach ($i in $Node) { Get-EtrStrings -Node $i -Into $Into -Depth ($Depth + 1) }
        return
    }
    foreach ($p in $Node.PSObject.Properties) { Get-EtrStrings -Node $p.Value -Into $Into -Depth ($Depth + 1) }
}

function Get-EtrRegistrableDomain {
    # contoso.com from mail.contoso.com; contoso.com.au from mail.contoso.com.au.
    param([string]$HostName)
    $labels = @($HostName.ToLowerInvariant().Trim('.').Split('.') | Where-Object { $_ })
    if ($labels.Count -lt 2) { return $HostName.ToLowerInvariant() }
    $n = 2
    if ($labels.Count -ge 3 -and $labels[-1].Length -eq 2 -and $labels[-2] -in @('com', 'net', 'org', 'edu', 'gov', 'co', 'asn', 'id')) { $n = 3 }
    return (($labels[($labels.Count - $n)..($labels.Count - 1)]) -join '.')
}

function Get-EtrRedactionMap {
    # Built from the report itself. Names are replaced longest first, whole
    # words only, case-insensitively; the same value always gets the same
    # placeholder so the report still reads consistently.
    param($Report)
    $strings = New-Object System.Collections.Generic.List[string]
    Get-EtrStrings -Node $Report -Into $strings
    $pairs = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$Find, [string]$Replace)
        if ([string]::IsNullOrWhiteSpace($Find) -or $Find.Length -lt 3) { return }
        if (@($pairs | Where-Object { $_.find -eq $Find }).Count) { return }
        $pairs.Add([pscustomobject]@{ find = $Find; replace = $Replace })
    }
    $h = $Report.host; $t = $Report.target
    # A workgroup machine's "FQDN" is its bare name - that must map to
    # EX-SERVER, not to the dotted placeholder.
    foreach ($f in @([string]$h.fqdn, [string]$t.fqdn)) { if ($f -like '*.*') { & $add $f 'ex-server.example.local' } }
    & $add ([string]$h.computerName) 'EX-SERVER'
    & $add ([string]$t.target) 'EX-SERVER'
    & $add ([string]$t.exchangeServer) 'EX-SERVER'
    $dns = [string]$h.domain
    & $add $dns 'example.local'
    $netbios = ''
    if ([string]$h.runAs -match '^([^\\]+)\\') { $netbios = $Matches[1] }
    if ($netbios -and $netbios -notmatch '^(NT AUTHORITY|BUILTIN)$') { & $add $netbios 'DOMAIN' }

    # DOMAIN\user names. Built-in account names say nothing about the client
    # and are left readable.
    $builtin = @('administrator', 'system', 'network service', 'local service', 'guest')
    $users = @{}
    # Domain accounts, and local accounts on the server itself (EX01\bob).
    $prefixes = @(@($netbios, [string]$h.computerName) | Where-Object { $_ } | Select-Object -Unique)
    foreach ($pfx in $prefixes) {
        foreach ($s in $strings) {
            foreach ($m in [regex]::Matches($s, ('(?i)\b{0}\\([A-Za-z0-9._$-]+)' -f [regex]::Escape($pfx)))) {
                $u = $m.Groups[1].Value
                if ($builtin -contains $u.ToLowerInvariant() -or $users.ContainsKey($u.ToLowerInvariant())) { continue }
                $users[$u.ToLowerInvariant()] = ('user{0}' -f ($users.Count + 1))
            }
        }
    }
    foreach ($k in $users.Keys) { & $add $k $users[$k] }

    # Names in the Security tab's "Accounts tried:" lists. These are only
    # replaced INSIDE such a list: a guessed name such as "backup" or "test"
    # is also an ordinary word, and replacing it everywhere would garble the
    # rest of the report.
    $accounts = @{}
    foreach ($s in $strings) {
        foreach ($m in [regex]::Matches($s, (Get-EtrAccountListPattern))) {
            foreach ($n in ($m.Groups['list'].Value -split ',\s*')) {
                $k = $n.Trim().ToLowerInvariant()
                if (-not $k -or $builtin -contains $k -or $accounts.ContainsKey($k)) { continue }
                if ($users.ContainsKey($k)) { $accounts[$k] = $users[$k] }
                else { $accounts[$k] = ('user{0}' -f ($users.Count + $accounts.Count + 1)) }
            }
        }
    }

    # Internet domains seen anywhere (certificate names, connector address
    # spaces, smart hosts, e-mail addresses). Microsoft's own names are left
    # alone - they identify nothing.
    $keep = @('microsoft.com', 'office.com', 'office365.com', 'outlook.com', 'windows.com', 'windows.net', 'live.com', 'example.local', 'example.com', 'example.net')
    $doms = @{}
    $rx = '(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b'
    foreach ($s in $strings) {
        foreach ($m in [regex]::Matches($s, $rx)) {
            $hn = $m.Value.ToLowerInvariant()
            if ($hn -match '\.(exe|dll|sys|log|edb|que|ps1|bat|cmd|xml|json|txt|config|chk|jrs|ffs_batch|msc)$') { continue }   # file names, not hosts
            if ($hn -match '^(m\.e\.|system\.|microsoft\.)') { continue }   # .NET namespaces in event and method text
            # Only real top-level domains: a dotted .NET name such as
            # Web.Administration is not a host.
            $tld = $hn.Split('.')[-1]
            if ($tld.Length -ne 2 -and $tld -notin @('com', 'net', 'org', 'local', 'info', 'biz', 'io', 'co', 'gov', 'edu', 'int', 'cloud', 'online', 'app', 'dev', 'lan', 'corp', 'internal')) { continue }
            $reg = Get-EtrRegistrableDomain $hn
            if ($keep -contains $reg -or $reg -eq $dns.ToLowerInvariant()) { continue }
            if ($reg.Split('.').Count -lt 2) { continue }
            if (-not $doms.ContainsKey($reg)) { $doms[$reg] = ('example{0}.com' -f ($doms.Count + 1)) }
        }
    }
    foreach ($k in $doms.Keys) { & $add $k $doms[$k] }

    $sorted = @($pairs | Sort-Object { $_.find.Length } -Descending)
    [pscustomobject]@{ pairs = [object[]]$sorted; ipMap = @{}; accounts = $accounts }
}

function Get-EtrAccountListPattern {
    # "Accounts tried: a, b, c." or "Accounts tried: a, b (+3 more)." - the
    # list ends at the first full stop followed by a space or the end, so a
    # name such as john.smith stays whole.
    '(?i)Accounts tried: (?<list>.+?)(?<more> \(\+\d+ more\))?\.(?=\s|$)'
}

function ConvertTo-EtrSafeText {
    # The single place text is redacted.
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $r = $script:EtrRedactor
    if (-not $r) { return $s }
    if ($r.accounts -and $r.accounts.Count -and $s -match 'Accounts tried: ') {
        $s = [regex]::Replace($s, (Get-EtrAccountListPattern), [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            $names = @($m.Groups['list'].Value -split ',\s*' | ForEach-Object {
                $k = $_.Trim().ToLowerInvariant()
                if ($script:EtrRedactor.accounts.ContainsKey($k)) { $script:EtrRedactor.accounts[$k] } else { $_.Trim() }
            })
            'Accounts tried: ' + ($names -join ', ') + $m.Groups['more'].Value + '.'
        })
    }
    foreach ($p in $r.pairs) {
        $s = [regex]::Replace($s, ('(?i)(?<![A-Za-z0-9-]){0}(?![A-Za-z0-9-])' -f [regex]::Escape($p.find)), [string]$p.replace)
    }
    # Certificate thumbprints (40 hex characters).
    $s = [regex]::Replace($s, '(?i)\b[0-9a-f]{40}\b', '<thumbprint>')
    # IPv4 addresses, numbered consistently; wildcard and loopback stay.
    $ipMap = $r.ipMap
    $s = [regex]::Replace($s, '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', {
        param($m)
        $ip = $m.Value
        if ($ip -in @('0.0.0.0', '127.0.0.1')) { return $ip }
        if (-not $ipMap.ContainsKey($ip)) { $ipMap[$ip] = ('x.x.x.{0}' -f ($ipMap.Count + 1)) }
        return $ipMap[$ip]
    })
    # IPv6 addresses (the Security tab records them). A candidate only counts
    # if it really parses as one, so clock times and MAC addresses stay.
    $s = [regex]::Replace($s, '(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])', {
        param($m)
        $v = $m.Value
        $a = $null
        if ($v -in @('::', '::1') -or -not [System.Net.IPAddress]::TryParse($v, [ref]$a) -or $a.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $v }
        $k = $a.ToString().ToLowerInvariant()
        if (-not $ipMap.ContainsKey($k)) { $ipMap[$k] = ('x:x::{0}' -f ($ipMap.Count + 1)) }
        return $ipMap[$k]
    })
    return $s
}

# -----------------------------------------------------------------------------
# Formatting helpers (from the 3CX report generator)
# -----------------------------------------------------------------------------
function Out-EtrText {
    # Redact, then HTML-encode. Every value on the page goes through here.
    param($Value)
    return [System.Net.WebUtility]::HtmlEncode((ConvertTo-EtrSafeText $Value))
}

function Get-EtrSlug {
    param([string]$Name)
    $s = (([string]$Name).Trim().ToLower() -replace '[^a-z0-9]+', '-').Trim('-')
    if (-not $s) { $s = 'server' }
    if ($s.Length -gt 40) { $s = $s.Substring(0, 40) }
    return $s
}

function Get-EtrZone {
    # Times in the server's own zone when the report records it, otherwise
    # this PC's - and the footer says which.
    param($Report)
    try { if ($Report.host.timeZone) { return [System.TimeZoneInfo]::FindSystemTimeZoneById([string]$Report.host.timeZone) } } catch { }
    return [System.TimeZoneInfo]::Local
}

function Format-EtrTime {
    param($Iso, $Zone, [string]$Format = 'ddd d MMM yyyy HH:mm')
    if (-not $Iso) { return '' }
    try {
        $dto = [DateTimeOffset]::Parse([string]$Iso, [System.Globalization.CultureInfo]::InvariantCulture)
        if (-not $Zone) { $Zone = [System.TimeZoneInfo]::Local }
        return [System.TimeZoneInfo]::ConvertTime($dto, $Zone).ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
    } catch { return [string]$Iso }
}

function Get-EtrArray { param($Value) if ($null -eq $Value) { return @() }; return @($Value) }

function Get-EtrStatusClass {
    param([string]$Status)
    switch -Regex (([string]$Status).ToLower()) {
        '^(ok|green)$'    { return 'ok' }
        '^(warn|amber)$'  { return 'warn' }
        '^(fail|red)$'    { return 'fail' }
        default           { return 'info' }
    }
}

function Get-EtrStatusLabel {
    param([string]$Status)
    switch (([string]$Status).ToLower()) {
        'ok' { 'OK' } 'warn' { 'Warning' } 'fail' { 'Problem' } 'green' { 'Clear' } 'amber' { 'Warnings' } 'red' { 'Problems' } 'notmeasured' { 'Not measured' } default { 'Info' }
    }
}

function Get-EtrFirstSentence {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $m = [regex]::Match($Text.Trim(), '^(.+?[\.\!\?])(\s|$)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $Text.Trim()
}

function New-EtrTable {
    # $Rows: arrays of already-encoded HTML cells. $CellClass (optional): a
    # scriptblock given (row, column, rowIndex) returning a CSS class.
    param([string[]]$Headers, $Rows, [scriptblock]$CellClass = $null, [string]$Class = '')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="' + $Class + '"><thead><tr>')
    foreach ($hd in $Headers) { [void]$sb.Append('<th>' + [System.Net.WebUtility]::HtmlEncode($hd) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    $ri = 0
    foreach ($row in @($Rows)) {
        [void]$sb.Append('<tr>')
        for ($ci = 0; $ci -lt @($row).Count; $ci++) {
            $cls = ''
            if ($CellClass) { $cls = [string](& $CellClass $row $ci $ri) }
            if ($cls) { [void]$sb.Append('<td class="' + $cls + '">') } else { [void]$sb.Append('<td>') }
            [void]$sb.Append([string]@($row)[$ci])
            [void]$sb.Append('</td>')
        }
        [void]$sb.Append('</tr>')
        $ri++
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function Get-EtrCss {
@'
<style>
:root { --ok:#1b7f3b; --okbg:#e6f4ea; --warn:#9a5b00; --warnbg:#fff4e0; --fail:#b3261e; --failbg:#fde7e6; --info:#5f6b77; --infobg:#eef1f5; --ink:#1f2933; --line:#d9dee5; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background: #eef2f7; color: var(--ink); font-size: 14px; }
.page { max-width: 1180px; margin: 0 auto; padding: 24px 28px 40px; }
header { background: #16324f; color: #fff; padding: 22px 28px; border-radius: 10px; }
header h1 { margin: 0 0 6px; font-size: 24px; }
header .meta { color: #c9d6e3; font-size: 13px; line-height: 1.6; }
header .meta b { color: #fff; font-weight: 600; }
.redacted { display: inline-block; margin-top: 8px; background: #fff4e0; color: #6b4200; border-radius: 6px; padding: 4px 10px; font-size: 12px; }
.overall { display: flex; align-items: center; gap: 18px; background: #fff; border-radius: 10px; padding: 16px 20px; margin: 18px 0 0; box-shadow: 0 1px 2px rgba(0,0,0,.06); border-left: 8px solid var(--info); }
.overall .big { font-size: 24px; font-weight: 800; letter-spacing: .02em; }
.overall .sub { color: #4a5568; font-size: 13px; line-height: 1.5; }
.overall.ok { border-left-color: var(--ok); } .overall.ok .big { color: var(--ok); }
.overall.warn { border-left-color: #e09200; } .overall.warn .big { color: var(--warn); }
.overall.fail { border-left-color: var(--fail); } .overall.fail .big { color: var(--fail); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; margin: 14px 0 18px; }
.tile { background: #fff; border-radius: 10px; padding: 12px 14px; border-left: 6px solid var(--info); box-shadow: 0 1px 2px rgba(0,0,0,.06); }
.tile .label { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--info); }
.tile .value { font-size: 18px; font-weight: 700; margin: 4px 0 2px; }
.tile .sub { font-size: 12px; color: #4a5568; }
.tile.ok { border-left-color: var(--ok); } .tile.ok .value { color: var(--ok); }
.tile.warn { border-left-color: #e09200; } .tile.warn .value { color: var(--warn); }
.tile.fail { border-left-color: var(--fail); } .tile.fail .value { color: var(--fail); }
section { background: #fff; border-radius: 10px; padding: 6px 20px 18px; margin: 16px 0; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
h2 { font-size: 18px; margin: 16px 0 10px; }
h3 { font-size: 15px; margin: 18px 0 6px; }
.state { font-size: 12px; font-weight: 400; color: var(--info); margin-left: 8px; }
.state.notrun { color: var(--warn); } .state.failed { color: var(--fail); }
.attention li { margin: 7px 0; line-height: 1.45; }
.attention .area { font-weight: 600; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin: 6px 0 10px; }
th { text-align: left; background: #f3f5f8; color: #3b4652; font-weight: 600; padding: 7px 8px; border-bottom: 2px solid var(--line); }
td { padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
td.ok { color: var(--ok); font-weight: 600; } td.warn { color: var(--warn); font-weight: 600; } td.fail { color: var(--fail); font-weight: 600; } td.info { color: var(--info); }
tr.fail td { background: #fdf3f2; } tr.warn td { background: #fffaf0; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }
.pill.ok { background: var(--okbg); color: var(--ok); } .pill.warn { background: var(--warnbg); color: var(--warn); }
.pill.fail { background: var(--failbg); color: var(--fail); } .pill.info { background: var(--infobg); color: var(--info); }
.mono { font-family: Consolas, "SF Mono", monospace; font-size: 12px; }
.note { color: var(--info); font-size: 12px; }
.method { color: var(--info); font-size: 12px; margin: 2px 0 6px; }
.callout { border-left: 4px solid var(--info); background: #f7f9fb; padding: 8px 12px; margin: 8px 0; }
.callout.warn { border-left-color: #e09200; } .callout.fail { border-left-color: var(--fail); }
details > summary { cursor: pointer; color: #16324f; font-weight: 600; margin: 4px 0; }
footer { color: var(--info); font-size: 12px; margin-top: 24px; line-height: 1.5; }
@media print { body { background: #fff; } section, .tile, .overall { box-shadow: none; border: 1px solid var(--line); } header { background: #fff; color: #000; border: 1px solid #000; } header .meta, header .meta b { color: #000; } section { break-inside: auto; } h2, h3 { break-after: avoid; } }
</style>
'@
}

# -----------------------------------------------------------------------------
# The report
# -----------------------------------------------------------------------------
function Get-EtrOverall {
    param([string]$Level)
    switch ($Level) {
        'red'   { return [pscustomobject]@{ text = 'PROBLEMS FOUND';   cls = 'fail' } }
        'amber' { return [pscustomobject]@{ text = 'WARNINGS';         cls = 'warn' } }
        'green' { return [pscustomobject]@{ text = 'NO PROBLEMS FOUND'; cls = 'ok' } }
        default { return [pscustomobject]@{ text = 'NOT MEASURED';     cls = 'info' } }
    }
}

function Get-EtrCountsText {
    # Counts of the areas the toolkit already graded - not a new verdict.
    param($Verdict)
    $c = @{ red = 0; amber = 0; green = 0; notmeasured = 0 }
    foreach ($s in (Get-EtrArray $Verdict.subscores)) { $l = [string]$s.level; if ($c.ContainsKey($l)) { $c[$l]++ } }
    $parts = @()
    if ($c.red) { $parts += ('{0} with problems' -f $c.red) }
    if ($c.amber) { $parts += ('{0} with warnings' -f $c.amber) }
    if ($c.green) { $parts += ('{0} clear' -f $c.green) }
    if ($c.notmeasured) { $parts += ('{0} not measured' -f $c.notmeasured) }
    if ($parts.Count -eq 0) { return 'No areas were graded.' }
    return ('Areas: ' + ($parts -join ', '))
}

function Get-EtrOrderedSections {
    # (tab, key, section) in the toolkit's own order, then anything unknown.
    param($Report)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $secs = $Report.sections
    $names = @(); if ($secs) { $names = @($secs.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($tab in (Get-EtrLayout)) {
        foreach ($k in $tab.sections) {
            if ($names -contains $k) { $out.Add([pscustomobject]@{ tab = $tab.tab; key = $k; section = $secs.$k }); $seen[$k] = $true }
        }
    }
    foreach ($k in $names) { if (-not $seen.ContainsKey($k)) { $out.Add([pscustomobject]@{ tab = 'Other checks'; key = $k; section = $secs.$k }) } }
    return $out.ToArray()
}

function Get-EtrAttention {
    # Problems first, then warnings, de-duplicated - taken from the rows as
    # recorded. Nothing is reworded beyond taking the first sentence.
    param($Ordered)
    $items = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($want in @('fail', 'warn')) {
        foreach ($o in $Ordered) {
            foreach ($r in (Get-EtrArray $o.section.rows)) {
                if ([string]$r.status -ne $want) { continue }
                $key = ('{0}|{1}|{2}' -f $o.key, $r.check, $r.result)
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $items.Add([pscustomobject]@{ status = $want; area = (Get-EtrSectionTitle $o.key); check = [string]$r.check; result = [string]$r.result; why = (Get-EtrFirstSentence ([string]$r.detail)) })
            }
        }
    }
    return $items.ToArray()
}

function Build-EtrHtml {
    param($Report, [string]$Title = '', [bool]$IncludeDetail = $true, [bool]$Redact = $false)
    $script:EtrRedactor = $null
    if ($Redact) { $script:EtrRedactor = Get-EtrRedactionMap -Report $Report }
    try {
        $zone = Get-EtrZone $Report
        $h = $Report.host; $t = $Report.target; $v = $Report.verdict
        $server = [string]$t.target; if (-not $server) { $server = [string]$h.computerName }
        if (-not $Title) { $Title = $server }
        $pageTitle = ('{0} - Exchange health report' -f $Title)
        $ordered = @(Get-EtrOrderedSections $Report)

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
        [void]$sb.Append('<title>' + (Out-EtrText $pageTitle) + '</title>' + (Get-EtrCss) + '</head><body><div class="page">')

        # ---- header ----
        $meta = New-Object System.Collections.Generic.List[string]
        $meta.Add('Server <b>' + (Out-EtrText $server) + '</b>')
        if ($t.version) { $meta.Add('Exchange <b>' + (Out-EtrText $t.version) + '</b>') }
        $via = switch ([string]$t.exchange) { 'session' { 'remote PowerShell' } 'snapin' { 'management snap-in' } default { '' } }
        if ($via) { $meta.Add('Connected via <b>' + (Out-EtrText $via) + '</b>') }
        else { $meta.Add('<b>Exchange not connected</b> - Windows checks only') }
        $who = [string]$h.runAs
        if ($h.technician) { $who = ('{0} (technician: {1})' -f $who, $h.technician) }
        $gen = ('Checked ' + (Out-EtrText (Format-EtrTime $Report.collectedUtc $zone)) + ' by <b>' + (Out-EtrText $who) + '</b> with ' + (Out-EtrText $Report.tool.name) + ' ' + (Out-EtrText $Report.tool.version))
        [void]$sb.Append('<header><h1>' + (Out-EtrText $pageTitle) + '</h1><div class="meta">' + ($meta -join ' &middot; ') + '<br>' + $gen + '</div>')
        if ($Redact) {
            [void]$sb.Append('<div class="redacted">Client details hidden: server, domain and user names, internet domains, IP addresses and certificate thumbprints are replaced with placeholders. Free text (event messages, task names, file paths) can still mention details the rules do not recognise - skim it before sharing.</div>')
        }
        [void]$sb.Append('</header>')

        # ---- summary ----
        $ov = Get-EtrOverall ([string]$v.overall)
        [void]$sb.Append('<div class="overall ' + $ov.cls + '"><div class="big">' + $ov.text + '</div><div class="sub">' + (Out-EtrText (Get-EtrCountsText $v)) + '<br>' + (Out-EtrText $v.headline) + '</div></div>')
        [void]$sb.Append('<div class="tiles">')
        foreach ($s in (Get-EtrArray $v.subscores)) {
            $cls = Get-EtrStatusClass ([string]$s.level)
            [void]$sb.Append('<div class="tile ' + $cls + '"><div class="label">' + (Out-EtrText $s.name) + '</div><div class="value">' + (Out-EtrText (Get-EtrStatusLabel ([string]$s.level))) + '</div><div class="sub">' + (Out-EtrText $s.summary) + '</div></div>')
        }
        [void]$sb.Append('</div>')

        $att = @(Get-EtrAttention $ordered)
        [void]$sb.Append('<section><h2 id="attention">What needs attention</h2>')
        if ($att.Count -eq 0) {
            [void]$sb.Append('<p>Nothing measured in this run was flagged as a problem or a warning. Check the list below for anything that could not be checked.</p>')
        } else {
            $cap = 15
            [void]$sb.Append('<ul class="attention">')
            foreach ($a in @($att | Select-Object -First $cap)) {
                [void]$sb.Append('<li><span class="pill ' + $a.status + '">' + (Get-EtrStatusLabel $a.status) + '</span> <span class="area">' + (Out-EtrText $a.area) + ':</span> ' +
                    (Out-EtrText $a.check) + ' &mdash; ' + (Out-EtrText $a.result))
                if ($a.why) { [void]$sb.Append('<br><span class="note">' + (Out-EtrText $a.why) + '</span>') }
                [void]$sb.Append('</li>')
            }
            [void]$sb.Append('</ul>')
            if ($att.Count -gt $cap) {
                [void]$sb.Append('<p class="note">' + ($att.Count - $cap) + ' more ' + $(if ($IncludeDetail) { 'in the <a href="#detail">technical detail</a>.' } else { 'in the full report.' }) + '</p>')
            }
        }
        [void]$sb.Append('</section>')

        # ---- not checked ----
        $gaps = @($ordered | Where-Object { [string]$_.section.state -in @('unsupported', 'failed') })
        # Sections that ran but could not read every source (data.notMeasured).
        $partial = @($ordered | Where-Object { [string]$_.section.state -eq 'measured' -and $_.section.data -and @(Get-EtrArray $_.section.data.notMeasured | Where-Object { $_ }).Count })
        [void]$sb.Append('<section><h2 id="notchecked">Not checked in this run</h2>')
        if ($gaps.Count -eq 0 -and $partial.Count -eq 0) {
            [void]$sb.Append('<p>Every check that applies to this server ran.</p>')
        } else {
            [void]$sb.Append('<p class="note">These were not measured, so they are not counted either way - a gap here is not a clean result.</p>')
            $grows = @($gaps | ForEach-Object { ,@((Out-EtrText (Get-EtrSectionTitle $_.key)), (Out-EtrText $_.section.state), (Out-EtrText $_.section.reason)) })
            $grows += @($partial | ForEach-Object { ,@((Out-EtrText (Get-EtrSectionTitle $_.key)), 'measured in part', (Out-EtrText ((@(Get-EtrArray $_.section.data.notMeasured)) -join '; '))) })
            [void]$sb.Append((New-EtrTable -Headers @('Check', 'State', 'Why') -Rows $grows))
        }
        [void]$sb.Append('</section>')

        # ---- technical detail ----
        if ($IncludeDetail) {
            [void]$sb.Append('<h2 id="detail" style="margin-top:28px">Technical detail</h2>')
            $collapsed = Get-EtrCollapsedSections
            foreach ($tabName in @($ordered | ForEach-Object { $_.tab } | Select-Object -Unique)) {
                [void]$sb.Append('<section><h2>' + (Out-EtrText $tabName) + '</h2>')
                foreach ($o in @($ordered | Where-Object { $_.tab -eq $tabName })) {
                    $sec = $o.section
                    $state = [string]$sec.state
                    $stCls = $(if ($state -eq 'measured') { '' } elseif ($state -eq 'failed') { 'failed' } else { 'notrun' })
                    $stText = $(if ($state -eq 'measured') { ('measured' + $(if ($sec.startedUtc) { ' ' + (Format-EtrTime $sec.startedUtc $zone 'HH:mm:ss') } else { '' }) + $(if ($sec.durationSec) { (', {0} s' -f $sec.durationSec) } else { '' })) } else { $state })
                    $head = ('<h3 id="s-' + $o.key + '">' + (Out-EtrText (Get-EtrSectionTitle $o.key)) + ' <span class="state ' + $stCls + '">' + (Out-EtrText $stText) + '</span></h3>')
                    $body = New-Object System.Text.StringBuilder
                    if ($sec.reason) { [void]$body.Append('<div class="callout ' + $(if ($state -eq 'failed') { 'fail' } else { 'warn' }) + '">' + (Out-EtrText $sec.reason) + '</div>') }
                    if ($sec.method) { [void]$body.Append('<div class="method">How: ' + (Out-EtrText $sec.method) + '</div>') }
                    foreach ($c in (Get-EtrArray $sec.caveats)) { if ($c) { [void]$body.Append('<div class="method">Caveat: ' + (Out-EtrText $c) + '</div>') } }
                    $rows = @(Get-EtrArray $sec.rows)
                    if ($rows.Count) {
                        $cells = @($rows | ForEach-Object { ,@((Out-EtrText $_.group), (Out-EtrText $_.check), (Out-EtrText $_.result), (Out-EtrText $_.basis), ('<span class="pill ' + (Get-EtrStatusClass ([string]$_.status)) + '">' + (Get-EtrStatusLabel ([string]$_.status)) + '</span>'), (Out-EtrText $_.detail)) })
                        [void]$body.Append((New-EtrTable -Headers @('Area', 'Check', 'Result', 'Basis', 'Status', 'What it means') -Rows $cells))
                    }
                    if ($collapsed -contains $o.key -and $rows.Count -gt 5) {
                        [void]$sb.Append($head + '<details><summary>Show ' + $rows.Count + ' rows</summary>' + $body.ToString() + '</details>')
                    } else {
                        [void]$sb.Append($head + $body.ToString())
                    }
                }
                [void]$sb.Append('</section>')
            }

            # ---- actions ----
            [void]$sb.Append('<section><h2 id="actions">Actions taken</h2>')
            $acts = @(Get-EtrArray $Report.actions)
            if ($acts.Count -eq 0) {
                [void]$sb.Append('<p>No actions were run in this session. Every result above is read-only.</p>')
            } else {
                $arows = @($acts | ForEach-Object {
                    $whoA = [string]$_.by; if ($_.technician) { $whoA = ('{0} (technician: {1})' -f $whoA, $_.technician) }
                    ,@((Out-EtrText (Format-EtrTime $_.startedUtc $zone 'd MMM HH:mm')), (Out-EtrText $whoA), (Out-EtrText $_.server), ('<span class="mono">' + (Out-EtrText $_.command) + '</span>'),
                       ('<span class="pill ' + $(if ($_.ok) { 'ok">Done' } else { 'fail">Failed' }) + '</span>'), (Out-EtrText $_.output)) })
                [void]$sb.Append((New-EtrTable -Headers @('When', 'Who', 'Server', 'Command', 'Result', 'Output') -Rows $arows))
            }
            [void]$sb.Append('</section>')

            # ---- known limits ----
            $lim = @(Get-EtrArray $Report.knownLimits)
            if ($lim.Count) {
                [void]$sb.Append('<section><h2 id="limits">What this report cannot see</h2><ul>')
                foreach ($l in $lim) { [void]$sb.Append('<li>' + (Out-EtrText $l) + '</li>') }
                [void]$sb.Append('</ul></section>')
            }
        } else {
            [void]$sb.Append('<p class="note">Summary report. The full technical detail is in the toolkit''s JSON report and can be generated as a separate HTML file.</p>')
        }

        [void]$sb.Append('<footer>Generated ' + (Get-Date -Format 'd MMM yyyy HH:mm') + ' by Exchange Toolkit report generator ' + $script:EtrVersion +
            ' from an ' + (Out-EtrText $Report.schema) + ' v' + (Out-EtrText $Report.schemaVersion) + ' report. Times are shown in ' + (Out-EtrText $zone.Id) + '.</footer>')
        [void]$sb.Append('</div><script>window.addEventListener("beforeprint",function(){var d=document.querySelectorAll("details");for(var i=0;i<d.length;i++){d[i].open=true;}});</script></body></html>')
        return $sb.ToString()
    } finally {
        $script:EtrRedactor = $null
    }
}

function Get-EtrOutputDir {
    $d = Join-Path $PSScriptRoot 'Output'
    try {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $d ('.write-test-' + [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($probe, ''); Remove-Item -LiteralPath $probe -Force
        return $d
    } catch { }
    $d2 = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Exchange-Toolkit\Output'
    New-Item -ItemType Directory -Path $d2 -Force | Out-Null
    return $d2
}

function Save-EtrReport {
    # Parse, build, write UTF-8 without a BOM. Returns the HTML path.
    param([string]$Text, [string]$Title = '', [bool]$IncludeDetail = $true, [bool]$Redact = $false, [string]$OutDir = '')
    $r = Get-EtrReportJson -Text $Text
    if (-not $OutDir) { $OutDir = Get-EtrOutputDir }
    $name = $Title; if (-not $name) { $name = [string]$r.target.target }; if (-not $name) { $name = [string]$r.host.computerName }
    if ($Redact) { $name = 'redacted' }
    $suffix = $(if ($IncludeDetail) { '' } else { '-summary' })
    $path = Join-Path $OutDir ('ExchangeReport-{0}{1}-{2}.html' -f (Get-EtrSlug $name), $suffix, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $html = Build-EtrHtml -Report $r -Title $Title -IncludeDetail $IncludeDetail -Redact $Redact
    [System.IO.File]::WriteAllText($path, $html, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

if ($NoGui) { return }

# -----------------------------------------------------------------------------
# GUI
# -----------------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

if (-not $NoHideConsole) {
    try {
        if (-not ('EtrNative.Win' -as [type])) {
            Add-Type -Namespace 'EtrNative' -Name 'Win' -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[DllImport("user32.dll")]   public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
'@
        }
        $hc = [EtrNative.Win]::GetConsoleWindow()
        if ($hc -ne [System.IntPtr]::Zero) { [void][EtrNative.Win]::ShowWindow($hc, 0) }
    } catch { }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = ('Exchange Toolkit - HTML report ' + $script:EtrVersion)
$form.Size = New-Object System.Drawing.Size(900, 640)
$form.MinimumSize = New-Object System.Drawing.Size(700, 420)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$top = New-Object System.Windows.Forms.Panel
$top.Dock = 'Top'; $top.Height = 66
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'Client / site:'; $lblTitle.Location = New-Object System.Drawing.Point(8, 12); $lblTitle.AutoSize = $true
$txtTitle = New-Object System.Windows.Forms.TextBox
$txtTitle.Location = New-Object System.Drawing.Point(90, 9); $txtTitle.Size = New-Object System.Drawing.Size(250, 24)
$chkDetail = New-Object System.Windows.Forms.CheckBox
$chkDetail.Text = 'Include technical detail'; $chkDetail.Checked = $true; $chkDetail.AutoSize = $true
$chkDetail.Location = New-Object System.Drawing.Point(360, 11)
$chkRedact = New-Object System.Windows.Forms.CheckBox
$chkRedact.Text = 'Hide client details'; $chkRedact.Checked = $false; $chkRedact.AutoSize = $true
$chkRedact.Location = New-Object System.Drawing.Point(530, 11)
$tips = New-Object System.Windows.Forms.ToolTip
$tips.SetToolTip($chkDetail, 'Off: a short summary for the client - overall result, what needs attention, what could not be checked.')
$tips.SetToolTip($chkRedact, 'Replaces server, domain and user names, internet domains, IP addresses and certificate thumbprints with placeholders. Skim the result before sharing.')
$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Text = 'Paste the report from the toolkit''s JSON report tab (with or without the <<<ETK_JSON_BEGIN>>> lines), or browse to the saved .json:'
$lblHint.Location = New-Object System.Drawing.Point(8, 42); $lblHint.AutoSize = $true
$lblHint.ForeColor = [System.Drawing.Color]::DimGray
$lblHint.UseMnemonic = $false
$top.Controls.AddRange(@($lblTitle, $txtTitle, $chkDetail, $chkRedact, $lblHint))

$paste = New-Object System.Windows.Forms.TextBox
$paste.Multiline = $true; $paste.ScrollBars = 'Both'; $paste.WordWrap = $false; $paste.Dock = 'Fill'
$paste.Font = New-Object System.Drawing.Font('Consolas', 9)
$paste.MaxLength = 0

$bottom = New-Object System.Windows.Forms.Panel
$bottom.Size = New-Object System.Drawing.Size($form.ClientSize.Width, 72)
$bottom.Dock = 'Bottom'
$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = 'Browse JSON...'; $btnBrowse.Location = New-Object System.Drawing.Point(8, 8); $btnBrowse.Size = New-Object System.Drawing.Size(120, 28)
$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = 'Clear'; $btnClear.Location = New-Object System.Drawing.Point(134, 8); $btnClear.Size = New-Object System.Drawing.Size(80, 28)
$btnGen = New-Object System.Windows.Forms.Button
$btnGen.Text = 'Generate report'; $btnGen.Size = New-Object System.Drawing.Size(160, 28); $btnGen.Anchor = 'Top,Right'
$btnGen.Location = New-Object System.Drawing.Point(($bottom.Width - 170), 8)
$btnGen.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(8, 44); $lblStatus.Size = New-Object System.Drawing.Size(($bottom.Width - 130), 20); $lblStatus.Anchor = 'Top,Left,Right'
$lblStatus.ForeColor = [System.Drawing.Color]::DimGray
$lblStatus.Text = ('Reports save to: ' + (Get-EtrOutputDir))
$lnkOpen = New-Object System.Windows.Forms.LinkLabel
$lnkOpen.Text = ''; $lnkOpen.Size = New-Object System.Drawing.Size(110, 20); $lnkOpen.Anchor = 'Top,Right'
$lnkOpen.Location = New-Object System.Drawing.Point(($bottom.Width - 118), 44)
$bottom.Controls.AddRange(@($btnBrowse, $btnClear, $btnGen, $lblStatus, $lnkOpen))

$form.Controls.Add($paste)
$form.Controls.Add($top)
$form.Controls.Add($bottom)

$state = @{ LastPath = ''; AutoTitle = '' }

$paste.Add_TextChanged({
    # Offer the report's own server name while the box is empty or still
    # holds the last name it filled in.
    try {
        $r = Get-EtrReportJson -Text $paste.Text
        $n = [string]$r.target.target; if (-not $n) { $n = [string]$r.host.computerName }
        if ($n -and (-not $txtTitle.Text.Trim() -or $txtTitle.Text -eq $state.AutoTitle)) { $txtTitle.Text = $n; $state.AutoTitle = $n }
    } catch { }
})
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $dlg.InitialDirectory = (Get-EtrOutputDir)
    if ($dlg.ShowDialog($form) -eq 'OK') {
        try { $paste.Text = [System.IO.File]::ReadAllText($dlg.FileName) }
        catch { [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Could not read the file', 'OK', 'Error') }
    }
})
$btnClear.Add_Click({ $paste.Clear(); $txtTitle.Clear(); $state.AutoTitle = ''; $lnkOpen.Text = '' })
$btnGen.Add_Click({
    try {
        $title = $txtTitle.Text.Trim()
        if ($chkRedact.Checked -and $title -eq $state.AutoTitle) { $title = '' }   # the auto-filled server name would defeat redaction
        $path = Save-EtrReport -Text $paste.Text -Title $title -IncludeDetail $chkDetail.Checked -Redact $chkRedact.Checked
        $state.LastPath = $path
        $lblStatus.Text = ('Saved: ' + $path)
        $lnkOpen.Text = 'Open report'
        if ([System.Windows.Forms.MessageBox]::Show(("Report saved to:`n$path`n`nOpen it now?"), 'Done', 'YesNo', 'Information') -eq 'Yes') { Start-Process $path }
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Could not generate the report', 'OK', 'Error')
    }
})
$lnkOpen.Add_LinkClicked({ if ($state.LastPath -and (Test-Path -LiteralPath $state.LastPath)) { Start-Process $state.LastPath } })

[void]$form.ShowDialog()
