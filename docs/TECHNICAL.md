# Exchange Toolkit - technical notes

> The full reference. The [README](../README.md) has the short version. The test suite described in the private copy is not part of this release.

A single-file WinForms tool (Windows PowerShell 5.1) for quick checks on an **on-premises Exchange Server**. Run it on the server, or point it at one from a workstation.

```
Launch-Exchange-Toolkit.cmd          (run elevated on the server)
```

## Why it exists

A single Exchange 2019 server (also the site's only domain controller) needed restarting every morning. Queues, back pressure and component state all looked healthy. It took two days of one-off commands to show the trouble was on the **disk path**, not in Exchange:

- **Snapshots on the Exchange volumes:**
  - EDR rollback snapshots every 4 hours
  - "Previous Versions" tasks snapshotting the **database volume** at 07:00, inside the morning rush
- **Backup software:**
  - filter drivers from more than one backup product in every disk write
  - a file-level backup agent trying to copy the live `.edb` all day
  - the Exchange VSS writer stuck on *Retryable error*
- **Log history:** event logs so small that the Security log covered less than a day.

None of that shows up from the Exchange cmdlets. This tool puts those checks next to the Exchange ones.

## Design stance (shared with the SMTP Toolkit, NetSpeed and 3CX Checker)

- **It never invents an answer.** A check that could not run says *why* (`unsupported` / `skipped` / `failed`, with a reason), and its area shows as **not measured** rather than green.
- **The Basis column** says how each row was arrived at: `measured`, `server-reported`, `inference`, `registry` or `not measured`. Product names guessed from service names, and snapshot owners guessed from timing, are marked **inference**.
- **Checks never change anything.** *Run all* only reads.
- **Actions are separate and guarded** (see below).

## Overall indicator

**After any run, a badge at the top right shows the result from every tab:** **PROBLEMS FOUND** (red), **WARNINGS** (amber), **NO PROBLEMS FOUND** (green) or **NOT MEASURED** (grey).
- It reflects the worst *measured* area. It's deliberately not a 0-100 score.
- Its tooltip, and the line next to the Overview headline, give the counts behind it, for example "1 with problems, 2 with warnings, 5 not measured".
- Click it to open the Overview.

**Each check tab's header is coloured by its worst result.**

**"Clear" (green) is only claimed when everything in an area ran.** If part of an area couldn't run (no elevation, or Exchange not connected), the area shows as not measured, names what didn't run, and isn't counted as clear. A problem found in the rest of that area still shows. A check skipped because the product isn't installed (no CrashPlan, for example) doesn't block green.

## Tabs

| Tab | What it checks |
|---|---|
| **Overview** | <ul><li>Verdict per area (worst measured result; no score)</li><li>Windows, hardware/VM, co-located roles (DC, Hyper-V)</li><li>CPU/RAM, commit, real page file</li><li>Exchange product and build, support status, days since the last CU/SU (date of `ExSetup.exe`)</li><li>Last restarts and who or what started them (1074 / 6008 / 41)</li></ul> |
| **Health** | <ul><li>Exchange and IIS services; `Test-ServiceHealth`</li><li>Inactive server components (ForwardSyncDaemon and ProvisioningRps are expected)</li><li>Databases: mounted, size, content index, log-folder file count</li><li>IIS/SMTP and Auth certificate expiry; MSExchange app pools</li><li>Disk space; memory and DB cache hit rate</li><li>Event-log retention</li><li>Event signals for the look-back window: back pressure, slow ESE I/O, crashes, Watson, ADAccess, 1035 SMTP AUTH failures, unclean shutdowns, Managed Availability recoveries</li><li>Log noise: one source flooding a log</li><li>A 10-second disk-latency sample</li></ul> |
| **Mail flow** | <ul><li>Queues (including poison)</li><li>Back pressure now, parsed from `Get-ExchangeDiagnosticInfo`</li><li>Message-tracking throughput in 10-minute buckets, with receive-to-delivery latency per *distinct* message</li><li>MessageRetryInterval / MaxPerDomainOutboundConnections</li><li>Receive and send connectors</li></ul> |
| **Storage & backup** | <ul><li>Last Exchange-aware backup per database</li><li>VSS writers</li><li>Shadow copies per volume: persistent? on an Exchange volume? cadence inferred from creation times</li><li>Volume filter drivers, identified from the driver file's own vendor metadata</li><li>Backup and snapshot software, with overlap warnings</li><li>SentinelOne's snapshot setting (`agent.vssSnapshots`), read from the agent's own configuration with `SentinelCtl.exe configure`, so it's measured rather than inferred from snapshot timing. Read-only; no passphrase needed. The key name comes from agent 25.2.6.442.</li><li>CrashPlan selecting Exchange files</li><li>**Schedule timeline**: every non-Microsoft scheduled task plus the `ShadowCopyVolume{GUID}` tasks, mapped to drive letters and sorted by time of day</li></ul> |
| **Security** | <ul><li>**Failed logins by source address** over the look-back window, merged from SMTP AUTH (1035), Windows (4625) and IIS **401.1** (bad password; 401.2 is the normal NTLM challenge and isn't counted). Public addresses with 10+ failures warn, and 100+ public failures make the summary warn and say to close the port</li><li>**Logons**: console and RDP (4624 types 2/10/11) by account and source. RDP from a public address **fails**, and so does a success from an address that also had repeated failures</li><li>**Exposure**: RDP on/off and NLA, firewall profiles, and listening ports outside Windows/AD/Exchange matched against inbound allow rules (an any-address rule warns)</li><li>**Copy public IPs**, and an opt-in **Look up locations...** (see below)</li><li>Security log, IIS logs and firewall rule filters need elevation; without it those parts say "not read" and the area isn't counted as clear</li></ul> |
| **Fix** | <ul><li>Every Exchange and IIS service (plus WinRM, the search host and the Exchange backup extension) with **Start / Stop / Restart**; stopped automatic services shown in red</li><li>Quick fixes: **start every stopped automatic service** (AD Topology first), **recycle the MSExchange app pools**, **IIS reset** (`/noforce`)</li><li>**Run HealthChecker**: Microsoft's CSS-Exchange checker, downloaded and signature-checked (see below)</li></ul> |
| **Evidence** | <ul><li>Export a time window to `Output\Evidence_<server>_<time>\`: Application/System CSV, an error timeline (the noisiest source left out), message tracking CSV plus buckets, IIS W3SVC1/2 lines (the UTC conversion is done for you) with a status-code summary, and HttpProxy logs</li><li>**Performance capture**: start/stop a `logman` collector (disk latency and queue, process CPU and I/O, memory, RPC latency, DB cache)</li></ul> |
| **JSON report** | <ul><li>Schema `exchange-toolkit-report` v1, wrapped in `<<<ETK_JSON_BEGIN>>>` / `<<<ETK_JSON_END>>>` markers</li><li>Save to `Output\` or copy to the clipboard</li><li>**HTML report...**: full, full with client details hidden, or summary only (see below)</li></ul> |

### What the Schedule timeline flags

**Amber (warn):** jobs that put load on the disk path, or shut the server down:
- anything that restarts or shuts down the server
- any snapshot of a volume holding the database, its logs or the transport queue
- backup, sync, snapshot and defrag jobs (and anything similar) that run inside the **busy window** (default 05:00-09:00)

**Noted, but left uncoloured:** ordinary tasks inside the window, such as an updater checking in.

**Timing rules:**
- A task that repeats more often than the window is long counts as running inside it.
- A one-off trigger that already ran is never "inside the window".
- Logon and boot triggers get no invented time of day.

## Actions

Rows with a **●** in the *Act* column offer an action. Right-click the row, or use **Actions for selected row…**. The **Fix** tab offers the service controls and quick fixes at any time, without running a check first. Every action:

1. **shows its exact command first**, which you can also just *Copy command* and run yourself;
2. **needs a confirmation**; a high-risk action also needs the server name typed in;
3. **is refused by the engine without that confirmation token.** The UI is not the only guard;
4. **is appended to `Output\Actions_<server>.log`** and to the report's `actions[]`;
5. **runs alone.** Nothing is chained, and the tab is not re-run for you;
6. **needs your name when the tool runs as a shared account:** SYSTEM (Backstage, an RMM), another NT AUTHORITY account, or the built-in Administrator (detected by RID 500, so renaming it doesn't hide it).
   - The name is asked once per session and logged as `DOMAIN\administrator (technician: <name>)`.
   - The engine refuses the action without it.
   - Reason: an action log that only says "Administrator" can't answer "who did this". On the server this tool was built for, identifying a 07:07 Administrator logon took a trawl through the Security log.

| Action | Risk |
|---|---|
| Start a service | low |
| Start / restart a service | medium |
| Start every stopped automatic Exchange/IIS service (AD Topology first, then Service Host, then by name; reports each one) | medium |
| Recycle an MSExchange app pool, or all of them in turn | medium |
| IIS reset (`iisreset /noforce`) | medium |
| Stop a service (`-Force`, so its dependents stop too; the dialog says what users lose) | **high** |
| Mount a database | medium |
| Set a server component Active (Functional or Maintenance requester) | medium |
| Retry / suspend / resume a queue | low |
| Enlarge event logs (Application/System to 1 GB, Security to 2 GB; never shrinks one) | low |
| Disable / enable a `ShadowCopyVolume` (Previous Versions) task | low |
| Start / stop the performance capture | low |
| Delete **one** shadow copy by ID (EDR products may block it) | **high** |

**Service actions only reach a fixed list**, checked by the engine: `MSExchange*`, `MSComplianceAudit`, `HostControllerService`, `wsbexchange`, `W3SVC`, `WAS`, `IISADMIN` and `WinRM`. Anything else, such as `Spooler` or an EDR agent, is refused even with a valid confirmation. The Fix tab's service list refreshes itself after a service action; it's a read-only view, so this doesn't break the "runs alone" rule.

**Deliberately not offered:**
- uninstalling drivers
- deleting all shadow copies
- changing authentication or IIS settings
- blocking IPs. A spray rotates its addresses, so the Security tab points at closing the port instead; **Copy public IPs** is there if you want to block at the router.

## HealthChecker (Microsoft CSS-Exchange)

**Run HealthChecker...** on the Fix tab:
1. downloads the latest `HealthChecker.ps1` from `https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1` into a new `Output\HealthChecker_<server>_<time>\` folder;
2. **runs it only if Windows reports a Valid Authenticode signature from Microsoft Corporation.** Anything else is deleted and refused, including the unsigned repo source, which reports itself as an "unsigned test build";
3. opens a new PowerShell window that loads the Exchange Management Shell (`RemoteExchange.ps1` + `Connect-ExchangeServer -auto`; the snap-in under SYSTEM or if that fails), runs HealthChecker, then builds its HTML report (`-BuildHtmlServersReport`) in the same folder. The window stays open.

Rules:
- **On the Exchange server only, elevated.** It's refused for a remote target, on a machine without Exchange, or without elevation.
- **Online only.** If github.com and objects.githubusercontent.com can't be reached, it says so; there's no option to use a local copy.
- **`-SkipVersionCheck` is passed on purpose.** The file was just downloaded and its signature checked; HealthChecker's self-update would otherwise replace it after that check.
- HealthChecker only reads. Each run is still logged in the action log and `actions[]` as `css-healthchecker`, with the version and signer.

Checked on a dev PC (no Exchange) on 24 Oct 2026: the download (3 s, version 26.10.13.1644) passed the signature rule, and every parameter the tool passes exists in the right parameter set.

## Local and remote

- **Exchange checks** use a remote PowerShell session to `http://<fqdn>/PowerShell/` (Kerberos), importing only the cmdlets the tool needs. This works the same on the server and from a workstation.
  - **Fallback on the server only:** the management snap-in, which bypasses RBAC. The target bar says so when it is in use.
- **OS checks** run directly when the target is this machine. Otherwise the engine text is sent with `Invoke-Command` (WinRM) and the *same* functions run on the server.
  - OS checks never call Exchange cmdlets, so there is no second-hop credential problem.
- **Running as SYSTEM** (ScreenConnect Backstage, an RMM):
  - Remote PowerShell is **skipped**, because it would sign in as the computer account, which Exchange normally refuses. The tool goes straight to the management snap-in, and the Target bar says so.
  - **Remote targets aren't available as SYSTEM:** the computer account has no rights on another server. Run the tool on that server instead.
  - Untick "Allow snap-in fallback" and it will try remote PowerShell anyway, with a warning that it usually fails.
- **On an Exchange server the tool connects at start-up.**
- **It removes its Exchange session when it closes.** An abandoned session keeps long-polling `/PowerShell` (3-minute requests in IIS) and logs MSExchange RBAC 74 "connection leak" events.
- **Without elevation**, VSS, shadow copies, the Security log and IIS say *unsupported (needs an elevated session)*. The **Restart as administrator** button relaunches the tool elevated.

## HTML report

`Generate-ExchangeReport.ps1` (started by `Launch-Exchange-Report.cmd`) turns one JSON report into a single self-contained HTML file: no external scripts, styles or fonts, so it can be emailed or printed as is. It needs no admin rights and no Exchange. The toolkit's **HTML report...** button does the same thing without leaving the tool; it needs the generator file next to the toolkit.

The file has two parts:
- **Summary, for the client:** an overall tile, area tiles, "What needs attention" (problems first, then warnings, capped at 15) and "Not checked in this run", with each reason.
- **Technical detail:** every section in the toolkit's own tab order, with its state, method, caveats and rows. Long sections collapse and open when printed. Then the actions taken and what the report can't see.

The generator never recomputes a verdict. It shows the one recorded in the JSON, so the HTML can't disagree with the tool. Times are shown in the server's own time zone (`host.timeZone`, which older reports don't have; they fall back to this PC's zone). The footer names the zone used.

GUI options:
- **Client / site name:** the title. It defaults to the server name.
- **Include technical detail:** on by default. Off gives a summary-only page for the client.
- **Hide client details:** off by default. It replaces server, domain and user names, internet domains, IP addresses and certificate thumbprints with placeholders (`EX-SERVER`, `example.local`, `DOMAIN\user1`, `example1.com`, `x.x.x.1`, `<thumbprint>`). Built-in names such as `administrator` and `NT AUTHORITY\SYSTEM` stay readable. **Skim the result before sharing it:** free text such as event messages, task names and file paths can mention things the rules don't recognise, and the page says so.

Output goes to `Output\` next to the generator (Documents if that isn't writable), as `ExchangeReport-<server|redacted>[-summary]-<time>.html`.

## IP locations (opt-in, third party)

Nothing in the Security checks leaves the server. **Look up locations...** is the one exception, and it only runs when you press it:
- it lists every public address it will send, and where each one was seen (failed logins, logons), then asks;
- it sends each address to **ipapi.co** in a separate HTTPS request, from the PC running the tool. Private and invalid addresses are refused before any request is made, and at most 50 go per run;
- it stops at ipapi.co's rate limit and says how far it got;
- results appear as an *IP locations* section (an estimate, often right only to the country). They're not part of the verdict;
- each run goes in the action log and `actions[]` as `ip-lookup`, with the count and who ran it.

A logon address may be the client's own or a technician's, and the dialog says so.

Checked against the real service on 24 Oct 2026, with one request for `1.1.1.1`. The reply carried `country_name`, `region`, `city`, `org` and `asn` as expected. `1.1.1.1` is an anycast address, so where it "is" depends on where you ask from: a good reminder that the location is an estimate.

## Known limits

The tool can't see these, so a clean result doesn't cover them:

- **Every check is a snapshot.** Use the schedule timeline and the perf capture for time-of-day problems.
- **AV/EDR exclusions** cannot be read from outside the product.
- **VSS writers** are parsed from English `vssadmin` output; any other language reports *unsupported*.
- **Performance counter names are localised**: on a non-English server, disk latency reports *unsupported*.
- **Message tracking is capped** (50k rows for the check, 100k for evidence); the section says so when the cap is hit.
- **The SMTP certificate can't be identified** when `Get-ExchangeCertificate` returns a blank `Services` field, which it did through remote PowerShell on the live 2019 CU15 server. The IIS certificate is read from IIS itself instead, and the section says the field was blank.
- **CrashPlan's log format is undocumented.** On the live server:
  - `I` lines carried a file size and block hashes, meaning the file was read and backed up, including the whole 250 GB live database.
  - `W` lines carried neither, most likely meaning the file couldn't be opened.

  The tool reports the two separately.
- **Security sees the server, not the router.** A port open in Windows Firewall is only reachable from the internet if the router forwards it, and the router's forwards can't be read from here. In the case that prompted this tool, the 7777 forward was only visible on the Draytek.
- **Behind NAT, a reverse proxy or an RD Gateway**, a recorded source address may be the router's or the gateway's. If every failure comes from one internal address, the Failed logins section says so.
- **SMTP AUTH failures (1035) don't record the account tried**, only the address and connector.
- **Security log reads are capped** at the newest 20,000 failures and 5,000 logons; IIS logs are read newest-first for up to 30 s. Each section says when a cap was hit.
- **IIS logs are read from `C:\inetpub\logs\LogFiles`.** If they've been moved, the section says no logs were found, rather than reporting no failures.

## Tests

The offline regression suite (376 checks, no Exchange needed: parsers, verdict roll-up, action safety, the HealthChecker signature rule, the HTML report and its redaction) is not part of this release: its fixtures were sanitised from a real case.

## Verified, and not yet

**First live run (24 Oct 2026):** Exchange 2019 CU15, elevated, local, connected through remote PowerShell. Every section measured. It found:
- 4-hourly persistent snapshots on C:, D: and E:
- the Previous Versions tasks (already disabled by then)
- `stcvsm` in the filter stack and as log noise
- the Exchange Writer *Retryable error*
- CrashPlan selecting the live database
- the 05:15 reboot task

That run exposed nine bugs, all now fixed and covered by tests:
1. back pressure read as "unknown" (real element names differ)
2. the IIS certificate missed, because the `Services` field was blank
3. the database counted as transaction logs
4. the transport queue path came back empty from `Get-TransportService`
5. snapshot volumes split by a trailing backslash
6. duplicate restart rows
7. the build date labelled as the install date
8. a Health Manager crash treated as severe
9. a 58-second CrashPlan read

**Second live run, same day:** all nine fixes confirmed, including the IIS certificate (now found) and the transaction logs (132 files, 132 MB). It also showed that CrashPlan had **read the entire live database** (an `I` line), not just failed on it. The CrashPlan check now separates database reads from failed attempts.

**Third live run, same day:** the CrashPlan split, certificate wording and F: dates were all confirmed. CrashPlan had read the live database 549 times over 80 days. The new summary took 49 s at that volume (about 137k lines), so it was rewritten to take 0.3 s, and a test now guards it.

**Not verified yet:**
- the faster CrashPlan summary on the live server
- the SentinelOne setting check on the live server (it should now report `agent.vssSnapshots` as off)
- remote mode from a workstation
- running as SYSTEM under Backstage: the snap-in route and the technician prompt are tested offline only
- any action on a real server (only the refusal paths have been tested)
- the HTML report from a live server's JSON, plain and redacted (checked so far on this PC's own run: layout, print expansion, and no computer or user name in the redacted copy)
- print preview in a real browser (the open-on-print script was triggered in code, not printed)
- the Fix tab on the live server: the service list, any start/stop/restart, the quick fixes, and the auto-refresh afterwards
- the Security tab elevated, on any machine: run here (not elevated) it correctly reported the Security log and firewall filters as "not read" and read RDP and the firewall profiles. The 4624/4625 reading, IIS 401 parsing on real logs and the listener-vs-rule match have only run against synthetic data
- HealthChecker end to end on the live server, normally and under SYSTEM (snap-in). The download and signature were checked on a dev PC; the run itself needs Exchange

## Next (v2 candidates)

- **Clients tab:** Autodiscover SCP and vdir URLs vs certificate SANs, DNS per accepted domain, and workstation-side HTTPS probes. `Invoke-StHttpProbe` / `Test-StAutodiscover` from the SMTP Toolkit can be reused.
- **HTML report: before/after comparison** of two runs (v1 renders one run).

## Files

| Path | Purpose |
|---|---|
| `Exchange-Toolkit.ps1` | The tool. `#region ENGINE` holds everything the worker and remote servers run; `-EngineOnly` loads it for tests. |
| `Launch-Exchange-Toolkit.cmd` | Launcher: full-path `powershell.exe`, `-STA`, conhost so the console can be hidden on Windows 11. |
| `Generate-ExchangeReport.ps1` | HTML report generator (GUI; `-NoGui` loads the functions only). Kept pure ASCII. |
| `Launch-Exchange-Report.cmd` | Launcher for the generator, built the same way as the toolkit's. |
| `Output\` | Reports, evidence packs, action log (created on first use). |
