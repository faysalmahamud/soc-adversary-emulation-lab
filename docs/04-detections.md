# Behavioral Detection Guide

Run searches over a narrow time range around each test. These detections do not
search for the word `Atomic`. Copy-ready versions are in `spl/detections/`.

## T1053.005 - Scheduled Task

Primary signal: Sysmon Event ID 1 records `schtasks.exe` process creation and
the full task-creation command line.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\schtasks.exe"
| where match(lower(CommandLine), "(?i)(/create|-create)")
| table _time host User Image CommandLine ParentImage ProcessId
| sort - _time
```

Likely false positives: legitimate administrator task deployment and software
updaters. Investigate the task name, action, user, parent process, and schedule.

## T1218.005 - Mshta

Primary signal: Event ID 1 exposes suspicious `mshta.exe` arguments. Event ID 3
can corroborate an outbound connection made by `mshta.exe`.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\mshta.exe"
| where match(lower(CommandLine), "(?i)(https?://|javascript:|vbscript:|\\.hta)")
| table _time host User Image CommandLine ParentImage ProcessId
| sort - _time
```

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 Image="*\\mshta.exe"
| table _time host User Image DestinationHostname DestinationIp DestinationPort
| sort - _time
```

Likely false positives: legacy enterprise applications using local HTA files.
Remote URLs, script schemes, unusual parents, and user-writable paths increase
confidence.

## T1003.001 - LSASS Memory

Primary signal: Event ID 10 records a source process opening `lsass.exe`.
Unlike a process-name-only search, this still identifies the behavior if a dump
tool is renamed.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(lower(SourceImage), "(?i)\\\\windows\\\\system32\\\\(csrss|wininit|services|svchost|wmiprvse)\\.exe$")
| table _time host User SourceImage TargetImage GrantedAccess CallTrace SourceProcessId
| sort - _time
```

Likely false positives: security products and diagnostic tools. Validate source
signature, path, user, access mask, and surrounding process activity.

## T1059.001 - PowerShell Download

Primary signal: Event ID 1 captures PowerShell's command line. Event ID 3
corroborates an outbound connection.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where match(lower(CommandLine), "(?i)(invoke-webrequest|iwr\\s|downloadstring|downloadfile|net\\.webclient|start-bitstransfer|iex\\s*\\()")
| table _time host User Image CommandLine ParentImage ProcessId
| sort - _time
```

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time host User Image DestinationHostname DestinationIp DestinationPort
| sort - _time
```

Likely false positives: administrative scripts and software deployment. Review
the parent process, account, destination, encoded content, and execution policy.

## T1112 - Defender Registry Modification

Primary signal: Event ID 13 records the registry value and data written.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13 TargetObject="*\\Microsoft\\Windows Defender*"
| where match(lower(TargetObject), "(?i)(disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection)")
| table _time host User Image TargetObject Details ProcessId
| sort - _time
```

Likely false positives: authorized security-policy deployment. Validate the
change-control context, process path, user, and written value.

## Why These Event IDs

| Event ID | Name | Assignment value |
|---:|---|---|
| 1 | Process creation | Full process and parent command lines |
| 3 | Network connection | Process-linked destination evidence |
| 10 | Process access | Direct evidence of access to LSASS memory |
| 13 | Registry value set | Exact security-policy value modification |

Sysmon timestamps use UTC. Splunk renders `_time` according to the user/profile
time zone, so document the time zone used in the report.
