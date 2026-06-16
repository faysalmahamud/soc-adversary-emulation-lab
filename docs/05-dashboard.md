# Splunk Dashboard

Create a Classic Dashboard named **Adversary Emulation and Detection Overview**.
Use a time-range input and set the default to **Last 24 hours**. The searches
below are also collected in `spl/dashboard-panels.spl`.

## Recommended Panels

### 1. Total Sysmon Events

Visualization: Single Value

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count AS "Total Sysmon Events"
```

### 2. Latest Event by Host

Visualization: Table

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count latest(_time) AS latest_event BY host
| convert ctime(latest_event)
| rename latest_event AS "Latest Event"
```

### 3. Sysmon Event Distribution

Visualization: Column Chart

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count BY EventCode
| sort - count
```

### 4. Recent Process Creations

Visualization: Table

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| table _time host User Image CommandLine ParentImage
| sort - _time
| head 20
```

### 5. Required-Technique Indicators

Visualization: Table

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(
  (EventCode=1 (Image="*\\schtasks.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe"))
  OR (EventCode=10 TargetImage="*\\lsass.exe")
  OR (EventCode=13 TargetObject="*\\Microsoft\\Windows Defender*")
)
| eval technique=case(
    EventCode=10, "T1003.001 LSASS access",
    EventCode=13, "T1112 Defender registry",
    like(lower(Image), "%\\schtasks.exe"), "T1053.005 Scheduled task",
    like(lower(Image), "%\\mshta.exe"), "T1218.005 Mshta",
    like(lower(Image), "%\\powershell.exe") OR like(lower(Image), "%\\pwsh.exe"), "T1059.001 PowerShell",
    true(), "Review"
  )
| eval evidence=coalesce(CommandLine, TargetObject, TargetImage)
| table _time host technique Image evidence User
| sort - _time
```

## Dashboard Evidence

Capture one screenshot that visibly shows:

- the dashboard title and selected time range;
- active event totals;
- the Windows host;
- recent process events;
- event-code distribution;
- required-technique indicators.

Use a recent time range so the dashboard visibly proves active log ingestion.
