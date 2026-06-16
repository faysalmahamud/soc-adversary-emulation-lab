# Adversary Emulation and Detection Lab

An original, reproducible SOC lab for CSE 802 Information Security and
Cryptography. The lab collects Windows Server 2019 Sysmon telemetry in Splunk
Enterprise and detects five MITRE ATT&CK techniques emulated with Atomic Red
Team.

Final report: [REPORT.md](REPORT.md)

## Assignment Coverage

| Requirement | Implementation |
|---|---|
| Two-VM NAT lab | Ubuntu/Kali Splunk server and Windows Server 2019 target |
| Splunk Enterprise receiving on TCP 9997 | [Infrastructure runbook](docs/01-infrastructure.md) |
| Sysmon and Universal Forwarder | [Telemetry runbook](docs/02-telemetry-pipeline.md) and [configs](configs/) |
| Invoke-AtomicRedTeam setup | [Emulation runbook](docs/03-emulation.md) |
| Five required attacks and behavioral detections | [Detection guide](docs/04-detections.md) and [SPL files](spl/detections/) |
| Active-log Splunk dashboard | [Dashboard guide](docs/05-dashboard.md) and [panel SPL](spl/dashboard-panels.spl) |
| Final report with screenshots | [REPORT.md](REPORT.md) |

## Architecture

```text
                         NAT lab network
+-------------------------+       TCP/9997       +--------------------------+
| Windows Server 2019     | -------------------> | Ubuntu/Kali Linux         |
|                         |                      |                          |
| Atomic Red Team         |                      | Splunk Enterprise        |
| Sysmon                  |                      | index=main                |
| Universal Forwarder     |                      | Search and Dashboard     |
+-------------------------+                      +--------------------------+
     Attack + telemetry                                 Detection
```

Actual lab allocation:

| VM | CPU | RAM | Network |
|---|---:|---:|---|
| Kali Splunk server | 4 cores | 8 GB | NAT |
| Windows Server 2019 target | 4 cores | 8 GB | NAT |

Use static DHCP reservations or record both VM addresses before configuration.
Do not expose Splunk management or forwarding ports to the public internet.

## Detection Matrix

The detections search for technical behavior, never the word `Atomic`.

| MITRE ATT&CK | Required behavior | Primary Sysmon event | Detection evidence |
|---|---|---:|---|
| T1053.005 Scheduled Task | `schtasks.exe` task creation | 1 | Process, full command line, user, time |
| T1218.005 Mshta | `mshta.exe` loading HTA/script content | 1; corroborate with 3 | Process, argument/URL, destination, time |
| T1003.001 LSASS Memory | Non-system process opening `lsass.exe` | 10 | Source process, target, access mask, time |
| T1059.001 PowerShell | PowerShell download or in-memory execution | 1; corroborate with 3 | Process, download command, destination, time |
| T1112 Modify Registry | Defender policy value modification | 13 | Registry path, value written, process, time |

## Execution Order

1. Build the NAT-only VMs and take clean snapshots.
2. Install Splunk Enterprise, confirm `main`, and enable TCP receiver
   `9997` using [docs/01-infrastructure.md](docs/01-infrastructure.md).
3. Install Sysmon and the Universal Forwarder using
   [docs/02-telemetry-pipeline.md](docs/02-telemetry-pipeline.md).
4. Prove live ingestion before emulation:

   ```spl
   index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
   | stats count latest(_time) AS latest_event BY host EventCode
   | convert ctime(latest_event)
   ```

5. Install Invoke-AtomicRedTeam, inspect each test, check prerequisites, run one
   selected test, capture evidence, and clean up.
6. Run the matching search from [spl/detections/](spl/detections/).
7. Build the dashboard, capture the required screenshots, and complete the
   report checklist.

## Repository Layout

```text
configs/
  splunk/inputs.conf             Windows Sysmon input
  splunk/outputs.conf.example    Forwarding destination example
  sysmon/sysmon-assignment.xml   Focused lab telemetry policy
docs/
  01-infrastructure.md
  02-telemetry-pipeline.md
  03-emulation.md
  04-detections.md
  05-dashboard.md
spl/
  dashboard-panels.spl
  detections/
```

## References

- [Assignment-provided Sysmon configuration source](https://github.com/SwiftOnSecurity/sysmon-config)
- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Invoke-AtomicRedTeam documentation](https://github.com/redcanaryco/invoke-atomicredteam/wiki)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Splunk Enterprise documentation](https://help.splunk.com/)
