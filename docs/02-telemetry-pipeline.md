# Sysmon and Splunk Universal Forwarder

## 1. Install Sysmon

On Windows Server, download Sysmon from Microsoft Sysinternals. Copy
`configs/sysmon/sysmon-assignment.xml` to the extracted Sysmon directory, then
open PowerShell as Administrator:

```powershell
.\Sysmon64.exe -accepteula -i .\sysmon-assignment.xml
.\Sysmon64.exe -c
Get-Service Sysmon64
```

If Sysmon is already installed, update it:

```powershell
.\Sysmon64.exe -c .\sysmon-assignment.xml
```

Verify events in Event Viewer:

```text
Applications and Services Logs
  Microsoft
    Windows
      Sysmon
        Operational
```

Event ID 3 network logging and Event ID 10 process-access logging can be noisy.
The included configuration limits them to behaviors needed by this assignment.

## 2. Install the Universal Forwarder

Install Splunk Universal Forwarder on Windows Server using the official MSI:

1. Run the installer as Administrator.
2. Use the default installation path.
3. Skip Deployment Server for this two-VM lab.
4. Set the receiving indexer to `192.168.150.132:9997`.
5. Finish installation and verify the `SplunkForwarder` service is running.

Copy the repository configurations:

```text
configs/splunk/inputs.conf
  -> C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf

configs/splunk/outputs.conf.example
  -> C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf
```

Confirm the receiving server in `outputs.conf`, then restart:

```powershell
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' restart
Get-Service SplunkForwarder
```

## 3. Validate End to End

In Splunk Search & Reporting, set the time picker to **Last 15 minutes**:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count latest(_time) AS latest_event BY host EventCode
| convert ctime(latest_event)
| sort - count
```

Then verify required fields:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| table _time host User Image CommandLine ParentImage
| head 20
```

Do not begin emulation until live Sysmon events appear and process-creation
events include `Image` and `CommandLine`.

## Troubleshooting

Use the forwarder's built-in checks:

```powershell
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' list forward-server
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' btool inputs list --debug
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' btool outputs list --debug
```

- `renderXml=true` is important for reliable Sysmon field extraction.
- Confirm the channel name exactly matches
  `Microsoft-Windows-Sysmon/Operational`.
- Confirm the index exists before forwarding.
- Check Windows and Linux clocks; Sysmon timestamps are recorded in UTC.
