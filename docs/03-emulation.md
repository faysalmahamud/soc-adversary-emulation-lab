# Atomic Red Team Emulation

## Safety Gate

Run these tests only inside the isolated Windows lab VM.

1. Take a clean VM snapshot.
2. Confirm Splunk is receiving fresh Sysmon events.
3. Open PowerShell as Administrator.
4. Inspect a test before running it.
5. Run only one selected test at a time.
6. Capture output and detection evidence.
7. Run cleanup immediately.

Never run `Invoke-AtomicTest All`. Do not use personal or production systems.

## Install Invoke-AtomicRedTeam

Follow the current official Invoke-AtomicRedTeam installation documentation.
After installation, verify the module and atomics path:

```powershell
Import-Module Invoke-AtomicRedTeam
Get-Command Invoke-AtomicTest
$PSDefaultParameterValues["Invoke-AtomicTest:PathToAtomicsFolder"] = "C:\AtomicRedTeam\atomics"
```

Record the installed module version and atomics revision in the report:

```powershell
Get-Module Invoke-AtomicRedTeam | Select-Object Name, Version, Path
Get-Date -Format o
```

## Repeatable Test Workflow

Atomic test numbers and names can change. First list the available tests, then
select the Windows test that matches the assignment behavior. Record its exact
name and GUID in the evidence log.

```powershell
$Technique = "T1053.005"

Invoke-AtomicTest $Technique -ShowDetailsBrief
Invoke-AtomicTest $Technique -TestNumbers <NUMBER> -CheckPrereqs
Invoke-AtomicTest $Technique -TestNumbers <NUMBER> -GetPrereqs
Invoke-AtomicTest $Technique -TestNumbers <NUMBER>

# After screenshots and Splunk verification:
Invoke-AtomicTest $Technique -TestNumbers <NUMBER> -Cleanup
```

Using a test GUID is more reproducible because GUIDs do not change when test
ordering changes:

```powershell
Invoke-AtomicTest <TECHNIQUE> -TestGuids <GUID> -CheckPrereqs
Invoke-AtomicTest <TECHNIQUE> -TestGuids <GUID>
Invoke-AtomicTest <TECHNIQUE> -TestGuids <GUID> -Cleanup
```

## Required Emulations

| Order | Technique | Select a Windows test that demonstrates |
|---:|---|---|
| 1 | T1053.005 | Creating a scheduled task that runs a script or command |
| 2 | T1218.005 | Executing HTA or script content with `mshta.exe` |
| 3 | T1003.001 | Accessing/dumping LSASS memory with an approved lab tool |
| 4 | T1059.001 | Downloading content with PowerShell |
| 5 | T1112 | Modifying a Windows Defender policy registry value |

The assignment's T1112 requirement is narrower than generic registry
modification. Atomic definitions change over time and a current T1112 test may
modify a different registry path. Use `-ShowDetailsBrief` and select only a test
that actually changes a Windows Defender policy value. If none exists, do not
substitute an unrelated registry test and claim it meets the requirement; get
instructor approval before creating or running a custom Atomic test.

For every technique, capture:

- the `-ShowDetailsBrief` output with selected test name;
- the execution command and successful result;
- the matching Splunk detection result;
- the cleanup command and result;
- the UTC/local test time and selected test GUID.

## Notes

- Some tests require dependencies. Use `-CheckPrereqs` before `-GetPrereqs`.
- Windows Defender or tamper protection may block a test. Report the observed
  result honestly; do not weaken protections outside the disposable lab VM.
- An Atomic console message alone is not proof of detection. The corresponding
  Sysmon behavior must appear in Splunk.
- Revert to the clean snapshot if cleanup fails.
