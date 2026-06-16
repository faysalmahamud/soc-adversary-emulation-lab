# Infrastructure Setup

## 1. Build the Lab

Create two VMs in VMware Workstation Pro or Oracle VirtualBox. Put both on the
same NAT network. Do not use bridged networking for this lab.

| Role | Operating system | CPU | RAM | Disk |
|---|---|---:|---:|---:|
| SIEM | Kali Linux | 4 | 8 GB | 100 GB |
| Target | Windows Server 2019 Desktop Experience | 4 | 8 GB | 80 GB |

This allocation is higher than the assignment minimum and gives Splunk,
Sysmon, and Atomic Red Team more room to run smoothly.

Recorded lab values:

```text
SIEM hostname: kali
SIEM IPv4: 192.168.150.132
Splunk URL: http://kali:8000
Windows hostname: WIN-NRK6CVIIP4J
Windows IPv4: 192.168.150.133
Hypervisor: VMware Workstation
Network mode: NAT
```

Validation from Windows:

```powershell
Test-NetConnection 192.168.150.132 -Port 9997
```

This test succeeds only after the Splunk receiver is enabled.

## 2. Install Splunk Enterprise on Ubuntu/Kali

Download the current Linux `.deb` package from Splunk using an account created
for the lab. Then run from the package directory:

```bash
sudo dpkg -i splunk-*.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start -user splunk
```

Open `http://kali:8000` from the host browser and sign in with the
administrator account created during first start.

## 3. Create the Index and Receiver

In Splunk Web:

1. Go to **Settings > Indexes**.
2. Confirm the default index `main` exists.
3. Go to **Settings > Forwarding and receiving > Configure receiving**.
4. Add TCP port `9997`.

CLI equivalents:

```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth '<admin>:<password>'
sudo /opt/splunk/bin/splunk restart
```

The CLI examples show syntax only; Splunk Web is preferable for the report.

## 4. Verify the Receiver

On the Linux SIEM:

```bash
sudo ss -lntp | grep 9997
sudo /opt/splunk/bin/splunk status
```

Capture screenshots showing:

- both VM hardware/network settings:
  `screenshots/kali-vm-config.png` and
  `screenshots/Windows Server2029 VM config.png`;
- both VM IP addresses;
- Splunk Web home page;
- `main` index;
- receiver listening on `9997`.

## Troubleshooting

- Confirm both VMs are on the same NAT network and can ping each other.
- Check the Linux firewall permits TCP `9997` only from the NAT subnet.
- Ensure port `8000` is used for Splunk Web and `9997` for forwarder traffic.
- If resources are tight, stop unnecessary services and increase VM RAM.
