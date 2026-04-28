# Setting Up a Splunk SIEM Home Lab Environment

Workflow used when building my Splunk SIEM lab at home for learning, detection engineering, and security monitoring practice.

---

## Phase 1 — Lab Architecture Plan

A well-rounded Splunk home lab typically includes:

| Component | Role |
|---|---|
| Splunk Enterprise | Central SIEM / indexer / search head |
| Universal Forwarder | Ships logs from endpoints to Splunk |
| Windows VM | Endpoint to generate Windows Event Logs |
| Linux VM | Endpoint to generate syslog/auth logs |
| Kali Linux | Attack simulation / red team actions |

---

## Phase 2 — Install a Hypervisor

1. Downloaded and installed **VMware Workstation Pro**: https://www.vmware.com/products/desktop-hypervisor.html
2. Created a **Host-Only Network Adapter** in VMware so my VMs can communicate internally:
   - Opened VMware → Edit → Virtual Network Editor → Add Network
   - Selected **Host-only** and note the subnet (e.g., `192.168.100.0/24`) — assigned IPs from this range
   - Ensured **DHCP** is enabled on the host-only network for easy IP assignment
3. Allocated resources carefully — planned my VM count before spinning anything up

---

## Phase 3 — Downloaded Splunk Enterprise

1. Accessed https://www.splunk.com and created my free account
2. Navigated to **Products → Free Trials & Downloads → Splunk Enterprise**
3. Downloaded the installer for my Splunk server

---

## Phase 4 — Set Up the Splunk Server VM

### 4.1 Created the VM
1. In VMware Workstation Pro, clicked **Create a New Virtual Machine**
2. Choose **Typical (recommended)** and selected my Rocky Server ISO
3. Set:
   - Name: `Splunk-Server`
   - RAM: 4–8 GB
   - Disk: 60 GB (Store virtual disk as a single file for better performance)
4. Before finishing, selected **Customize Hardware** and set the network adapter to **Host-only** adapter
5. Completed the Ubuntu Server OS installation

### 4.2 Install Splunk Enterprise (Linux)
```bash
# Moved the installer to /opt
sudo mv splunk-*.deb /opt/

# Installed
sudo dpkg -i /opt/splunk-*.deb

# Started Splunk and accept the license
sudo /opt/splunk/bin/splunk start --accept-license

# Enabled Splunk to start on boot
sudo /opt/splunk/bin/splunk enable boot-start
```

### 4.3 Access the Splunk Web Interface
1. From my host machine, navigated to: `http://<splunk-server-ip>:8000`
2. Logged in with the admin credentials you set during installation
3. Confirmed the Splunk home dashboard loads successfully

---

## Phase 5 — Configure Splunk to Receive Data

### 5.1 Enabled a Receiving Port
1. In Splunk Web → **Settings → Forwarding and Receiving**
2. Clicked **Configure Receiving → New Receiving Port**
3. Set port to **9997** (standard Splunk forwarder port)
4. Saved

### 5.2 Create Indexes for My Log Sources
Indexes organized data by source type:

1. Under **Settings → Indexes → New Index**
2. Created the following (one at a time):
   - `windows_logs` — for Windows Event Logs
   - `linux_logs` — for syslog / auth logs
   - `network_logs` — for firewall / router logs (optional)

---

## Phase 6 — Set Up a Windows Endpoint VM

### 6.1 Created the Windows VM
1. Downloaded a Windows 10/11 evaluation ISO from Microsoft
2. In VMware Workstation Pro, clicked **Create a New Virtual Machine**:
   - Name: `Win10-Endpoint`
   - RAM: 4 GB
   - Disk: 40 GB
3. Under **Customize Hardware**, set the network adapter to my **Host-only** adapter
4. Installed VMware Tools after Windows is up

### 6.2 Enable Windows Audit Policies
Increases log verbosity to have events to analyze:

1. Opened **Group Policy Editor** (`gpedit.msc`)
2. Navigated to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration`
3. Enabled (Success + Failure) for:
   - Account Logon
   - Account Management
   - Logon/Logoff
   - Object Access
   - Process Creation
   - Privilege Use

### 6.3 Enabled Sysmon
Sysmon dramatically improves process, network, and file event visibility:

```powershell
# Download Sysmon from Microsoft Sysinternals
# Download SwiftOnSecurity's config (my choice for a baseline)

# Install with config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

---

## Phase 7 — Install the Splunk Universal Forwarder

Install this on every endpoint you want to ship logs from.

### On the Windows endpoint VM:
1. Downloaded the Universal Forwarder from: https://www.splunk.com/en_us/download/universal-forwarder.html
2. Ran the `.msi` installer
3. During setup:
   - Set the **Deployment Server** (optional, skip for now)
   - Set **Receiving Indexer** to your Splunk server IP on port `9997`

### On the Linux endpoint VM:
```bash
sudo dpkg -i splunkforwarder-*.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
sudo /opt/splunkforwarder/bin/splunk add forward-server <splunk-server-ip>:9997
sudo /opt/splunkforwarder/bin/splunk enable boot-start
```

---

## Phase 8 — Configure Inputs on the Forwarder
Tell the forwarder *what* to collect and *where* to send it.

### On the Windows endpoint VM — Edited `inputs.conf`:
File location: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
index = windows_logs
disabled = 0

[WinEventLog://System]
index = windows_logs
disabled = 0

[WinEventLog://Application]
index = windows_logs
disabled = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = windows_logs
disabled = 0
```

Restart the forwarder after editing:
```powershell
Restart-Service SplunkForwarder
```

### On the Linux enpoint VM — Edited `inputs.conf`:
File location: `/opt/splunkforwarder/etc/system/local/inputs.conf`

```ini
[monitor:///var/log/auth.log]
index = linux_logs
sourcetype = linux_secure

[monitor:///var/log/syslog]
index = linux_logs
sourcetype = syslog
```

---

## Phase 9 — Verify Data Is Flowing into Splunk

1. In Splunk Web, traveresed to **Search & Reporting**
2. Run a basic search to confirm events are arriving:

```spl
index=windows_logs | head 50
```

```spl
index=linux_logs | head 50
```

3. I had no results, so I checked:
   - Forwarder service is running on the endpoint
   - Firewall on the Splunk server allows port 9997
   - Indexes were created correctly
   - `outputs.conf` on the forwarder points to the correct server/port

---

## Phase 10 — Build Useful Dashboards & Alerts

### Starter Searches I Saved

**Failed Logon Attempts (Event ID 4625):**
```spl
index=windows_logs EventCode=4625
| stats count by Account_Name, src_ip
| sort -count
```

**New Process Creation (Sysmon Event ID 1):**
```spl
index=windows_logs source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, Computer, User, Image, CommandLine, ParentImage
```

**PowerShell Execution:**
```spl
index=windows_logs EventCode=4688 New_Process_Name="*powershell*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
```

### Created a Dashboard
1. Ran one of the searches above
2. Clicked **Save As → Dashboard Panel**
3. Created a new dashboard called `Home Lab SOC`
4. Added multiple panels for a consolidated view

### Set Up an Alert
1. Ran a search (I chose failed logons)
2. Clicked **Save As → Alert**
3. Configured:
   - Trigger: Number of results > 5 within 15 minutes
   - Action: Log to Splunk (or email if configured)

---

## Phase 11 — Add MITRE ATT&CK Coverage

### Installed Splunk Security Essentials
1. In Splunk Web → **Apps → Find More Apps**
2. Searched for **Splunk Security Essentials**
3. Installed and configure it
4. This mapped my data to MITRE ATT&CK techniques and suggests detections

### Installed the MITRE ATT&CK App for Splunk
- Also available in the Splunk App catalog
- Provides a full ATT&CK matrix overlay showing which techniques you're covering

---

## Phase 12 — Simulate Attacks for Practice

Use your Kali Linux VM to generate realistic events:

| Simulation | Tool |
|---|---|
| Port scanning | `nmap -sV <windows-vm-ip>` |
| Failed SSH logins | `hydra -l root -P wordlist.txt ssh://<target>` |
| Mimikatz (Windows cred dump) | Invoke-Mimikatz in PowerShell |
| Atomic Red Team | Framework of ATT&CK-mapped tests |

**Atomic Red Team** is highly recommended for structured attack simulation:
```powershell
# Install (on Windows endpoint)
Install-Module -Name invoke-atomicredteam
Import-Module invoke-atomicredteam

# Run a specific ATT&CK technique (e.g., T1059 - Command Scripting)
Invoke-AtomicTest T1059.001
```

Then search Splunk for the resulting logs and build detections around them.

---

## Troubleshooting I Implemetnted

| Issue | Check |
|---|---|
| No data in Splunk | Forwarder service running? Port 9997 open? Index exists? |
| Forwarder won't connect | `outputs.conf` correct IP/port? Firewall rules? |
| Missing Windows events | Audit policy enabled? Sysmon installed? |
| Splunk won't start | Port 8000 in use? Check `/opt/splunk/var/log/splunk/splunkd.log` |
| License warning | Stay under 500 MB/day; reduce monitored log sources |

---

## Learning Resources

- **Splunk Fundamentals 1** — Free official course at education.splunk.com
- **Boss of the SOC (BOTS)** — Splunk's free CTF-style dataset for practice
- **LetsDefend* — Has Splunk-specific rooms and SOC analyst paths
- **Splunk Docs** — docs.splunk.com (reference for SPL and configuration)
- **SwiftOnSecurity Sysmon Config** — github.com/SwiftOnSecurity/sysmon-config
