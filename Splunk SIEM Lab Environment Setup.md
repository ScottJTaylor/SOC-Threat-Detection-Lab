## 🔐 Setting Up a Splunk SIEM Home Lab Environment

My step-by-step to building a functional Splunk SIEM lab at home for learning, detection engineering, and security monitoring practice.

---

## 🗺️ Phase 1 — Lab Architecture

| Component | Role |
|---|---|
| Splunk Enterprise (Ubuntu Server) | Central SIEM / indexer / search head |
| Universal Forwarder | Ships logs from endpoints to Splunk |
| Windows 11 | Endpoint used to generate Windows desktop event logs |
| Windows Server 2025 | Endpoint used to generate Windows server event logs |
| Ubuntu Linux | Endpoint used to generate syslog/auth logs |
| Kali Linux | Used for attack simulation / red team actions |

---

## 🖥️ Phase 2 — Hypervisor Setup

1. **VMware Workstation Pro** was downloaded and installed from: https://www.vmware.com/products/desktop-hypervisor.html
   - A Broadcom account was created to access the free personal use download
2. A **Host-Only Network Adapter** was created in VMware so VMs could communicate internally:
   - VMware → Edit → Virtual Network Editor → Add Network was opened
   - **Host-only** was selected and the subnet `192.168.100.0/24` was noted
   - **DHCP** was enabled on the host-only network for easy IP assignment
3. Resources were allocated carefully before any VMs were spun up

---

## 📦 Phase 3 — Splunk Enterprise Was Downloaded

1. My free account was created at https://www.splunk.com
2. Navigated to **Products → Free Trials & Downloads → Splunk Enterprise**
3. The Linux `.deb` installer was downloaded for the Splunk server on the host machine

---

## 🐧 Phase 4 — The Splunk Server VM Was Set Up

### 4.1 🔧 The SOC Slunk Server VM Was Created in VMware

1. Start with **Create a New Virtual Machine**
2. **Typical (recommended)** was chosen and the Ubuntu Server ISO was selected
3. The following was configured:
   - Name: `SOC-Splunk-Server`
   - RAM: 8 GB
   - Disk: 60 GB (stored as a single file for better performance)
4. **Customize Hardware** was clicked and the network adapter was set to the **Host-only** adapter
5. **Finish** was clicked — VMware booted the VM from the ISO automatically

---

### 4.2 🛠️ Ubuntu Server Was Installed via the CLI

#### Network Configuration
- The installer attempted DHCP automatically on the Host-only adapter
- The proxy address was left blank as the network did not require one

#### Storage Configuration
- **Use an entire disk** was selected
- The 60 GB VMware virtual disk was confirmed as the target
- LVM was left enabled (default) to allow easy disk expansion later

#### SSH Setup
- **Install OpenSSH server** was checked using Space
- This allowed SSH access from the host machine, eliminating the need to use the VMware console window going forward

#### Featured Snaps
- All optional snaps were skipped as they are not needed

#### Installation
- The installer copied files and configured the system
- **Reboot Now** was selected upon completion

---

### 4.3 🔄 First Boot & Post-Install CLI Configuration

#### System Was Updated
The system was updated before anything else was installed:
```bash
sudo apt update && sudo apt upgrade -y
```

#### Static IP Was Configured
A static IP was set to prevent Splunk's web address from changing between reboots.

The network interface name was identified first:
```bash
ip a
```
The interface `ens33` was found showing the current IP.

The Netplan configuration was edited:
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

The contents were replaced with the following (interface name and IP substituted accordingly):
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.100.10/24
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

The configuration was applied:
```bash
sudo netplan apply
```

The static IP was verified as active:
```bash
ip a show ens33
```

#### Firewall (UFW) Was Configured
Only the ports Splunk required were opened:
```bash
# UFW was enabled
sudo ufw enable

# SSH was allowed to preserve remote access
sudo ufw allow 22/tcp

# Splunk Web UI port was opened
sudo ufw allow 8000/tcp

# Splunk forwarder data reception port was opened
sudo ufw allow 9997/tcp

# Splunk management port was opened
sudo ufw allow 8089/tcp

# Rules were confirmed as active
sudo ufw status verbose
```

#### VMware Tools Were Installed
```bash
sudo apt install open-vm-tools -y
```

#### Connectivity from the Host Was Verified
From the host machine, connectivity to the Splunk server was confirmed:

![Host Machine Connection](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Screenshot%202026-04-29%20154927.png)

Once SSH was working, the server was managed entirely from a terminal on the host machine — the VMware console window was no longer needed.

---

### 4.4 📥 Splunk Enterprise Was Installed

**Transferred from the host machine via SCP:**
```bash
# This was run on the HOST machine, not the VM
scp "X:\Home Labs\SOC Splunk Server\splunk-10.2.2-80b90d638de6-linux-amd64.deb" staylor@192.168.100.10:/tmp/

```

#### Splunk Was Installed and Configured
```bash
# The package was installed
sudo dpkg -i /tmp/splunk--10.2.2-80b90d638de6-linux-amd64.deb

# Navigated to Splunk's binary directory
cd /opt/splunk/bin

# Splunk was started for the first time and the license was accepted
# An admin username and password were created at this prompt
sudo ./splunk start --accept-license

# Splunk failed to auto-start for the first time
Warning: cannot create "/opt/splunk/etc/licenses/download-trial"

# Troubleshooting License Creation
ls -la /opt/splunk (File ownership was wrong)


# Splunk was enabled to start automatically on system boot
sudo ./splunk enable boot-start -user staylor
```

#### Splunk Was Verified as Running
```bash
sudo /opt/splunk/bin/splunk status
splunkd is running (PID: 1403248).
splunk helpers are running (PIDs: 1403253 1406463 1406468 1406671 1406726).

```

The listening ports were confirmed:
```bash
sudo ss -tlnp | grep splunk

```

```
LISTEN 0      4096       127.0.0.1:40833      0.0.0.0:*    users:(("splunk-cmp-orch",pid=1408187,fd=4))                 
LISTEN 0      4096       127.0.0.1:40397      0.0.0.0:*    users:(("splunk-spotligh",pid=1408750,fd=9))                 
LISTEN 0      4096       127.0.0.1:43017      0.0.0.0:*    users:(("splunk-postgres",pid=1407562,fd=3))                 
LISTEN 0      4096       127.0.0.1:35007      0.0.0.0:*    users:(("splunk-supervis",pid=1406468,fd=4))                 
LISTEN 0      4096       127.0.0.1:43271      0.0.0.0:*    users:(("splunk-cmp-orch",pid=1408187,fd=14))                
LISTEN 0      4096       127.0.0.1:35265      0.0.0.0:*    users:(("splunk-supervis",pid=1406468,fd=10))                
LISTEN 0      128          0.0.0.0:8089       0.0.0.0:*    users:(("splunkd",pid=1403248,fd=5))                         
LISTEN 0      4096       127.0.0.1:5435       0.0.0.0:*    users:(("splunk-postgres",pid=1407562,fd=11))                
LISTEN 0      128          0.0.0.0:8000       0.0.0.0:*    users:(("splunkd",pid=1403248,fd=194))                       
LISTEN 0      4096       127.0.0.1:45825      0.0.0.0:*    users:(("splunk-cmp-orch",pid=1408187,fd=15))                
LISTEN 0      4096       127.0.0.1:41353      0.0.0.0:*    users:(("splunk-spotligh",pid=1408750,fd=4))  
```
---

### 4.5 🌐 Splunk Web Interface

1. From the host machine browser was navigated to: `http://192.168.100.10:8000`

![Splunk Login](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Screenshot%202026-04-29%20230351.png)
 
2. Login was completed with the admin credentials set during the `splunk start` step
3. The Splunk home dashboard was confirmed as loading successfully

![Splunk Dashboard](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Screenshot%202026-04-29%20230559.png)


4. A **VMware Snapshot** was taken as a clean baseline before any configuration changes

---

## 📡 Phase 5 — Prep Splunk to Receive Data

### 5.1 🔌 A Receiving Port Was Enabled

1. Splunk Web → **Settings → Forwarding and Receiving** was opened
2. **Configure Receiving → New Receiving Port** was clicked
3. Port **9997** was set as the receiving port (standard Splunk forwarder port)
4. The configuration was saved

### 5.2 🗂️ Indexes Were Created for Log Sources

Indexes were created to organize data by source type:

1. **Settings → Indexes → New Index** was navigated to
2. The following indexes were created one at a time:
   - `windows_logs` — for Windows Event Logs
   - `linux_logs` — for syslog / auth logs
   - `network_logs` — for firewall / router logs

---

## 🪟 Phase 6 — A Windows 11 Endpoint VM Was Set Up

### 6.1 🔧 The Windows 11 VM Was Created

1. A free Windows 10/11 evaluation ISO was downloaded from Microsoft
2. In VMware **Create a New Virtual Machine** was clicked:
   - Name: `Win11-SOCLAB`
   - RAM: 4 GB
   - Disk: 40 GB
3. Under **Customize Hardware**, the network adapter was set to the **Host-only** adapter
4. VMware Tools were installed after Windows was up

### 6.2 📋 Windows Audit Policies Were Enabled

Log verbosity was increased to ensure useful events were available for analysis:

1. **Group Policy Editor** (`gpedit.msc`) was opened with the **Run** tool
2. The following path was navigated to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration`
3. Success + Failure was enabled for:
   - Account Logon
   - Account Management
   - Logon/Logoff
   - Object Access
   - Process Creation
   - Privilege Use

### 6.3 🔍 Sysmon Was Installed using PowerShell

```powershell
# Sysmon was downloaded from Microsoft Sysinternals
# SwiftOnSecurity's config was downloaded as a baseline

# Sysmon was installed with the config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

---

## 📤 Phase 7 — The Splunk Universal Forwarder Was Installed

The forwarder was installed on every endpoint logs were to be shipped from.

### On Windows:
1. The Universal Forwarder was downloaded from: https://www.splunk.com/en_us/download/universal-forwarder.html
2. The `.msi` installer was run
3. During setup:
   - The **Deployment Server** field was skipped
   - The **Receiving Indexer** was set to the Splunk server IP on port `9997`

### On Linux:
```bash
sudo dpkg -i splunkforwarder-*.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
sudo /opt/splunkforwarder/bin/splunk add forward-server <splunk-server-ip>:9997
sudo /opt/splunkforwarder/bin/splunk enable boot-start
```

---

## 📝 Phase 8 — Inputs Were Configured on the Forwarder

The forwarder was told what to collect and where to send it.

### On Windows — `inputs.conf` Was Edited:
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

The forwarder was restarted after editing:
```powershell
Restart-Service SplunkForwarder
```

### On Linux — `inputs.conf` Was Edited:
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

## ✅ Phase 9 — Data Flow into Splunk Was Verified

1. **Search & Reporting** was opened in Splunk Web
2. Basic searches were run to confirm events were arriving:

```spl
index=windows_logs | head 50
```

```spl
index=linux_logs | head 50
```

3. Where no results were returned, the following were checked:
   - Forwarder service was confirmed as running on the endpoint
   - Port 9997 was confirmed as open on the Splunk server firewall
   - Indexes were confirmed as created correctly
   - `outputs.conf` on the forwarder was confirmed as pointing to the correct server/port

---

## 📊 Phase 10 — Dashboards & Alerts Were Built

### Starter Searches Were Saved

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

### A Dashboard Was Created
1. One of the searches above was run
2. **Save As → Dashboard Panel** was clicked
3. A new dashboard was created called `Home Lab SOC`
4. Multiple panels were added for a consolidated view

### An Alert Was Set Up
1. A search was run (e.g., failed logons)
2. **Save As → Alert** was clicked
3. The following was configured:
   - Trigger: Number of results > 5 within 15 minutes
   - Action: Log to Splunk (or email if configured)

---

## 🎯 Phase 11 — MITRE ATT&CK Coverage Was Added

### Splunk Security Essentials Was Installed
1. Splunk Web → **Apps → Find More Apps** was opened
2. **Splunk Security Essentials** was searched for
3. The app was installed and configured
4. Data was mapped to MITRE ATT&CK techniques and detections were suggested

### The MITRE ATT&CK App for Splunk Was Installed
- The app was found in the Splunk App catalog
- A full ATT&CK matrix overlay was provided showing which techniques were being covered

---

## 💥 Phase 12 — Attacks Were Simulated for Practice

A Kali Linux VM was used to generate realistic events:

| Simulation | Tool |
|---|---|
| Port scanning | `nmap -sV <windows-vm-ip>` |
| Failed SSH logins | `hydra -l root -P wordlist.txt ssh://<target>` |
| Mimikatz (Windows cred dump) | Invoke-Mimikatz in PowerShell |
| Atomic Red Team | Framework of ATT&CK-mapped tests |

**Atomic Red Team** was used for structured attack simulation:
```powershell
# Installed on the Windows endpoint
Install-Module -Name invoke-atomicredteam
Import-Module invoke-atomicredteam

# A specific ATT&CK technique was run (e.g., T1059 - Command Scripting)
Invoke-AtomicTest T1059.001
```

Splunk was then searched for the resulting logs and detections were built around them.

---

## 🔧 Troubleshooting seen during the setup

| Issue | Check |
|---|---|
| No data in Splunk | Was the forwarder service running? Was port 9997 open? Did the index exist? |
| Forwarder wouldn't connect | Was `outputs.conf` pointing to the correct IP/port? Were firewall rules correct? |
| Missing Windows events | Was the audit policy enabled? Was Sysmon installed? |
| Splunk wouldn't start | Was port 8000 in use? `/opt/splunk/var/log/splunk/splunkd.log` was checked |
| License warning | Data was kept under 500 MB/day by reducing monitored log sources |

---

## 📚 Learning Resources

- **Splunk Fundamentals 1** — Free official course at education.splunk.com
- **Boss of the SOC (BOTS)** — Splunk's free CTF-style dataset for practice
- **LetsDefend** — Splunk-specific rooms and SOC analyst paths
- **Splunk Docs** — docs.splunk.com (reference for SPL and configuration)
- **SwiftOnSecurity Sysmon Config** — github.com/SwiftOnSecurity/sysmon-config
