# 🖥️ Use Case 06 — Suspicious Process Execution (Endpoint Detection)

---

## 📌 Scenario

Attackers often execute suspicious or malicious processes after gaining access.

Examples:

* `malware.exe`
* `powershell.exe` (for attacks)
* Unknown or rare processes

👉 Detecting unusual process execution is critical in SOC.

---

## 🎯 Objective

Detect:

* Suspicious or rare processes
* Abnormal process behavior
* Processes linked with attacks

---

## 🧰 Environment Details

* Tool: Splunk Enterprise
* Index: `practicelog`
* Key Fields:

  * process
  * user
  * src_ip
  * event_type
  * command

---

## 📊 Step 1 — Explore Process Activity

```spl id="r1a2b3"
index=practicelog event_type=process_execution
| stats count by process
| sort - count
```

---



## 🧠 Learning

👉 Understand:

* Most common processes
* Baseline behavior

---

## 🔍 Step 2 — View Raw Process Events

```spl id="r2b3c4"
index=practicelog event_type=process_execution
| table timestamp user src_ip process command
```

---

## 🧪 Step 3 — Detect Known Suspicious Process

```spl id="r3c4d5"
index=practicelog event_type=process_execution process="malware.exe"
| stats count by user, src_ip
```

---


## 🧠 Logic

👉 Known bad process = immediate alert

---

## 🔥 Step 4 — Detect PowerShell Usage

```spl id="r4d5e6"
index=practicelog event_type=process_execution process="powershell.exe"
| stats count by user, src_ip
```

---

## 🧠 Why Important

PowerShell is commonly abused for:

* File download
* Execution
* Persistence

---

## ⚡ Step 5 — Detect Encoded Commands

```spl id="r5e6f7"
index=practicelog process="powershell.exe" command="encoded_command"
| stats count by user, src_ip
```

---

## 🧠 Logic

Encoded commands = attempt to hide activity

---

## 🧠 Step 6 — Detect Rare Processes (Anomaly)

```spl id="r6f7g8"
index=practicelog event_type=process_execution
| stats count by process
| eventstats avg(count) as avg_count
| where count < avg_count
```

---

## 🧠 Learning

👉 Rare processes often indicate:

* Malware
* Custom attacker tools

---

## ⚡ Step 7 — Detect Process per User

```spl id="r7g8h9"
index=practicelog event_type=process_execution
| stats values(process) as processes by user
```

---


## 🧠 Meaning

👉 Which user runs which processes

---

## ⏱️ Step 8 — Timeline of Suspicious Processes

```spl id="r8h9i0"
index=practicelog event_type=process_execution
| sort 0 timestamp
| table timestamp user process src_ip
```

---

## 🔗 Step 9 — Correlate Login + Process Execution

```spl id="r9i0j1"
index=practicelog 
(event_type=successful_login OR event_type=process_execution)
| stats 
    count(eval(event_type="successful_login")) as logins,
    count(eval(event_type="process_execution")) as processes
    by user, src_ip
| where processes > 5
```

---

## 🧠 Why This Matters

👉 Detects:

> User logs in → executes many processes

Possible attacker activity.

---

# 🧠 EXTRA SPL PRACTICE

---

## 🔹 Step 10 — Top Processes

```spl id="r10j2k3"
index=practicelog event_type=process_execution
| top process
```

---

## 🔹 Step 11 — Process by User

```spl id="r11k3l4"
index=practicelog event_type=process_execution
| stats count by user, process
| sort - count
```

---

## 🔹 Step 12 — Filter Suspicious Processes

```spl id="r12l4m5"
index=practicelog event_type=process_execution
| search process="*malware*" OR process="powershell.exe"
| stats count by process
```

---


## 🔹 Step 13 — Use `where` for Filtering

```spl id="r13m5n6"
index=practicelog event_type=process_execution
| stats count by process
| where count > 5
```

---

## 🔹 Step 14 — Rename Fields (Better Readability)

```spl id="r14n6o7"
index=practicelog event_type=process_execution
| stats count by process
| rename process as "Process Name", count as "Execution Count"
```

---


## 🔹 Step 15 — Add Calculated Field (`eval`)

```spl id="r15o7p8"
index=practicelog event_type=process_execution
| eval risk_level = if(process ="malware.exe","high","medium")
| table process risk_level user
```

---


## 🔹 Step 16 — Use `dedup` (Remove Duplicates)

```spl id="r16p8q9"
index=practicelog event_type=process_execution
| dedup process
| table process
``` 
---
* dedup = remove duplicates, keep one
  * Unique values
  * remove duplicates

    
## 🔹 Step 17 — Count Unique Processes

```spl id="r17q9r0"
index=practicelog event_type=process_execution
| stats dc(process) as unique_processes by user
```

---

## 🕵️ Investigation Process

When alert triggers:

1. Is process known or unknown?
2. Is it executed by normal user or admin?
3. Is PowerShell used with encoding?
4. Is process executed after login?
5. Same process across multiple users?

---

## ❌ False Positives

* Legitimate admin tools
* Scripts and automation
* Software updates

---

## 🧭 MITRE ATT&CK Mapping

* T1059 — Command and Scripting Interpreter
* T1204 — User Execution
* T1106 — Execution

---

## 🧾 Conclusion

Suspicious process execution detection helps identify attacker activity at endpoint level.

Monitoring processes is essential to detect malware and unauthorized actions.

---

## 🚀 Key Learning Outcome

* Learned process-based detection
* Practiced `stats`, `eventstats`, `eval`, `dedup`, `top`
* Understood anomaly detection
* Built endpoint-level SOC skills

---
