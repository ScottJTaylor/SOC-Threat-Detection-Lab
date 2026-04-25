# ⚡ Use Case 07 — PowerShell Abuse Detection

---

## 📌 Scenario

Attackers use PowerShell to:

* Execute malicious scripts
* Download payloads
* Run encoded/hidden commands
* Maintain persistence

👉 PowerShell is powerful—and dangerous when abused.

---

## 🎯 Objective

Detect:

* PowerShell usage
* Encoded commands
* Abnormal PowerShell activity
* Suspicious patterns of execution

---

## 🧰 Environment Details

* Tool: Splunk Enterprise
* Index: `practicelog`
* Key Fields:

  * process
  * command
  * user
  * src_ip
  * event_type

---

## 📊 Step 1 — Identify PowerShell Activity

```spl id="ps1"
index=practicelog process="powershell.exe"
| stats count by user, src_ip
```

---

## 🧠 Learning

👉 Who is using PowerShell and how frequently

---

## 🔍 Step 2 — View Raw PowerShell Events

```spl id="ps2"
index=practicelog process="powershell.exe"
| table timestamp user src_ip command
```


---

## 🧪 Step 3 — Detect Encoded Commands (HIGH RISK)

```spl id="ps3"
index=practicelog process="powershell.exe" command="encoded_command"
| stats count by user, src_ip
```

---

## 🧠 Logic

👉 Encoded command = attempt to hide malicious activity

---

## 🔥 Step 4 — Frequency-Based Detection

```spl id="ps4"
index=practicelog process="powershell.exe"
| stats count by user
| where count > 5
```

---

## 🧠 Meaning

👉 User running PowerShell too often = suspicious

---

## ⚡ Step 5 — Rare PowerShell Usage

```spl id="ps5"
index=practicelog process="powershell.exe"
| stats count by user
| eventstats avg(count) as avg_count
| where count > avg_count
```
## without where condition:




## with where condition:


---

## 🧠 Why Important

👉 Rare usage can indicate:

* Sudden abnormal behavior
* First-time compromise

---

## 🔗 Step 6 — Correlate Login + PowerShell

```spl id="ps6"
index=practicelog 
(event_type=successful_login OR process="powershell.exe")
| stats 
    count(eval(event_type="successful_login")) as logins,
    count(eval(process="powershell.exe")) as ps_exec
    by user, src_ip
| where ps_exec > 3
```

---

## 🧠 Logic

👉 Login → PowerShell execution
= possible attacker behavior

---

## ⏱️ Step 7 — Sequence Detection (Advanced)

```spl id="ps7"
index=practicelog
| sort 0 user, timestamp
| streamstats last(process) as prev_process by user
| where process="powershell.exe" AND prev_process!="powershell.exe"
```

---

## 🧠 Why This Is Powerful

👉 Detects:

> PowerShell suddenly appearing in user activity

---

## 📊 Step 8 — Timeline Analysis

```spl id="ps8"
index=practicelog process="powershell.exe"
| table timestamp user src_ip command
| sort timestamp
```


---

## 🔹 Step 9 — Top PowerShell Users

```spl id="ps9"
index=practicelog process="powershell.exe"
| top user
```

---

## 🔹 Step 10 — PowerShell by IP

```spl id="ps10"
index=practicelog process="powershell.exe"
| top src_ip 

```

---

## 🔹 Step 11 — Filter Suspicious Commands

```spl id="ps11"
index=practicelog process="powershell.exe"
| search command="encoded_command"
```

---

## 🔹 Step 12 — Use `eval` for Risk Scoring

```spl id="ps12"
index=practicelog process="powershell.exe"
| eval risk=if(command="encoded_command","high","medium")
| table user process command risk
```



---

## 🔹 Step 13 — Count Unique Users Running PowerShell

```spl id="ps13"
index=practicelog process="powershell.exe"
| stats dc(user) as unique_users
```

---

## 🔹 Step 14 — Use `dedup` for Clean Results

```spl id="ps14"
index=practicelog process="powershell.exe"
| dedup user
| table user src_ip
```



---

## 🔹 Step 15 — Combine Filters 
```spl id="ps15"
index=practicelog process="powershell.exe" command="encoded_command"
| stats count by user, src_ip
| where count > 1
```


---

## 🕵️ Investigation Process

When alert triggers:

1. Is PowerShell expected for this user?
2. Is command encoded?
3. Did execution happen after login?
4. Any privilege escalation after this?
5. Same IP used by multiple users?

---

## ❌ False Positives

* Admin scripts
* Automation tools
* DevOps pipelines

---

## 🧭 MITRE ATT&CK Mapping

* T1059.001 — PowerShell
* T1027 — Obfuscated/Encoded Files
* T1055 — Process Injection

---

## 🧾 Conclusion

PowerShell abuse detection is critical because attackers use it extensively for stealthy operations.

Monitoring PowerShell helps detect execution, persistence, and lateral movement.

---

## 🚀 Key Learning Outcome

* Learned deep PowerShell detection
* Practiced `streamstats`, `eval`, `top`, `dc`, `dedup`
* Understood attacker techniques
* Built strong endpoint detection skills

---
