# 🕵️ Use Case 08 — Encoded / Obfuscated Command Detection

---

## 📌 Scenario

Attackers often **hide their commands** using encoding or obfuscation to evade detection.

Examples:

* Base64 encoded PowerShell
* Obfuscated scripts
* Hidden execution commands

👉 In your dataset: `command="encoded_command"` simulates this.

---

## 🎯 Objective

Detect:

* Encoded commands
* Hidden/obfuscated execution
* Suspicious command patterns

---

## 🧰 Environment Details

* Tool: Splunk Enterprise
* Index: `practicelog`
* Key Fields:

  * process
  * command
  * user
  * src_ip

---

## 📊 Step 1 — Identify Encoded Commands

```spl id="ec1"
index=practicelog command="encoded_command"
| stats count by user, src_ip
```

---

## 🧠 Learning

👉 Direct detection of encoded activity

---

## 🔍 Step 2 — View Raw Encoded Events

```spl id="ec2"
index=practicelog command="encoded_command"
| table timestamp user src_ip process command
```

---

## 🧪 Step 3 — Combine with PowerShell

```spl id="ec3"
index=practicelog process="powershell.exe" command="encoded_command"
| stats count by user, src_ip
```



---

## 🧠 Logic

👉 PowerShell + encoded = 🔥 HIGH RISK

---

## 🔥 Step 4 — Frequency-Based Detection

```spl id="ec4"
index=practicelog command="encoded_command"
| stats count by user
| where count > 2
```

---

## ⚡ Step 5 — Rare Encoded Usage (Anomaly)

```spl id="ec5"
index=practicelog command="encoded_command"
| stats count by user
| eventstats avg(count) as avg_count
| where count < avg_count
```
## without where condition



---

## 🧠 Insight

👉 Even **single encoded usage** can be suspicious

---

## 🔗 Step 6 — Correlate Login + Encoded Execution

```spl id="ec6"
index=practicelog 
(event_type=successful_login OR command="encoded_command")
| stats 
    count(eval(event_type="successful_login")) as logins,
    count(eval(command="encoded_command")) as encoded_exec
    by user, src_ip
| where encoded_exec > 0
```

---

## 🧠 Meaning

👉 User logs in → executes encoded command

---

## ⏱️ Step 7 — Sequence Detection

```spl id="ec7"
index=practicelog
| sort 0 user, timestamp
| streamstats last(command) as prev_command by user
| where command="encoded_command" AND prev_command!="encoded_command"
```

---

## 🧠 Why This Matters

👉 Detects **first appearance of encoded behavior**

---

## 📊 Step 8 — Timeline View

```spl id="ec8"
index=practicelog command="encoded_command"
| table timestamp user src_ip process
| sort timestamp
```

---

## 🔹 Step 9 — Top Users Running Encoded Commands

```spl id="ec9"
index=practicelog command="encoded_command"
| top user
```

---

## 🔹 Step 10 — Encoded Commands by Process

```spl id="ec10"
index=practicelog command="encoded_command"
| stats count by process
```

---

## 🔹 Step 11 — Filter Using Wildcards

```spl id="ec11"
index=practicelog
| search command="*encoded*"
```

---

## 🔹 Step 12 — Use `eval` for Risk Scoring

```spl id="ec12"
index=practicelog
| eval risk=if(command="encoded_command","high","low")
| stats count by user, risk
```

---

## 🔹 Step 13 — Group Multiple Values

```spl id="ec13"
index=practicelog command="encoded_command"
| stats values(src_ip) as ips by user
```

---

## 🔹 Step 14 — Unique Encoded Users

```spl id="ec14"
index=practicelog command="encoded_command"
| stats dc(user) as unique_users
```

---

## 🔹 Step 15 — Deduplicate Encoded Events

```spl id="ec15"
index=practicelog command="encoded_command"
| dedup user
| table user src_ip
```

---

## 🔹 Step 16 — Use `where` with Multiple Conditions

```spl id="ec16"
index=practicelog process="powershell.exe" command="encoded_command"
| stats count by user
| where count >= 1
```

---

## 🔹 Step 17 — Sort High-Risk Activity

```spl id="ec17"
index=practicelog command="encoded_command"
| stats count by user
| sort - count
```

---

## 🕵️ Investigation Process

When alert triggers:

1. Which user executed encoded command?
2. Was PowerShell used?
3. Did this happen after login?
4. Any privilege escalation after?
5. Same behavior across multiple users?

---

## ❌ False Positives

* Admin scripts
* Automation tools
* Dev/test environments

---

## 🧭 MITRE ATT&CK Mapping

* T1027 — Obfuscated/Encoded Files
* T1059 — Command Execution
* T1140 — Deobfuscate/Decode

---

## 🧾 Conclusion

Encoded command detection helps uncover hidden attacker activity that bypasses simple monitoring.

It is a key indicator of advanced threats.

---

## 🚀 Key Learning Outcome

* Learned obfuscation detection
* Practiced wildcard search, `values`, `dc`, `sort`
* Built anomaly + behavior correlation
* Strengthened detection mindset

---
