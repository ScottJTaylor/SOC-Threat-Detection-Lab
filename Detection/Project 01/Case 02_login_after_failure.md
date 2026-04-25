# 🔐 Use Case 02 — Successful Login After Multiple Failures (Account Compromise)

---

## 📌 Scenario

An attacker attempts multiple logins using different passwords (brute force).
👉 This indicates a **potential account compromise**.

---

## 🎯 Objective

Detect cases where:

* Multiple failed login attempts occur
* Followed by a successful login
* From the same source IP and user

---

## 🧰 Environment Details

* Tool: Splunk Enterprise
* Index: `practicelog`
* Source: `splunk_synthetic_logs.csv`
* Sourcetype: `csv`

---

## 📊 Step 1 — Explore the Data

Understand what data is available before writing detection logic.

```spl
index=practicelog source="splunk_synthetic_logs.csv"
| stats count by event_type
```
## Snapshot



### 🔍 Expected Output

* All registed events will show.
* Check for:
    * failed_login
    * successful_login

👉 This confirms we have required authentication data.

---

## 📋 Step 2 — Inspect Raw Events

```spl
index=practicelog
(event_type="failed_login" OR event_type="successful_login")
| table timestamp user src_ip event_type EventCode
```
## Snapshot:



### 🧠 Learning

* `failed_login` → EventCode 4625
* `successful_login` → EventCode 4624

---

## 🧪 Step 3 — Build Basic Detection Logic

```spl
index=practicelog 
(event_type=failed_login OR event_type=successful_login)
| stats 
    count(eval(event_type="failed_login")) as failed,
    count(eval(event_type="successful_login")) as success
    by src_ip, user
| where failed > 5 AND success > 0
```


## 📸 Screenshots

With condition: where failed > 5 AND success > 0
No successful login registered.




With condition: where failed > 3 AND success > 0
Successful login registered, but this can be user error also.



---

## 🧠 Step 4 — Detection Logic Explained

* Count failed login attempts per user and IP
* Count successful logins
* Apply condition:

  * Failed attempts > 5
  * At least one successful login

👉 Meaning:

> Multiple failed attempts followed by success = possible compromise

---


## 📊 Step 5 — Add Timeline Context

```spl
index=practicelog 
(event_type=failed_login OR event_type=successful_login)
| stats 
    min(timestamp) as first_attempt,
    max(timestamp) as last_attempt,
    count(eval(event_type="failed_login")) as failed,
    count(eval(event_type="successful_login")) as success
    by src_ip, user
| where failed > 5 AND success > 0
```
## Snapshot:
CONDITION FAILED >3 AND SUCCESS>0



---

## 🔍 Step 6 — Analyze Results

From results, identify:

* Suspicious source IP
* Targeted user
* Time duration of attack

---

## 🕵️ Step 7 — Investigation Process

When alert is triggered:

1. Check if IP is internal or external
2. Verify if user is privileged (e.g., admin)
3. Look for activity after login:

   * Process execution
   * File access
4. Check if same IP targets multiple users

---

## 🚨 Step 8 — Alert Configuration

* Trigger Condition: Results > 0
* Severity: High
* Frequency: Real-time or every 5 minutes

---

## 🧭 Step 9 — MITRE ATT&CK Mapping

* T1110 — Brute Force
* T1078 — Valid Accounts

---

## ❌ Step 10 — False Positives

* User forgot password
* Multiple login attempts due to typo
* Automated system retries

---



## 🧾 Step 11 — Conclusion

This detection identifies potential account compromise by correlating:

* Failed authentication attempts
* Followed by successful access

It helps SOC analysts detect brute force attacks that succeed.

---

## 🚀 Key Learning Outcome

* Learned how to correlate multiple event types
* Understood sequence-based detection
* Built real-world SOC detection logic
* Practiced SPL using `stats` and `streamstats`

---
