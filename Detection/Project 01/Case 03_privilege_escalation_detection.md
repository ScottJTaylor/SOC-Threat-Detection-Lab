# 🔐 Use Case 03 — Privilege Escalation Detection

---

## 📌 Scenario

An attacker gains initial access as a normal user and then attempts to **elevate privileges** to admin/root level.

👉 This is called **Privilege Escalation** and is a critical attack stage.

---

## 🎯 Objective

Detect events where:

* A user attempts or gains elevated privileges
* Activity indicates movement from normal user → admin-level access

---

## 🧰 Environment Details

* Tool: Splunk Enterprise
* Index: `practicelog`
* Source: `splunk_synthetic_logs.csv`
* Sourcetype: `csv`

---

## 📊 Step 1 — Explore Privilege Events

```spl id="c1b7zv"
index=practicelog event_type=privilege_escalation
| stats count by user, src_ip
```
## Snapshot:


---

## 🔍 Step 2 — Inspect Raw Events

```spl id="j2k9lm"
index=practicelog event_type=privilege_escalation
| table timestamp user src_ip process command
```
## Snapshot:


---

## 🧪 Step 3 — Basic Detection Query

```spl id="p4n8rt"
index=practicelog event_type=privilege_escalation
| stats count by user, src_ip
```

---

## 🧠 Step 4 — Detection Logic Explained

* `event_type=privilege_escalation` → Direct indicator
* Count occurrences per user and IP

👉 Meaning:

> A user attempting privilege escalation is inherently suspicious

---

## 🔥 Step 5 — Add Context (User Risk)

```spl id="z7q2xs"
index=practicelog event_type=privilege_escalation
| stats count by user
| sort - count
```

## Snapshot:



👉 Helps identify:

* Which user is attempting escalation most

---

## ⚡ Step 6 — Detect Suspicious Non-Admin Behavior

```spl id="t6w3yb"
index=practicelog event_type=privilege_escalation
| where user!="admin"
| stats count by user, src_ip
```

## Snapshot:



👉 Focus:

> Non-admin users attempting escalation = HIGH RISK

---

## ⏱️ Step 7 — Add Timeline

```spl id="g5u1pa"
index=practicelog event_type=privilege_escalation
| stats 
    min(timestamp) as first_seen,
    max(timestamp) as last_seen,
    count
    by user, src_ip
```
## Snapshot:



---

## 🔍 Step 8 — Correlate With Login Activity

```spl id="k8v0dn"
index=practicelog 
(event_type=successful_login OR event_type=privilege_escalation)
| stats 
    count(eval(event_type="successful_login")) as logins,
    count(eval(event_type="privilege_escalation")) as escalations
    by user, src_ip
| where escalations > 0
```
## Snapshot:



👉 This shows:

* Who logged in and then escalated privileges

👉 What if escalation happens without login?

It could indicate missing logs, exploitation without authentication, or activity outside the time window. 


---

## 🧠 Why This Is Powerful

👉 You are correlating:

* Authentication → Privilege change

This is exactly how attackers behave:

> “Login → Escalate → Take control”

---

## 🕵️ Step 9 — Investigation Process

When alert triggers:

1. Is user supposed to have admin rights?
2. Was escalation expected (IT admin activity)?
3. What happened after escalation?

   * Process execution
   * File access
4. Same IP used elsewhere?

---

## 🚨 Step 10 — Alert Configuration

* Trigger: privilege escalation event detected
* Severity: High
* Frequency: Real-time

---

## 🧭 Step 11 — MITRE ATT&CK Mapping

* T1068 — Exploitation for Privilege Escalation
* T1078 — Valid Accounts

---

## ❌ Step 12 — False Positives

* Legitimate admin activity
* System updates or installations
* IT maintenance tasks

---


## 🧾 Step 13 — Conclusion

Privilege escalation detection identifies attempts to gain higher-level access, which is a key step in attacker progression.

Early detection helps prevent full system compromise.

---

## 🚀 Key Learning Outcome

* Learned how to detect privilege escalation events
* Understood importance of user role context
* Practiced correlation between login and escalation
* Built SOC-level detection logic

---

## Author: Scott Taylor
