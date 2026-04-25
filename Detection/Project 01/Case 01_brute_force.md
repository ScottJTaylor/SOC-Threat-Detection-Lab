# 🔐 Brute Force Detection

## 🎯 Objective

Detect multiple failed login attempts from a single source.

---

## 📊 Log Source

Splunk synthetic dataset: ''splunk_synthetic_logs.csv''
Index: `practicelog`

---

## 🔎 SPL Query

```spl
index=practicelog event_type=failed_login
| stats count by src_ip, user
| where count > 5
```

---

## 🧠 Detection Logic

Multiple failed login attempts indicate potential brute force attack.

---

## 🧭 MITRE ATT&CK

* T1110 — Brute Force

---

## 🚨 Alert Configuration

* Trigger: count > 5
* Severity: High

---

## 🕵️ Investigation Steps

* Identify source IP
* Check if login succeeded
* Analyze targeted accounts

---

## ❌ False Positives

* User forgot password
* System retries

---

## 📸 Screenshots

