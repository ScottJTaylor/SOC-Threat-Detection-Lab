# 👑 Use Case 05 — Privileged Account Misuse

---

## 📌 Scenario

Privileged accounts (like `admin`) have **high-level access**.
If misused, they can:

* Change system settings
* Access sensitive data
* Disable security controls

👉 Attackers LOVE targeting admin accounts.

---

## 🎯 Objective

Detect:

* Suspicious activity performed by privileged users
* Admin performing unusual or risky actions

---

## 🧰 Environment Details

* Tool: Splunk Enterprise
* Index: `practicelog`
* Key Fields:

  * user
  * event_type
  * process
  * src_ip

---

## 📊 Step 1 — Identify Privileged Users

In our dataset:
👉 `admin` = privileged account

---

## 🔍 Step 2 — View All Admin Activity

```spl id="s1k2jd"
index=practicelog user="admin"
| stats count by event_type
```

---

## 🧠 Learning

👉 Understand:

* What actions admin is performing
* Baseline behavior

---

## 🧪 Step 3 — Detect Suspicious Admin Actions

```spl id="x9v2fa"
index=practicelog user="admin"
(event_type=privilege_escalation OR event_type=log_cleared OR event_type=suspicious_task)
| stats count by event_type, src_ip
```


---

## 🧠 Logic

👉 Admin doing:

* privilege escalation ❗
* log clearing ❗
* suspicious tasks ❗

= 🚨 HIGH RISK

---

## 🔥 Step 4 — Admin Activity from Multiple IPs

```spl id="p4r8lm"
index=practicelog user="admin"
| stats dc(src_ip) as ip_count,
        values(src_ip) as ips by user
| where ip_count > 1
```



---

## 🧠 Meaning

👉 Admin logged in from multiple IPs
→ Possible:

* Account sharing
* Credential compromise

---

## ⚡ Step 5 — Admin Performing Rare Actions

```spl id="t6z3vn"
index=practicelog user="admin"
| stats count by event_type
| eventstats avg(count) as avg_count
| where count < avg_count
```

---


## 🧠 Logic

👉 Rare actions = suspicious
(especially for admin)

---

## ⏱️ Step 6 — Admin Activity Timeline

```spl id="q7y5cx"
index=practicelog user="admin"
| table timestamp event_type src_ip process
| sort timestamp
```

---

## 🔍 Step 7 — Correlate Admin Login + Risky Activity

```spl id="u8m1wr"
index=practicelog user="admin"
(event_type=successful_login OR event_type=privilege_escalation OR event_type=log_cleared)
| stats 
    count(eval(event_type="successful_login")) as logins,
    count(eval(event_type="privilege_escalation")) as escalations,
    count(eval(event_type="log_cleared")) as log_clears
    by src_ip
| where escalations > 0 OR log_clears > 0
```

---

## 🧠 Why This Matters

👉 Detects:

> Admin logs in → performs risky action

This is a classic attacker pattern.

---

## 🚨 Step 8 — High Risk Detection

```spl id="n3k8op"
index=practicelog user="admin"
(event_type=privilege_escalation OR event_type=log_cleared)
| stats count by user, src_ip
```

---

## 🕵️ Step 9 — Investigation Process

When alert triggers:

1. Was admin activity expected?
2. Is IP known?
3. What happened after action?
4. Any login anomalies before?
5. Any lateral movement after?

---

## ❌ Step 10 — False Positives

* IT admin performing maintenance
* Scheduled tasks
* System upgrades

---

## 🧭 Step 11 — MITRE ATT&CK Mapping

* T1078 — Valid Accounts
* T1098 — Account Manipulation
* T1070 — Indicator Removal (log clearing)

---


## 🧾 Step 12 — Conclusion

Privileged account misuse detection helps identify high-risk activity that could lead to full system compromise.

Monitoring admin behavior is critical in SOC operations.

---

## 🚀 Key Learning Outcome

* Learned how to monitor privileged users
* Understood risk-based detection
* Practiced correlation of login + action
* Built real SOC detection logic

---
