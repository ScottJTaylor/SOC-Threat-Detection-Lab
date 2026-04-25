# 🌍 Use Case 04 — Unusual Login Location (Anomaly Detection)

---

## 📌 Scenario

A user usually logs in from one country/location.
Suddenly, the same user logs in from a different country.

👉 This could indicate:

* Stolen credentials
* VPN misuse
* Account compromise

---

## 🎯 Objective

Detect:

* Same user logging in from **multiple countries**
* Or login from **unusual country**

---

## 🧰 Environment Details

* Tool: Splunk Enterprise
* Index: `practicelog`
* Fields used:

  * user
  * src_ip
  * country
  * event_type

---

## 📊 Step 1 — Explore Login Locations

```spl
index=practicelog event_type=successful_login
| stats count by user, country
```


## Snapshot:



---

## 🧠 Learning

👉 This shows:

* Which user logs in from which country
* Baseline behavior

---

## 🔍 Step 2 — Identify Users With Multiple Countries

```spl
index=practicelog event_type=successful_login
| stats dc(country) as country_count by user
| where country_count > 1
```

---

## 🧠 Logic

* `dc(country)` = distinct count
* If >1 → suspicious

👉 Meaning:

> Same user logged in from multiple countries

---

## 🔥 Step 3 — Show Full Details

```spl
index=practicelog event_type=successful_login
| stats values(country) as countries, count by user
| where mvcount(countries) > 1
```


---

## 🧠 Learning

* `values(country)` → shows all countries
* `mvcount()` → counts them

---

## ⚡ Step 4 — Add IP Context

```spl
index=practicelog event_type=successful_login
| stats values(country) as countries, values(src_ip) as ips by user
| where mvcount(countries) > 1
```


---

## 🎯 Step 5 — Detect Rare Country (Anomaly Style)

```spl
index=practicelog event_type=successful_login
| stats count by user, country
| eventstats avg(count) as avg_count by user
| where count < avg_count
```

---

## 🧠 Logic

👉 Finds:

* Less frequent (unusual) login locations

---

## 🚨 Step 6 — High Risk (Admin + Multiple Countries)

```spl
index=practicelog event_type=successful_login
| search user="admin"
| stats values(country) as countries by user
| where mvcount(countries) > 1
```

👉 Admin + multiple countries = 🔥🔥🔥



---

## ⏱️ Step 7 — Impossible Travel (Advanced Thinking)

```spl
index=practicelog event_type=successful_login
| sort 0 user, timestamp
| streamstats current=f last(country) as prev_country by user
| where country != prev_country
```

---

## 🧠 Why This Is Powerful

👉 Detects:

> User logged in from one country → then immediately another

This mimics:

* Stolen credentials
* VPN hopping

---

## 📊 Step 8 — Timeline View

```spl
index=practicelog event_type=successful_login
| table timestamp user src_ip country
| sort timestamp
```


---

## 🕵️ Step 9 — Investigation Mindset

When alert triggers:

Ask:

1. Is user traveling?
2. Is IP known or suspicious?
3. Is login followed by:

   * privilege escalation
   * process execution
4. Same pattern for multiple users?

---

## ❌ Step 10 — False Positives

* VPN usage
* Remote work
* Cloud infrastructure

---

## 🧭 Step 11 — MITRE ATT&CK Mapping

* T1078 — Valid Accounts
* T1021 — Remote Services

---


## 🧾 Step 12 — Conclusion

This detection identifies anomalies in user login behavior based on geographic patterns.

It helps detect credential misuse and unauthorized access.

---

## 🚀 Key Learning Outcome

* Learned anomaly detection using SPL
* Used `dc()`, `values()`, `eventstats`, `streamstats`
* Understood behavior-based detection
* Practiced multi-value field handling

---

## Quick Referece:

🔹 SPL Quick Reference (dc, values, eventstats, streamstats)

1. dc(field) — Distinct Count
--------------------------------
When to use:
- Count number of unique values

Use case:
- How many different countries per user?

Example:
| stats dc(country) as country_count by user

Output:
user    country_count
bob     3

--------------------------------

2. values(field) — List Unique Values
--------------------------------
When to use:
- Show actual unique values (not just count)

Use case:
- See which countries a user logged in from

Example:
| stats values(country) as countries by user

Output:
user    countries
bob     [US, UK, DE]

--------------------------------

3. eventstats — Add Aggregation Without Losing Rows
--------------------------------
When to use:
- Add group-level stats to each row
- Keep original events intact

Use case:
- Compare each country count to user average

Example:
| stats count by user, country
| eventstats avg(count) as avg_count by user

Output:
user   country   count   avg_count
alice  AU        10      6
alice  US        2       6

--------------------------------

4. streamstats — Track Sequence / Previous Values
--------------------------------
When to use:
- Analyze ordered events (time-based)
- Get previous or running values

IMPORTANT:
- Always sort before using

Example:
| sort 0 user _time
| streamstats current=f last(country) as prev_country by user

Output:
user   country   prev_country
alice  US        AU

--------------------------------

🧠 Quick Memory Tips:
- dc()         → count uniques
- values()     → list uniques
- eventstats   → add context to rows
- streamstats  → track changes over time

--------------------------------

⚠️ Tips:
- Use _time for ordering (not timestamp unless confirmed)
- Use sort 0 before streamstats to not limit by default 10,000 rows
- values() returns multivalue fields → use mvcount() if needed
