## 🚨 Use Case 1: Brute Force Attack Detection

---

## 🎯 Objective

Detect repeated failed login attempts from a single source IP indicating a brute force attack.

---

## 📂 Data Source

* Index: `practicelog`
* Log Type: Linux Authentication Logs (auth.log)

---

## 🧠 Investigation Strategy

A brute force attack is identified by:

* Multiple failed login attempts
* Same source IP
* Short time window

---

## 🔍 Step 1: Identify Failed Login Events

### SPL Query

```spl
index=practicelog "Failed password"
```



### ✅ What we are doing

Filtering only failed login attempts.

### 🤔 Why

This isolates suspicious authentication failures from normal activity.

---

## 🔍 Step 2: Count Failures by Source IP

### SPL Query

```spl
index=practicelog "Failed password"
| rex "from (?<ip>\d+\.\d+\.\d+\.\d+)"
| stats count by ip
| sort -count
```

### ✅ What we are doing

* Filtering all failed login attempts using `"Failed password"`
* Extracting source IP address using `rex`
* Counting number of failed attempts per IP using `stats`
* Sorting results to identify top offending IPs

### 🤔 Why

* Raw logs do not always have structured fields like IP
* `rex` helps extract IP using regex pattern
* Grouping by IP helps identify brute force behavior
* High number of failures from one IP = strong attack indicator



---

## 🔍 Step 3: Detect Abnormal Threshold

### SPL Query

```spl
index=practicelog "Failed password"
| rex "from (?<ip>\d+\.\d+\.\d+\.\d+)"
| stats count by ip
| where count > 20
```

### ✅ What we are doing

Filtering IPs with high failure count.

### 🤔 Why

Normal users rarely fail more than a few times.

---

## 🔍 Step 4: Identify Targeted Users

### SPL Query

```spl
index=practicelog "Failed password"
| rex "for (invalid user )?(?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(user) as unique_users values(user) as usernames by src_ip
```

### ✅ What we are doing

Using the rex command to extract the user and src_ip fields from raw log events, 
then applying the stats command to count distinct usernames (dc(user)) and list all usernames (values(user)) grouped by each src_ip.

### 🤔 Why

Multiple usernames → indicates brute force or enumeration. The SPL query is designed to correlate usernames with their originating IP addresses. 
By extracting these fields and aggregating them, we can identify if a single IP is attempting multiple usernames. 
This behavior is a strong indicator of brute force or user enumeration attacks.

---

## 🔍 Step 5: Time-Based Attack Pattern

### SPL Query

```spl
index=practicelog "Failed password" 
| rex "for (invalid user )?(?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)" 
| bucket _time span=5m 
| stats count by _time, src_ip
```

### ✅ What we are doing

Grouping events into 5-minute intervals.

### 🤔 Why

Brute force attacks usually show spikes in short time windows.

---

## 🔍 Step 6: Rare IP Detection

### SPL Query

```spl
index=practicelog "Failed password"
| rex "for (invalid user )?(?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rare src_ip
| sort - count
```


### ✅ What we are doing

Finding uncommon IPs. Extracting the username and source IP from failed login events, then using the rare command to identify source IPs that appear least frequently in the dataset. 
Splunk determines rarity by counting how often each IP occurs and highlighting those with the lowest counts compared to others, which can indicate unusual or suspicious activity.

### 🤔 Why

Attackers are often not part of normal traffic. Attackers often originate from unfamiliar or infrequent IP addresses. 
Using the rare command helps highlight unusual sources that may indicate malicious activity, making it easier to detect potential brute force attempts.

---

## 🔍 Step 7: Raw Event Inspection

### SPL Query

```spl
index=practicelog "Failed password"
| rex "for (invalid user )?(?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time src_ip user
```


### ✅ What we are doing

Viewing raw structured events.

### 🤔 Why

Validates findings and prepares for reporting.

---

## 📊 Findings

* Identified IP with unusually high failed login attempts
* Multiple usernames targeted

---

## 🧠 Correlation Insight

* High failure count + multiple usernames + time spike
  = Confirmed brute force attack behavior

---

## ⚠️ Risk Level

High — potential credential compromise

---

## 🛡️ Recommendation

* Block attacking IP
* Enable MFA
* Monitor authentication logs continuously

---
## Author: Scott Taylor
