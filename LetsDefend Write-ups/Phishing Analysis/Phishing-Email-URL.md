## 🎯 Phishing Email with URL Link 🎯

### 🛠️ Tools used:
  - SIEM
  - Log management
  - URL scanning websites

### 📌 Key actions:
  - ⚠️ Reviewed SIEM alert
  - 🔎 Search through logs
  - 🔗 Extracted and analyzed URLs
  - 🌐 Checked domain/IP reputation

Let’s dive into the SIEM alert investigation!

## ⚠️ The SIEM Alert

![SOC Alert](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20052010.png)

First step is gathering details of the event from the alert. Asking, what information is relevant or has a potential to be relevant?
  - IP address of the source
  - IP address of the destination
  - Ports used
  - Link URL
  - If the link accessed or not
  - Anything else that might seem off

## 🔎 Log Analysis

![Log Analysis](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20052459.png)

Second phase includes checking the logs for additional information and the travel path ot the email in the network, including the endpoints affected.
  - Search for the IP addresses and locate any endpoint involved
  - With the logs, we can get a more detailed look at the event as it occured on the endpoint

![Event Details](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20052603.png)

## 🌐 Web Anlysis of Link URL
At this phase we get into the meat of the analysis by check whether the URL is malicious or not. Multiple sources are available online to check credablity of the URL.

ℹ️ Highly recommend utilizing multple sources

### URLscan.io - Failed Analysis

![URLscan.io](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot_2026-05-07_09-28-14.png)

### ANY.RUN - Sandboxed Environment Analysis > Understand what the malicious link will try to do

![ANY.RUN](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot_2026-05-07_09-36-20.png)

### ANY.RUN - MITRE ATTACK Sequence > Understand the attack vector

![MTIRE ATTACK](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot_2026-05-07_09-37-08.png)

### VirusTotal - Successful URL Scan

![VirusTotal](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20053234.png)

With multiple sources confirming the link as malicious, we can move on to the next phase.

## 🖥️ Endpoint Activity

At this point we know the link is malicious. Now we must find out if any endpoint accessed the link and answer the following:
  - Who accessed the URL?
  - When was it accessed?
  - What is the source IP address?
  - What is the destination IP address?
  - Who is the user that accessed it?
  - What is the User Agent?
  - Is the request blocked?

### 🗒️ Endpoint details

![Endpoint Search](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20053700.png)

### 🔎 Checking for unusual processes > scan the hash values iin VirusTotal

![process](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20053801.png)

### 🐛 VirusTotal scan of the KBDYAK.exe informs us that a malicious executable is running

![Bug](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20053822.png)

### 🔐 Containment of the endpoint in an attempt to limit the potential spread

![Bug](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20053909.png)

### 🗄️ Make sure to collect all artifacts used in the analysis and document actions

![Artifacts](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20055142.png)

![Actions](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20060308.png)

### 🏁 Close the incident and mark the case as a true positive to fine-tune the SIEM rules

![Closed](https://github.com/ScottJTaylor/Lab-Screenshots/blob/main/Phishing%20Email%20Analysis/Malicious%20URL/Screenshot%202026-05-07%20060356.png)
