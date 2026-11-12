# Project 3: SIEM Threat Detection Lab with Splunk

**Date:** November 12, 2026
**Tools:** Splunk Enterprise 10.6, SPL (Search Processing Language), Sysmon, Suricata IDS, VirusTotal
**Source:** Splunk Boss of the SOC (BOTS) v1 dataset, [github.com/splunk/botsv1](https://github.com/splunk/botsv1) (33.4 million events)

## Scenario

The public website of the company Wayne Enterprises, `imreallynotbatman.com`, was attacked. Acting as a SOC analyst, I loaded the company's security logs into Splunk (a SIEM) and searched them to find out who attacked the website, how they got in, and what they did inside the server. I then built detection alerts so the same attack would be caught automatically next time.

## Goal

1. Identify the attacker's IP addresses and tools.
2. Find out how the attacker gained access to the website.
3. Find out what the attacker did after getting in.
4. Build detection alerts for the attack, mapped to MITRE ATT&CK.

## Lab Setup

- Installed Splunk Enterprise on Windows 11.
- Loaded the pre-indexed BOTS v1 dataset into Splunk (`index=botsv1`).
- Installed the Splunk add-ons for Stream (network traffic), Microsoft Windows, and Sysmon, so Splunk could read the log fields.

## Steps Taken

1. **Found the attackers:** counted web requests to the website by source IP. One IP sent 20,932 requests (94% of all traffic), which points to an automated tool.
   `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | stats count by src_ip | sort -count`

2. **Identified the scanning tool:** checked the IDS (Suricata) alerts for that IP. It triggered 51 different alert types, including "ET SCAN Acunetix Version 6 Scan Detected", plus SQL injection, cross-site scripting (XSS), and Shellshock attempts.
   `index=botsv1 earliest=0 sourcetype=suricata 40.80.148.42 | spath | stats count by alert.signature | sort -count`

3. **Found the web server and its software:** the requests went to 192.168.250.70 (host `we1149srv`). The page paths all started with `/joomla/`, showing the site runs the Joomla CMS, with its admin login page at `/joomla/administrator/index.php`.
   `index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 src_ip=40.80.148.42 | stats count by uri | sort -count`

4. **Detected the brute-force attack:** filtered login attempts (HTTP POST requests containing a password field). A second IP made 412 login attempts using a Python script (`Python-urllib/2.7`) against the `admin` account.
   `index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST form_data=*passwd* | stats count by src_ip, http_user_agent`

5. **Extracted the guessed passwords:** used `rex` to pull the password out of each login attempt. The script tried 412 different common passwords, starting with `12345678`, in about 11 seconds (around 39 per second).
   `... | rex field=form_data "passwd=(?<password>[^&]+)" | stats dc(password)`

6. **Found the correct password:** the script tries each password once, so the correct one is the only password used twice, once by the script and once by the attacker logging in manually. The password was `batman`, used from both attacker IPs, which links them to the same attacker.
   `... | stats count values(src_ip) as ips by password | where count > 1`

7. **Found the uploaded files:** searched POST requests mentioning `.exe`. After logging in, the attacker uploaded `3791.exe` and `agent.php` through the Joomla admin page at 23:52:47.
   `index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST *.exe | table _time src_ip uri part_filename{}`

8. **Confirmed the malware ran:** switched to Sysmon logs (Event ID 1 = a program started). The website's PHP engine (`php-cgi.exe`, running the `agent.php` web shell) launched `3791.exe`, which then opened command prompts (`cmd.exe`), giving the attacker remote control of the server. I extracted the file's MD5 hash with `rex`.
   `index=botsv1 earliest=0 source="*Sysmon*" EventCode=1 3791.exe | rex field=_raw "MD5=(?<md5>[A-Fa-f0-9]{32})" | table _time host User ParentImage Image CommandLine md5`

9. **Checked the hash on VirusTotal:** 63 of 68 security vendors flagged the file as malicious. It is a trojanized copy of ApacheBench (`ab.exe`), labeled `trojan.swrort/cryptz` and detected as `Trojan/Win32.Shell`.

## Findings

| Question | Answer | Where it was found |
|---|---|---|
| Scanner IP | 40.80.148.42 | Web traffic (stream:http) |
| Scanning tool | Acunetix web vulnerability scanner | Suricata IDS alerts |
| Web server | 192.168.250.70 (we1149srv), running Joomla | Web traffic (dest_ip, uri) |
| Brute-force IP | 23.22.63.114 | Login POST requests |
| Passwords tried | 412 unique, starting with 12345678 | form_data field (rex) |
| Correct password | batman (Joomla admin account) | Password used by both attacker IPs |
| Uploaded files | 3791.exe and agent.php | HTTP upload (part_filename) |
| Malware executed? | Yes, at 23:56:18 via the agent.php web shell | Sysmon Event ID 1 |
| Malware hash (MD5) | AAE3F5A29935E6ABCC2C2754D12A9AF0 | Sysmon (rex on raw event) |
| VirusTotal result | 63/68, Trojan/Win32.Shell | VirusTotal |

## Attack Timeline (August 10, 2016)

| Time | What happened | MITRE ATT&CK |
|---|---|---|
| Before 23:45 | Acunetix vulnerability scan from 40.80.148.42 | T1595.002 Vulnerability Scanning |
| 23:45:21 | Brute-force attack on the Joomla admin login begins from 23.22.63.114 | T1110.001 Password Guessing |
| ~23:45:32 | Password "batman" found and used by the attacker | T1078 Valid Accounts |
| 23:52:47 | 3791.exe and agent.php uploaded | T1105 Ingress Tool Transfer |
| 23:56:18 | Web shell launches 3791.exe | T1505.003 Web Shell |
| 23:58 – 00:08 | Malware opens command shells | T1059.003 Windows Command Shell |

## Detection Alerts

I turned the findings into two scheduled Splunk alerts. Unlike the investigation searches, which look for this specific attacker, these look for the attacker's **behavior**, so they would also catch future attacks.

| Alert | Logic | MITRE ATT&CK | Result |
|---|---|---|---|
| Brute Force Login Detected | More than 20 login attempts from one IP within 5 minutes | T1110.001 | Flags 23.22.63.114 (412 attempts); does not flag the attacker's single manual login |
| Executable Uploaded to Web Server | Any .exe file uploaded through HTTP POST | T1105 | Flags 3791.exe |

**Brute Force Login Detected:**
`index=botsv1 earliest=0 sourcetype=stream:http http_method=POST form_data=*passwd* | bin _time span=5m | stats count by _time, src_ip | where count > 20`

**Executable Uploaded to Web Server:**
`index=botsv1 earliest=0 sourcetype=stream:http http_method=POST part_filename{}=*.exe | table _time src_ip dest_ip part_filename{}`

Both alerts run hourly, trigger when results are found, and have High severity.

**Notes:**
- The searches use `earliest=0` because the lab data is from 2016. In a real SOC, each alert would only search the last hour (`earliest=-1h`).
- The threshold of 20 attempts would need tuning against normal traffic to avoid false positives.
- The Sysmon add-on renamed the Sysmon sourcetype, which broke my first search. I fixed it by searching by `source="*Sysmon*"` instead.

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Scanner / attacker IP | 40.80.148[.]42 |
| Brute-force IP | 23.22.63[.]114 |
| Malware file | 3791.exe |
| Malware MD5 | AAE3F5A29935E6ABCC2C2754D12A9AF0 |
| Malware SHA-256 | ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d |
| Web shell | agent.php |
| Compromised account | Joomla admin |
| Compromised server | we1149srv (192.168.250.70) |

## Conclusion

The attacker scanned the website with Acunetix, discovered the Joomla admin page, and brute-forced the `admin` account's weak password (`batman`). They then uploaded a web shell (`agent.php`) and a trojan (`3791.exe`), and used the web shell to run the trojan on the web server `we1149srv`, giving them remote command access to the server.

## Recommended Actions

- Isolate the web server we1149srv (192.168.250.70) from the network.
- Block 40.80.148[.]42 and 23.22.63[.]114 at the firewall.
- Remove 3791.exe and agent.php, and rebuild the server from a clean backup.
- Search all other computers for the malware's hash.
- Change the Joomla admin password to a strong one and turn on multi-factor authentication.
- Lock accounts after several failed logins, and restrict the admin page to internal IP addresses.
- Block executable file uploads on the website and keep Joomla updated.

## What I Learned

- How a SIEM collects different log types in one place, and how to search millions of events with SPL
- Combining network logs (web traffic, IDS alerts) with host logs (Sysmon) to rebuild a full attack from start to finish
- Using SPL commands such as `stats`, `rex`, `bin`, and `where` to pull evidence like passwords and file hashes out of raw logs
- The difference between investigating one attacker and writing detection rules that catch the same behavior in the future
- Mapping attacker actions to MITRE ATT&CK techniques
- Troubleshooting real tool problems, such as an add-on renaming a sourcetype

## Screenshots

![Top attacking IPs](screenshots/a1-top-ips.png)
*Web requests by source IP*

![IDS alerts](screenshots/a2-scanner-alerts.png)
*Suricata alerts showing the Acunetix scanner*

![Web server IP](screenshots/a3-web-server.png)
*Web server identified by destination IP*

![Joomla paths](screenshots/a4-website-software.png)
*Pages requested by the scanner, showing Joomla*

![Brute force](screenshots/a5-brute-force.png)
*Login attempts by IP and user agent*

![Login attempts](screenshots/a6-login-attempts.png)
*Raw brute-force login data*

![Unique passwords](screenshots/a6-unique-passwords.png)
*412 unique passwords tried*

![First password](screenshots/a6-first-password.png)
*First password tried*

![Correct password](screenshots/a7-correct-password.png)
*The correct password, used by both attacker IPs*

![Uploaded files](screenshots/a8-uploaded-files.png)
*Files uploaded by the attacker*

![Malware executed](screenshots/a9-malware-executed.png)
*Sysmon process chain: web shell → 3791.exe → cmd.exe*

![Malware hash](screenshots/a9-hash.png)
*MD5 hash extracted with rex*

![VirusTotal](screenshots/a9-virustotal.png)
*VirusTotal result: 63/68 vendors*

![Brute force detection](screenshots/d1-brute-force.png)
*Brute-force detection search*

![Brute force alert](screenshots/d1-alert-saved.png)
*Brute-force alert saved in Splunk*

![Upload detection](screenshots/d2-exe-upload.png)
*Executable upload detection search*

![Upload alert](screenshots/d2-alert-saved.png)
*Upload alert saved in Splunk*
