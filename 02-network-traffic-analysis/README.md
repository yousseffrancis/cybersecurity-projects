# Project 2: Network Traffic Analysis with Wireshark

**Date:** November 9, 2026
**Tools:** Wireshark, 7-Zip
**Source:** Practice traffic capture from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/2026/10/01/index.html) (exercise from October 1, 2026)

## Scenario
A Windows computer on the company network "natureforce" was suspected of being infected with malware. Acting as a SOC analyst, I analyzed a recording of its network traffic (a pcap file) to identify the infected computer and the user account, so the incident can be contained.

## Goal
Identify the infected Windows client's:
1. IP address
2. MAC address
3. Host name
4. User account name

## Steps Taken
1. **IP and MAC address:** reviewed the DHCP traffic at the start of the capture, where the client requests and receives its IP address. The Ethernet header of the DHCP request showed the client's MAC address, and the ARP traffic ("Tell 10.10.1.128") linked that MAC address to its IP.
2. **Host name:** found in an LLMNR query sent by the client right after it received its IP address.
3. **User account:** filtered for Kerberos login traffic using `kerberos.CNameString`, then excluded computer accounts (names ending in `$`) with the filter:
   `kerberos.CNameString and !(kerberos.CNameString contains "$")`
   The remaining Kerberos requests from the client contained the user's account name.

## Findings
| Question | Answer | Where it was found |
|----------|--------|--------------------|
| IP address | 10.10.1.128 | DHCP and ARP traffic |
| MAC address | 00:22:fb:ec:7e:e7 | Ethernet header of DHCP request |
| Host name | DESKTOP-4VGYQX7 | LLMNR query |
| User account | bdiaz | Kerberos AS-REQ (CNameString) |

## Indicators of Compromise (IOCs)
| Type | Value |
|------|-------|
| Infected host IP | 10.10.1.128 |
| Infected host MAC | 00:22:fb:ec:7e:e7 |
| Infected host name | DESKTOP-4VGYQX7 |
| Affected user account | bdiaz |
| Suspicious server (sent a Windows EXE file) | 107.175.82[.]242:9000 |

## Note on Safety
The exercise also asked for the SHA-256 hash of a Windows EXE file sent from 107.175.82[.]242:9000. I chose not to extract this file, because it is live malware and extracting it on a personal Windows computer risks infection. In a real investigation, this step should be done inside an isolated virtual machine or malware analysis sandbox.

## Conclusion
The infected computer is **DESKTOP-4VGYQX7** (IP 10.10.1.128, MAC 00:22:fb:ec:7e:e7), used by the account **bdiaz** in the natureforce domain.

## Recommended Actions
1. Isolate DESKTOP-4VGYQX7 from the network.
2. Reset the password for the account bdiaz and review its recent activity.
3. Block the IP 107.175.82[.]242 at the firewall.
4. Search other computers' traffic for connections to the same IP.

## What I Learned
- How DHCP, ARP, LLMNR, and Kerberos traffic reveal a computer's identity on a network
- Using Wireshark display filters to narrow 42,000+ packets down to the few that matter
- Telling apart computer accounts (ending in `$`) and user accounts in Kerberos traffic
- Handling malware evidence safely

## Screenshots

<img width="1302" height="990" alt="Screenshot 2026-11-09 201854" src="https://github.com/user-attachments/assets/f5d05fe0-c44b-4913-bf7c-684719e6d15a" />
<img width="1917" height="1075" alt="Screenshot 2026-11-09 202918" src="https://github.com/user-attachments/assets/e6169d64-8160-4ad9-bee5-ce794ed6262d" />
<img width="1250" height="1020" alt="Screenshot 2026-11-09 204517" src="https://github.com/user-attachments/assets/2b7ec882-4f19-4bec-a5e1-34f0059c675d" />


**Host name in LLMNR query**

**User account in Kerberos traffic**
