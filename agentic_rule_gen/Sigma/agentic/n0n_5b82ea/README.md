# n0n

Source: https://socradar.io/blog/n0n-ransomware-ai-assisted-extortion/

n0n is a data exfiltration and destructive extortion group that uses an AI coding agent to generate attack scripts. Initial access relies on stolen or weak credentials for remote access services like FortiGate SSL-VPN and RDP. The malware, with Windows and Linux variants, encrypts files with a .n0n extension or destroys data and backups.

- **N0n_Ransomware_Persistence_Scheduled_Task** (sigma, high): This rule detects the creation of scheduled tasks with specific names used by N0n ransomware for persistence.
- **N0n_Ransomware_Persistence_Run_Key** (sigma, high): This rule detects a specific registry key value name "n0nNote" used by N0n ransomware for persistence.
- **N0n_Actor_Hide_User_Account** (sigma, high): This rule detects the specific registry change used to hide user accounts named "svc_upd" and "svc_reg".
- **N0n_Ransomware_C2_Domain_Query** (sigma, high): This rule detects DNS queries for domains specifically identified as part of the N0n ransomware C2 infrastructure.
