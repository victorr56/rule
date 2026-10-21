# XMRig

Source: https://www.huntress.com/blog/ahsaycbs-flaws-exploit

Threat actors chain CVE-2026-105133 (authentication bypass) and CVE-2026-105134 (unauthenticated RCE via /rps/api/json/UpdateReceivers.do) in AhsayCBS to spawn commands from cbssvcX64.exe, drop JSP webshells and deploy an XMRig Monero miner renamed edge.exe. Persistence is established through the masquerading MicrosoftEdgeUpdateSvc service running a renamed NSSM (msedge.exe) as SYSTEM, with Taskgmr.ps1 hiding the miner from Task Manager and WinRing0x64.sys giving the miner kernel-level hardware access. Payloads are fetched over HTTP from an Alibaba Cloud OSS bucket and mining traffic goes to an XMR pool on port 8029.

- **MAL_MinerDropper_AhsayCBS_Exploit_Oct2026** (yara, high): This rule keys on the unique and specific URI path used to exploit AhsayCBS for RCE, as reported.
- **Suspicious_Child_Process_Of_AhsayCBS_Service** (sigma, high): This rule detects suspicious child processes of the specific AhsayCBS service binaries, indicating post-exploitation.
- **Persistence_via_Masquerading_Service_MicrosoftEdgeUpdateSvc** (sigma, high): This rule detects the creation of a Windows Service using a highly specific, non-standard name used for persistence.
- **XMRig_Campaign_Drops_Vulnerable_WinRing0_Driver** (sigma, high): This rule keys on a specific driver filename (`WinRing0x64.sys`) created in a non-standard and suspicious location.
- **XMRig_Campaign_DNS_Queries** (sigma, high): This rule detects DNS queries for domains specifically associated with the payload delivery and mining pool of this campaign.
- **XMRig_Campaign_C2_and_Mining_Pool_Connections** (sigma, high): This rule detects network connections to a list of IP addresses specifically identified as attacker infrastructure.
