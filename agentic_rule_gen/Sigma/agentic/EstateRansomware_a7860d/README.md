# EstateRansomware

Source: https://www.group-ib.com/blog/estate-ransomware/

EstateRansomware gains initial access via a FortiGate SSL VPN using a dormant account. The actors deploy a backdoor, move laterally via RDP, and exploit CVE-2023-27532 in Veeam to create a rogue SQL account. After discovery and credential harvesting with tools like AdFind and Nirsoft utilities, they disable Windows Defender and deploy the ransomware using PsExec.

- **MAL_EstateRansomware_Toolkit_Oct2026** (yara, low): This rule keys on a combination of four supporting strings derived from the actor's TTPs, requiring three to match to achieve reasonable precision for a potential toolkit.
- **EstateRansomware_Payload_Execution** (sigma, high): This rule detects the specific ransomware payload name (`LB3.exe`) executed from its known staging directory (`C:\PerfLogs`).
- **EstateRansomware_C2_IPs** (sigma, high): This rule detects network connections to a list of IP addresses hardcoded in the report as actor infrastructure.
- **Suspicious_PsExec_Staging_PerfLogs** (sigma, medium): This rule detects a common attacker TTP: staging and executing a legitimate tool (`PsExec.exe`) from an unusual but common-for-attackers directory (`C:\PerfLogs`).
- **Veeam_Exploit_PoC_Execution** (sigma, medium): This rule detects execution from a highly specific file path associated with the build artifacts of a public Veeam exploit tool.
- **Veeam_Credential_Dumper_Folder** (sigma, medium): This rule detects the creation of a folder with a specific name (`veeam-creds-main`) tied to a public credential dumping tool.
- **Nirsoft_Credential_Dumping_Tools** (sigma, medium): This rule detects the execution of several well-known Nirsoft password recovery tools often abused by attackers for credential theft.
