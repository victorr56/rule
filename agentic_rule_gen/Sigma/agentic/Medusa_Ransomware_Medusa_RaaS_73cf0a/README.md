# Medusa Ransomware (Medusa RaaS)

Source: https://www.darktrace.com/blog/under-medusas-gaze-how-darktrace-uncovers-rmm-abuse-in-ransomware-campaigns

Medusa is a Ransomware-as-a-Service operation whose affiliates gain initial access through exploited internet-facing systems (GoAnywhere MFT, SimpleHelp, ScreenConnect, Exchange ProxyShell, Fortinet EMS) and then abuse legitimate RMM tools such as SimpleHelp, Atera and PDQ Deploy for C2, persistence and lateral movement. Encryption appends the .MEDUSA extension and drops !!!READ_ME_MEDUSA!!!.txt, while data is staged with Robocopy/Rclone and exfiltrated to endpoints such as erp.ranasons.com over ports 443/445/80. Detection should focus on unusual JWrapper/SimpleHelp agent connections, PDQ Deploy service execution of AdminArsenal payloads like gaze.exe, and large uploads to rare external hosts.

- **APT_Storm1175_Tool_CikaBika_RAT_Oct2026** (yara, high): This rule keys on a hardcoded Discord bot token and a unique command list string associated with the CikaBika RAT.
- **MAL_Medusa_Affiliate_PSScript_Deployer_Oct2026** (yara, medium): This rule keys on a combination of embedded C# P/Invoke definitions and PowerShell commands used to sideload a malicious DLL.
- **MedusaRansomwarePayloadDeployedViaPDQDeploy** (sigma, high): This rule detects the specific path and filename used by Medusa affiliates to deploy their ransomware via PDQ Deploy, indicating lateral movement.
- **MedusaRansomwareNoteCreation** (sigma, high): This rule detects the highly specific and unique filename of the Medusa ransom note.
- **MedusaRansomwareFileEncryption** (sigma, high): This rule detects the specific file extension appended by the Medusa ransomware during the encryption phase.
- **CikaBikaRATPowerShellStager** (sigma, high): This rule is based on a highly specific and unique combination of strings in a PowerShell script block, characteristic of the CikaBika RAT loader.
- **CikaBikaRATUACBypassViaMSSettings** (sigma, high): This rule detects the hijacking of the `ms-settings` handler to point to `cmd.exe`, a specific UAC bypass technique used by CikaBika RAT.
- **MedusaRaaSAffiliateC2Domains** (sigma, high): This rule detects DNS lookups for specific, high-confidence C2 and exfiltration domains associated with Medusa RaaS affiliates.
