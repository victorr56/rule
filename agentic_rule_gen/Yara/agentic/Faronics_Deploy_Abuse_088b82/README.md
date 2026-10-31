# Faronics Deploy Abuse

Source: https://www.huntress.com/blog/faronics-deploy-abuse

Threat actors conduct phishing campaigns to trick users into installing a legitimately signed Faronics Deploy agent. The attackers then abuse the Faronics platform to remotely execute PowerShell scripts, download additional malware like ScreenConnect, and establish persistent access on the compromised system.

- **MAL_Faronics_Deploy_Abuse_Component_Oct2026** (yara, medium): The rule keys on a unique GUID which reportedly identifies an attacker's account on the Faronics Deploy platform.
- **FaronicsDeploy_MaliciousEnrollmentKey** (sigma, high): This rule keys on a unique attacker-controlled Faronics enrollment ID seen in URL requests, making it a highly precise indicator of compromise.
- **FaronicsDeploy_PowerShellSecondStageDownload** (sigma, high): This rule detects a PowerShell command line containing a full, specific URL to a malicious second-stage script, which is a critical-level indicator.
- **FaronicsDeploy_FSCscriptSpawnsPowershell** (sigma, medium): This rule detects the behavioral TTP of the Faronics agent process spawning PowerShell for remote execution, a key part of the abuse chain.
- **FaronicsDeploy_C2Domain** (sigma, high): This rule keys on a DNS query for a specific, attacker-controlled domain used for C2 communications.
- **FaronicsDeploy_SecondStageScriptDropped** (sigma, high): This rule keys on the creation of a specifically named payload ('Jhinstaller.ps1') in a specific directory ('C:\Users\Public\'), a strong post-exploitation indicator.
- **FaronicsDeploy_LureExecutionFromDownloads** (sigma, medium): This rule keys on the execution of specific lure filenames from the common user Downloads folder, indicative of a user executing a malicious file from a phishing email.
