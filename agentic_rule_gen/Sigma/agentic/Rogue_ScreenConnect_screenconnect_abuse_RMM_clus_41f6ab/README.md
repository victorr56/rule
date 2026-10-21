# Rogue ScreenConnect (screenconnect-abuse RMM cluster)

Source: https://www.huntress.com/blog/screenconnect-power-bi

A phishing campaign abuses a legitimate Microsoft Power BI page as the lure and attacker-controlled staging sites to fingerprint victims before downloading rogue ScreenConnect RMM installers from a shared tenant. Persistence is layered: a second ScreenConnect client, the SCAutoFix.ps1 PowerShell script run every two minutes via the SCAutoRepairEvery2Min scheduled task, and the defense-evasion tool HideUL_x64.exe. Staging pages leak victim telemetry to a hardcoded Telegram bot and redirect visitors that fail anti-analysis checks.

- **Win_ProcCreation_RogueScreenConnectClient_43773b3da4ccb17b** (sigma, high): This rule detects the execution of a highly specific rogue ScreenConnect client path, combined with its C2 host in the command line.
- **Win_ProcCreation_SchtasksSCAutoRepairEvery2Min** (sigma, high): This rule detects the creation of a scheduled task with a specific name, which is set to execute a specific malicious script, making it a reliable indicator of this threat.
- **Win_ProcCreation_SCAutoFixScriptExec** (sigma, medium): This rule detects the execution of a PowerShell script with a specific name used by the malware for persistence and second-stage deployment.
- **Net_Dns_RogueScreenConnectC2** (sigma, high): This rule detects DNS queries to a list of domains known to be used for C2 and payload delivery in this campaign.
- **Net_Proxy_RogueScreenConnectPayloadURL** (sigma, high): This rule detects web requests to specific URLs known to be used for staging and delivering malware in this campaign.
