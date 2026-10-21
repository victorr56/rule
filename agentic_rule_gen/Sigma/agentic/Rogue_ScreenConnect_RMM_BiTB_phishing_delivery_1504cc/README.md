# Rogue ScreenConnect RMM (BiTB phishing delivery)

Source: https://www.huntress.com/blog/phishing-bitb-rmm-attacks

Phishing emails redirect victims to browser-in-the-browser pages impersonating Adobe, which trick users into installing ScreenConnect installers disguised as Adobe Reader updates. Each installer drops two rogue ScreenConnect clients that register as Windows services for persistent remote access, after which cmd.exe/curl retrieve and execute the defense-evasion binaries HideCursor.exe and HideUL.exe.

- **MAL_RogueScreenConnect_BiTB_Lure_Oct2026** (yara, medium): The rule keys on a unique and high-specificity typo-squatted lure URL found in the campaign's payloads.
- **PotentialRogueScreenConnectSecondStagePayloadDownload** (sigma, high): This rule detects a highly specific command line for downloading a second-stage payload via curl from a ScreenConnect parent process.
- **PotentialRogueScreenConnectDefenseEvasionToolExecution** (sigma, high): This rule detects the execution of specific defense evasion tools from a ScreenConnect parent process, a strong post-exploitation indicator.
- **PotentialRogueScreenConnectDeceptiveExeExecution** (sigma, high): This rule detects the execution of a uniquely named fake installer from a common parent process (browser, shell, explorer).
- **PotentialRogueScreenConnectPersistenceViaServiceCreation** (sigma, medium): This rule detects the key persistence mechanism by identifying service creation for ScreenConnect outside of its default installation path.
- **PotentialRogueScreenConnectC2OrPayloadDnsQuery** (sigma, high): This rule uses a list of specific, attacker-controlled domains identified in the campaign for C2 and payload delivery.
