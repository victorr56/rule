# QBOT

Source: https://www.elastic.co/security-labs/threat-command/exploring-the-qbot-attack-pattern

QBOT is a modular trojan that uses complex command lines with curl.exe and regsvr32.exe for initial execution, followed by injection into explorer.exe. It achieves persistence via randomly named registry run keys and escalates privileges by creating a scheduled task to run as SYSTEM. The malware decrypts a configuration containing C2 IP addresses and evades defenses by checking for analysis tools.

- **MAL_QBOT_Oct2026** (yara, high): The rule keys on a unique hardcoded encryption key and a specific scheduled task command format string, both confirmed to be in the binary.
- **QbotC2IPConnections** (sigma, medium): This rule detects network connections to a list of known QBot C2 server IP addresses from the provided threat profile.
- **QbotPayloadDownloadURI** (sigma, medium): This rule detects the specific URI structure QBot uses for payload downloads, featuring a random directory and a fake PNG file.
