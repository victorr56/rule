# ICMacOS

Source: https://socradar.io/blog/icmacos-infostealer-rat/

ICMacOS (Icarus macOS) is a macOS MaaS infostealer sold by the actor GlowComa that uses ClickFix copy-paste scripts to drop a bash dropper, harvest the login password via spoofed System Preferences dialogs, and exfiltrate browser, Keychain, wallet, messaging and developer-secret data. Version 2 adds a persistent RAT with a KeepAlive LaunchAgent (com.apple.systemupdater) and a Gorilla WebSocket C2 channel executing operator commands through /bin/sh. Detection anchors include the escapeai.live C2 endpoints, /tmp/.update-helper.log and /tmp/.cache-update.log, the com.apple.systemupdater LaunchAgent, and CIS geo-fencing checks.

- **APT_GlowComa_ICMacOS_Payload_Oct2026** (yara, high): This rule detects the ICMacOS payload via highly specific social engineering dialog text and the unique LaunchAgent label string.
- **ICMacOS_Persistence_LaunchAgent** (sigma, high): This rule detects the creation of a highly specific LaunchAgent plist file used by ICMacOS for persistence.
- **ICMacOS_Persistence_LaunchAgent_Loading** (sigma, high): This rule detects the specific command used to load the malware's persistence agent, combining `launchctl` with the characteristic plist name.
- **ICMacOS_Staging_And_Log_Files** (sigma, high): This rule detects a set of highly specific hidden files and scripts created by ICMacOS in the `/tmp` directory.
- **ICMacOS_Browser_Credential_Key_Extraction** (sigma, high): This rule detects a specific command used to steal the master key for Chromium-based browser credentials from the macOS Keychain.
- **ICMacOS_Keychain_Dumping** (sigma, high): This rule detects a specific command line used by ICMacOS to dump the user's keychain to a uniquely named output file.
