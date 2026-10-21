# AMOS

Source: https://www.huntress.com/blog/google-doc-sidebar-malware-mac-windows

A post-DEF CON X DM phishing campaign lures security researchers to a real Google Doc with a container-bound Apps Script sidebar that fakes a decryption failure and ClickFix instructions, beacons victim IP/geolocation/wallet presence to the actor's Telegram, and routes macOS and Windows users down separate malware chains. macOS victims receive an AMOS infostealer variant via a piped zsh command or a signed-out DMG download, while Windows victims receive a ClickOnce app, an encoded PowerShell loader, and three encrypted payloads (NetSupport Manager RMM, a stolen-Lenovo-signed local proxy that installs a self-generated CA, and a Ledger wallet implant).

- **MAL_AMOS_Win_Stagers_Oct2026** (yara, high): This rule detects the Windows PE payloads from the AMOS campaign using unique filenames, registry values, and other hardcoded strings.
- **MAL_AMOS_Mac_Downloader_Oct2026** (yara, high): This rule targets the macOS variant of AMOS using the unique C2 domain, download URL, and DMG filename.
- **AMOS_Infostealer_Curl_Download_macOS** (sigma, high): This rule detects the specific curl command line used to download the AMOS infostealer on macOS, matching the process image and malicious URL.
- **AMOS_Infostealer_Persistence_RunKey** (sigma, high): This rule detects the creation of a specific and unusual registry run key, combining the value name 'Ledger Wallet Installer' with the target 'MsBuild.exe'.
- **AMOS_Infostealer_C2_Domains_DNS** (sigma, high): This rule detects DNS queries to a list of domains known to be used exclusively by the AMOS infostealer campaign infrastructure.
- **AMOS_Infostealer_C2_Payload_Proxy** (sigma, high): This rule detects web requests combining specific malicious hostnames and URI paths used for AMOS infostealer payload delivery.
