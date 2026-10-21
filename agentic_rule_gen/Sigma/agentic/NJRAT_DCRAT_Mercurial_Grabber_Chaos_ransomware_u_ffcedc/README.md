# NJRAT, DCRAT, Mercurial Grabber, Chaos ransomware (used as wiper)

Source: https://www.huntress.com/blog/fake-gta6-download-malware-analysis

An ISO masquerading as a leaked Grand Theft Auto VI build, distributed via SEO poisoning, gaming forums and torrent sites, drops a fake GTA6 installer (gta6installer.exe) that unpacks multiple NJRAT copies, DCRAT, the Mercurial Grabber infostealer, a Yandex Browser installer and Chaos ransomware repurposed as a wiper into %TEMP%. NJRAT instances beacon to AWS-hosted IPs and an ngrok tunnel, DCRAT uses a Spybot Anti-Beacon hosts-file sinkhole list and a .xsph.ru C2, Mercurial Grabber exfiltrates to a Discord webhook, and the wiper only runs as administrator, encrypts files <=200MB and drops read_it.txt notes. Branded filenames (rockstar.exe, steam.exe, gta6.exe) and Russian-language installer/ransom text are the strongest host-side anchors.

- **APT_AshaHackerTeam_Wiper_Oct2026** (yara, high): This rule keys on highly unique and actor-specific strings from the wiper's ransom note and wallpaper text.
- **MAL_FakeGTA6_Installer_Oct2026** (yara, high): This rule detects the initial installer via a unique hardcoded email address or a combination of lure-specific strings.
- **MAL_DCRAT_SpybotList_Oct2026** (yara, medium): This rule detects a DCRAT variant by the presence of a hardcoded Spybot Anti-Beacon hosts file blocklist.
- **Win_Malware_FakeGTA6_DCRAT_Persistence** (sigma, high): This rule detects DCRAT execution from a highly specific and anomalous file path (`C:\Users\Default\Local Settings\UserOOBEBroker.exe`) used for persistence.
- **Win_Malware_FakeGTA6_Chaos_Masquerading** (sigma, high): This rule detects `svchost.exe` execution from `AppData\Roaming`, a classic masquerading TTP used by the Chaos wiper. Legitimate `svchost.exe` lives in System32.
- **Win_Malware_FakeGTA6_Dropper_Temp** (sigma, high): This rule detects the execution of executables with specific, actor-chosen, game-related names from the temp directory, a core behavior of this malware campaign.
- **Win_Malware_FakeGTA6_NJRAT_Spawn** (sigma, high): This rule detects a specific process chain where known NJRAT launchers spawn their payloads, with all executables running from the `%TEMP%` directory.
- **DNS_Malware_FakeGTA6_DCRAT_C2** (sigma, high): This rule detects DNS queries for a known, specific DCRAT C2 domain, which is a high-confidence indicator of compromise.
