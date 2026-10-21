# Pawns.app (proxyware)

Source: https://www.greynoise.io/blog/proxyjacking-edge-devices-residential-proxies

An actor tracked as skynox7 compromises internet-facing edge devices (D-Link ShareCenter NAS, Ubiquiti UniFi Video NVR, SAP NetWeaver Visual Composer, plus DVR/NVR brands like Hikvision and Dahua) via known CVEs and installs the Pawns.app proxyware CLI to proxyjacking their bandwidth. At least 143 devices in 34 countries were compromised; in some cases the actor also drops an SSH public key into root and ubnt authorized_keys files as backup access. The download-and-execute chain uses /bin/sh, curl, /tmp/gs and a DONE callback beacon to an attacker-controlled IP.

- **APT_Skynox7_Dropper_Oct2026** (yara, high): The rule keys on highly specific shell command strings used by the skynox7 actor to install SSH keys for both `root` and `ubnt` users, and to download and execute the Pawns.app payload from `/tmp/gs`, making it precise to the actor's TTPs.
- **Skynox7PawnsAppExecution** (sigma, high): This rule detects the core payload execution with specific command-line arguments, making it very precise.
- **Skynox7SshDirectoryCreation** (sigma, high): This rule keys on the unusual `mkdir` command that creates SSH directories for two different users at once.
- **Skynox7PawnsAppInstallationCallback** (sigma, high): This rule detects a highly specific `curl` command line containing the unique callback URL parameter `/cb?out=DONE_`.
- **Skynox7PawnsAppPayloadDownload** (sigma, medium): This rule detects a `curl` command downloading from a specific path to a specific filename `/tmp/gs`.
- **Skynox7ExploitationC2Ip** (sigma, high): This rule detects network connections to a known C2 IP address used for exploitation by the actor.
