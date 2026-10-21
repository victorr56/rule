# macos-stealer-v2

Source: https://blog.virustotal.com/2026/10/introducing-macos-mirage.html.html

A macOS Apple Silicon infostealer chain that shows a deceptive AppleScript "Password Request" dialog via /usr/bin/osascript, validates the harvested password with dscl . authonly, and installs a LaunchDaemon for persistence. It stages Keychain, Safari cookie, Notes, SSH and shell-history files under /tmp/lksopo, compresses them with ditto, exfiltrates the archive via curl POST to 109.238.87.111, and downloads a second-stage bot from 193.178.159.129 before deleting the staging directory. Hidden state files (~/.bhost, ~/.phost, ~/.username, ~/.pwd) written by the first stage are required by the dropped bot.

- **MAL_MACOS_Stealer_V2_Oct2026** (yara, medium): The rule keys on a highly unique literal string and a cluster of behavioral artifacts.
- **macos_stealer_v2_osascript_phishing** (sigma, high): This rule keys on the specific `osascript` command line arguments, including the unique typo "passwen", used for credential phishing.
- **macos_stealer_v2_curl_exfiltration** (sigma, high): This rule keys on the unique combination of curl, the custom 'buildid' HTTP header, and the specific staging filename for exfiltration.
- **macos_stealer_v2_hidden_state_files** (sigma, high): This rule keys on a list of highly specific hidden file names created by the malware in the user's home directory.
- **macos_stealer_v2_launchdaemon_persistence** (sigma, high): This rule keys on the specific command line used to copy the malicious plist from a temporary location to the LaunchDaemons directory.
- **macos_stealer_v2_c2_network_connection** (sigma, high): This rule keys on a list of specific IP addresses hardcoded in the malware for C2 command and control and data exfiltration.
