# GambleForce

Source: https://www.group-ib.com/blog/gambleforce-gang/

GambleForce is a threat actor active since September 2023, primarily using SQL injection attacks against organizations in the APAC region. They leverage a set of public open-source tools including sqlmap, dirsearch, and a customized Cobalt Strike instance for C2. The group has successfully exfiltrated user databases from gambling, retail, travel, and government websites.

- **APT_GambleForce_CS_Beacon_Oct2026** (yara, high): The rule keys on a highly specific, spoofed certificate subject string used by GambleForce in their Cobalt Strike beacons. This string is a strong anchor and can fire the rule alone. An alternative condition detects samples using a combination of other unique, actor-chosen strings like passwords and usernames.
- **APT_GambleForce_Tooling_Oct2026** (yara, medium): This rule detects GambleForce's operational tooling, such as scripts or C2 configuration files, by requiring a combination of at least three specific strings including a profile filename, password, and usernames. This combination is highly unlikely to occur in legitimate files.
- **HKTL_Supershell_Downloader_Oct2026** (yara, medium): This rule detects downloaders for the `supershell` hacking tool based on a unique and lengthy URL path hardcoded into the binary. The path itself is specific enough to serve as a strong indicator.
- **Suspicious_Cobalt_Strike_Certificate_Generation** (sigma, high): This rule keys on a unique combination of `keytool` arguments, including a specific `alias`, `dname`, and keystore file name, used to set up Cobalt Strike C2.
- **Potential_Redis_Rogue_Server_Exploitation** (sigma, high): This rule detects the execution of `redis-master.py` with arguments characteristic of the redis-rogue-getshell exploit tool.
- **Suspected_Sqlmap_Database_Exfiltration** (sigma, medium): This rule detects `sqlmap` usage with the `--dump` flag and a specific set of column names related to user data, as used by GambleForce.
- **GambleForce_C2_Domains** (sigma, high): This rule detects DNS queries for C2 domains exclusively associated with the GambleForce threat actor.
- **GambleForce_C2_And_Payload_Server_IPs** (sigma, high): This rule detects network connections to IP addresses exclusively associated with GambleForce C2 and payload delivery infrastructure.
