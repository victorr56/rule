# JOMANGY

Source: https://cyble.com/blog/hijacked-pbx-to-stolen-trunk-inj3ctor3s-campaign/

INJ3CTOR3's JOMANGY webshell campaign has evolved to exfiltrate SIP trunk and other credentials from infected PBX systems, enabling toll fraud even after the host is disinfected. The malware uses self-healing persistence via cron and uploads credentials from 17 specific configuration files. While the actor rotates identifiers like watermarks and hashes, core behaviors and persistence techniques remain consistent.

- **INJ3CTOR3_Takeover_Script_Download** (sigma, high): This rule detects a highly specific command line pattern where cron executes curl/wget to download a file named 'x', matching the actor's initial access technique.
- **JOMANGY_Persistence_Script_Execution** (sigma, high): This rule keys on the execution of specific binaries from a highly unusual and actor-specific path, making it a high-fidelity indicator of compromise.
- **JOMANGY_Webshell_Exfiltration_Activity** (sigma, high): This rule correlates a web server parent process with an exfiltration command line containing a specific URI path from the JOMANGY malware, indicating webshell activity.
- **JOMANGY_Crontab_Backup** (sigma, high): This rule detects file creation at highly suspicious, non-standard hidden paths used by the malware for storing its persistence mechanism.
