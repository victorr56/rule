# Custom PHP2Shell Toolkit

Source: https://socradar.io/blog/php2shell-ai-agents-credential-harvesting/

An initial access broker uses a custom, AI-augmented toolkit to exploit PHP2Shell (CVE-2026-109618, CVE-2026-109619). The campaign establishes persistence via SSH keys, cron jobs, and webshells to harvest credentials, secrets, and cloud API keys from compromised PHP/Apache servers.

- **APT_UnnamedIAB_PHP2Shell_Toolkit_Nov2026** (yara, medium): The rule keys on a highly unique instruction string, specific script filenames, and webshell parameter fragments from the PHP2Shell toolkit, ensuring high precision.
- **PHP2ShellToolkitReverseShell** (sigma, high): This rule keys on the unique combination of `setsid`, an interactive bash reverse shell, and a specific lock file pattern.
- **PHP2ShellToolkitSystemdPersistence** (sigma, high): This rule keys on the creation of specifically named systemd service files in standard systemd paths.
- **PHP2ShellToolkitWebshellCreation** (sigma, high): This rule keys on a highly specific webshell path and name regex, created by a legitimate web server process.
- **PHP2ShellToolkitScriptDownload** (sigma, high): This rule keys on the download of specific actor script names ('collect.sh', 'deep-loot.sh') via `curl` or `wget`.
- **UnnamedIAB_C2_IPs** (sigma, high): This rule keys on a list of hardcoded C2 and operator IP addresses identified in the threat intelligence report.
- **UnnamedIAB_C2_Domains** (sigma, high): This rule keys on a list of hardcoded C2 and operator domains identified in the threat intelligence report.
