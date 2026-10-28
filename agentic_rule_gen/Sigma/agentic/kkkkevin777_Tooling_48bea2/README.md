# kkkkevin777 Tooling

Source: https://socradar.io/blog/php2shell-weaponized-japanese-real-estate-extortion/

A financially motivated actor known as kkkkevin777 conducted an extortion campaign against Japanese real estate websites using custom PHP web shells and stolen credentials. The actor's staging server was found exposed, revealing tools, stolen data, and preparations to weaponize the PHP2Shell exploit (CVE-2026-109618, CVE-2026-109619) for future operations.

- **Kkkkevin777_Web_Shell_Creation** (sigma, high): This rule is precise because it combines a highly specific web shell filename with the context of it being created by a legitimate web server process, indicative of code execution within the web server.
- **Kkkkevin777_C2_Network_Connection** (sigma, high): This rule detects connections to a known-bad IP address on ports specifically associated with the actor's PHP and PowerShell C2 listeners, making it a high-confidence indicator of compromise.
- **Kkkkevin777_Backup_File_Creation_Pattern** (sigma, medium): This rule is precise by keying on a specific regex for filenames created by the actor, combined with creation by a web server process, which indicates a web compromise context.
