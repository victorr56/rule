# TSGA

Source: https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/

An attacker exploited PHP2Shell (CVE-2026-109618, CVE-2026-109619) and a privilege escalation vulnerability (CVE-2026-123039) on Check Point Security Gateways. They deployed the TSGA backdoor and TSProxy components, modified versions of the PhiliKit malware, for persistence and C2. In some cases, the attacker moved laterally to ESXi hosts to deploy the destroy_v6 wiper.

- **MAL_TSGA_Philikit_Backdoor_Nov2026** (yara, medium): This rule keys on a combination of specific filenames and internal project names associated with the TSGA/PhiliKit backdoor family.
- **WEBSHELL_UNC5221_PHP_PHP2Shell_Nov2026** (yara, medium): This rule detects the PHP webshell by combining a session marker, a hardcoded key, and a specific template filename.
- **MAL_TSGA_Wiper_DestroyV6_Nov2026** (yara, low): This rule keys on the wiper's filename, the name of the note it drops, and a hardcoded username for ESXi access.
- **unc5221_tsga_backdoor_execution** (sigma, high): This rule keys on the specific command line used to launch the TSGA backdoor, combining the image path and output redirection for high precision.
- **unc5221_tsga_wiper_execution** (sigma, high): This rule detects the execution of the `destroy_v6` wiper; its name is highly specific to this threat actor's toolset.
- **unc5221_tsga_wiper_note_creation** (sigma, high): This rule detects the creation of the `DREAM_ANNEXATION.txt` wiper note, which is a unique and high-confidence indicator of compromise.
