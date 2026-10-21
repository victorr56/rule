# Gamaredon (Ptero family of tools)

Source: https://www.welivesecurity.com/en/eset-research/gamaredon-2025-leveraging-tunnels-workers-dead-drops-new-alliances/

Gamaredon targeted Ukrainian governmental and military institutions throughout 2025 with 35 spearphishing campaigns delivering HTA downloaders, VBScript downloaders (PteroSand), and six new PowerShell tools, plus weaponizers for lateral movement. The group hid C&C behind third-party tunnels, serverless workers, PaaS and DDNS, abused legitimate messaging, blogging, paste and social services as dead drops, and moved data exfiltration to S3-compatible cloud storage. Detection should focus on the Ptero* tool names, the abused third-party service domains, and cloud-storage exfiltration endpoints.

- **APT_Gamaredon_Ptero_Oct2026** (yara, medium): This rule detects Gamaredon's Ptero family using unique tool names and a highly specific exfiltration domain, all sourced from prose due to lack of binary evidence.
- **PowerShell_Execution_of_Gamaredon_Ptero_Tooling** (sigma, high): This rule is precise because it keys on a list of highly specific tool names from the Gamaredon 'Ptero' malware family, observed in PowerShell script logs.
- **Gamaredon_CVE-2025-8088_HTA_Drop_in_Startup_Folder** (sigma, high): This rule is precise because it combines a specific process (WINRAR.EXE), a specific file type (.hta), and a specific, high-value location (Startup folder).
- **Gamaredon_Exfiltration_to_Intercolo_S3** (sigma, high): This rule is precise because it targets a specific, non-mainstream cloud storage domain identified as a primary exfiltration point for this threat actor.
