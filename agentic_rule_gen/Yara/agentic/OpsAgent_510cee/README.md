# OpsAgent

Source: https://securelist.com/auditteam-opsagent-forced-audit/122031/

AuditTeam is a threat group deploying the OpsAgent framework, which transitioned from C++ to Rust. The malware uses a public GitHub repository for C2 discovery and features modules for disabling security products and encrypting files, framing their extortion as a paid 'Audit & Consulting fee'.

- **APT_AuditTeam_OpsAgent_Core_Nov2026** (yara, high): This rule detects the core OpsAgent payload using highly specific keys/salts and command strings.
- **APT_AuditTeam_OpsAgent_DotNetLoader_Nov2026** (yara, medium): This rule targets the OpsAgent .NET loader by requiring the presence of three distinctive strings within a .NET assembly.
- **AuditTeam_OpsAgent_Jiangmin_Driver_Install** (sigma, high): This rule detects the file creation of a legitimate but abused driver at its specific path, a core TTP for this actor.
- **OpsAgent_Abused_AV_Driver_Named_Pipe** (sigma, high): This rule detects a highly specific named pipe used by the malware to interact with an abused driver.
- **OpsAgent_Abused_AV_Driver_Log_File** (sigma, high): This rule detects a specific log file path and name, which is a unique artifact of the malware's activity.
- **AuditTeam_OpsAgent_C2_Connection** (sigma, high): This rule detects network connections to a C2 IP address observed in the campaign, a transient but high-fidelity indicator.
