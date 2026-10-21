# GHOSTENGINE

Source: https://www.elastic.co/security-labs/threat-command/invisible-miners-unveiling-ghostengine

GHOSTENGINE is a multi-stage crytomining malware targeting Windows systems. It uses vulnerable drivers to terminate EDR products, establishes persistence via scheduled tasks and a phantom DLL loaded by msdtc.exe, and ultimately deploys the XMRig miner for Monero.

- **MAL_GHOSTENGINE_XMRig_Miner_Oct2026** (yara, high): This rule targets the GHOSTENGINE-deployed XMRig miner using its unique and hardcoded Monero wallet ID, which serves as a strong, high-confidence indicator.
- **MAL_GHOSTENGINE_EDR_Killer_Oct2026** (yara, medium): This rule detects the GHOSTENGINE EDR killer component by keying on the unique IOCTL control codes it uses to abuse vulnerable drivers and the specific event log channels it clears.
- **MAL_GHOSTENGINE_Scripts_Oct2026** (yara, medium): This rule identifies GHOSTENGINE's PowerShell-based components by the co-occurrence of specific filenames (e.g., `kill.png`, `backup.png`) that are referenced or contained within the scripts.
- **GHOSTENGINE_Phantom_DLL_Hijacking_msdtc** (sigma, high): This rule detects the specific phantom DLL hijacking TTP used by GHOSTENGINE for persistence.
- **GHOSTENGINE_Scheduled_Task_Creation** (sigma, high): This rule detects GHOSTENGINE's persistence mechanism by keying on its unique scheduled task names.
- **GHOSTENGINE_PowerShell_PNG_Execution** (sigma, high): This rule detects the malware's evasion technique of executing PowerShell scripts disguised as PNG image files.
- **GHOSTENGINE_Vulnerable_Driver_Drop** (sigma, medium): This rule detects a key GHOSTENGINE defense evasion technique: dropping specific vulnerable drivers.
- **GHOSTENGINE_C2_DNS_Queries** (sigma, high): This rule detects network requests to high-confidence GHOSTENGINE command and control domains.
