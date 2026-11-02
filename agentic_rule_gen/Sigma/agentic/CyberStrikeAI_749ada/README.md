# CyberStrikeAI

Source: https://securelist.com/tr/cyberstrikeai-attacks/121715/

CyberStrikeAI is a Go-based C2 framework used by a likely Chinese-speaking actor to automate post-exploitation on Windows and Linux systems. The framework's server component uses an LLM to orchestrate attacks, including credential dumping via LSASS, lateral movement with WMI and SMB, and establishing persistence using Scheduled Tasks or Run keys. While the decision-making is AI-driven, the on-host techniques are standard and detectable.

- **MAL_CyberStrikeAI_Agent_Nov2026** (yara, medium): The rule combines the unique family name "CyberStrikeAI" with several supporting strings related to filenames, persistence, and C2 activity, providing a high-confidence signature.
- **Mimikatz_Variant_Wdiag2_DCSync_Attempt** (sigma, high): This rule detects the specific execution of a renamed Mimikatz variant 'wdiag2.exe' with DCSync arguments.
- **CyberStrikeAI_Persistence_Scheduled_Task** (sigma, medium): This rule detects the creation of a scheduled task with the specific name 'SystemUpdate' used for persistence.
- **CyberStrikeAI_Persistence_Run_Key** (sigma, medium): This rule detects the setting of a registry Run key with the specific value 'SystemUpdate' used for persistence.
- **CyberStrikeAI_C2_DNS_Query** (sigma, high): This rule detects DNS queries to domains specifically associated with CyberStrikeAI command and control.
