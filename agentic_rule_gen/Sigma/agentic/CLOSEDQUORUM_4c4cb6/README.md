# CLOSEDQUORUM

Source: https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/

CLOSEDQUORUM is a 16.4MB 64-bit Go Windows implant whose command and control is delegated to a quorum of commercial LLM providers (DeepSeek, Qwen, Mistral, Gemini), which vote on each next action (inject, persist, steal, move) via plurality voting. It steals LSASS credentials, browser passwords and crypto wallets, exfiltrating AES-256-GCM/base64 data to an operator Discord webhook, and evades analysis with ETW patching, time-based guards and WindowsUpdate-themed persistence. The public distribution build is inert, with placeholder API keys and webhook, and configured per-operator builds are generated at compile time.

- **MAL_CLOSEDQUORUM_Implant_Oct2026** (yara, high): This rule detects the CLOSEDQUORUM implant using highly specific LLM prompt fragments and JSON schema definitions which are strong anchors.
- **CLOSEDQUORUM_Execution_Filenames** (sigma, high): This rule detects the execution of known, specific filenames for CLOSEDQUORUM from common drop locations, making it highly precise.
- **CLOSEDQUORUM_Persistence_Run_Key** (sigma, high): This rule keys on the specific and anomalous registry value `WindowsUpdate` created in a standard persistence `Run` key path.
- **CLOSEDQUORUM_WMI_Persistence_Script_Execution** (sigma, high): This rule is precise by combining the generic `powershell.exe` process with the specific, suspicious script path `C:\Windows\Temp\wmi.ps1`.
- **CLOSEDQUORUM_Staging_Stolen_Data** (sigma, high): This rule detects the creation of specific credential and wallet filenames inside the `C:\Windows\Temp` staging directory, a highly anomalous event.
