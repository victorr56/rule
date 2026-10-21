# TCLBANKER

Source: https://www.elastic.co/security-labs/threat-command/tclbanker-brazilian-banking-trojan

TCLBANKER is a Brazilian banking trojan, assessed as a major MAVERICK/SORVEPOTEL update, delivered as an MSI inside a ZIP that sideloads a malicious screen_retriever_plugin.dll into the signed Logitech LogiAiPromptBuilder.exe. Its environment-gated, syscall-generating loader decrypts two .NET Reactor-protected modules: Tcl.Agent, which monitors browser URLs and drives WebSocket C2 with WPF full-screen bank overlays, and Tcl.WppBot, a worm that hijacks WhatsApp Web sessions and sends phishing mail via the victim's Outlook account.

- **MAL_TCLBANKER_Loader_Oct2026** (yara, medium): The rule targets TCLBANKER's native loader using unique 8-byte hex constants from its anti-analysis routines and a collection of specific anti-analysis strings.
- **MAL_TCLBANKER_DotNet_Payloads_Oct2026** (yara, high): This rule detects the .NET payloads of TCLBANKER using hardcoded GUIDs, API tokens, encrypted strings, and a combination of unique C2 URLs and Portuguese-language artifacts.
- **TCLBANKER_Sideloading_Execution** (sigma, high): This rule detects the core TCLBANKER execution by observing the abused Logitech binary running from the specific, non-standard path the malware creates.
- **TCLBANKER_Loader_Command_Line** (sigma, high): This rule detects a unique command-line argument used by the TCLBANKER loader, providing a high-confidence signal of malware execution.
- **TCLBANKER_Persistence_Scheduled_Task** (sigma, high): This rule targets the specific and unique name of the scheduled task created by TCLBANKER for persistence.
- **TCLBANKER_Debug_File_Creation** (sigma, high): This rule detects a high-confidence file artifact created by the main malware process, indicating its presence on the system.
- **TCLBANKER_Disguised_Selenium_Manager** (sigma, high): This rule detects the execution of a legitimate binary from a highly unusual and malware-specific path, indicating process masquerading.
- **TCLBANKER_C2_Phishing_DNS_Query** (sigma, high): This rule detects network lookups for domains and specific subdomains on shared infrastructure known to be controlled by the TCLBANKER operators.
