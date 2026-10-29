# NANOREMOTE

Source: https://www.elastic.co/security-labs/threat-command/nanoremote

NANOREMOTE is a C++ backdoor for Windows, loaded by WMLOADER and likely developed by the threat actor behind FINALDRAFT. It provides command execution, discovery, and file transfer capabilities by abusing the Google Drive API for C2 and data staging. The malware also incorporates open-source tools like libPeConv and Microsoft Detours for its PE loading and process hooking functionalities.

- **MAL_NANOREMOTE_Payload_Oct2026** (yara, medium): This rule targets the NANOREMOTE payload using its unique AES key, environment variable, and crash dump format string as strong indicators.
- **MAL_NANOREMOTE_WMLOADER_Oct2026** (yara, medium): This rule detects WMLOADER using its unique AES decryption key, which is a strong indicator. It also includes an alternative condition based on file names mentioned in the report.
- **HKTL_libPeConv_Strings_Oct2026** (yara, low): This rule detects the use of the libPeConv library by looking for a combination of its exported function name strings. This is an HKTL rule as the library is a public tool.
- **NANOREMOTE_C2_Communication** (sigma, high): This rule combines the unique 'NanoRemote/1.0' User-Agent with the specific C2 URI '/api/client', making it a high-fidelity indicator of compromise.
- **WMLOADER_Payload_Access** (sigma, high): This rule correlates the masquerading loader `BDReinit.exe` with its specific payload file `wmsetup.log`, providing a precise behavioral detection.
- **NANOREMOTE_Execution_Log_File_Creation** (sigma, medium): This rule detects the creation of a specific log file path `\Log\pe_exe_run.log`, a characteristic artifact of NANOREMOTE execution.
