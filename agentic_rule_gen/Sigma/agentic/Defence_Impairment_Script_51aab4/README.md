# Defence Impairment Script

Source: https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment

Threat actors deployed steganographic ASPX webshells, potentially by exploiting Adobe ColdFusion vulnerabilities. Post-exploitation, a batch script (`i.bat`) executed numerous defense impairment techniques, including disabling Microsoft Defender, terminating logging services like Sysmon, and modifying registry keys to enable credential dumping via a Mimikatz-based tool.

- **EnableWDigestUseLogonCredential** (sigma, high): The registry key and value `UseLogonCredential=1` are a specific and well-known credential dumping preparation technique.
- **ImageFileExecutionOptionsDebuggerForSecurityTool** (sigma, high): Setting an IFEO debugger for specific security tools like Sysmon is a classic, high-confidence defense evasion method.
- **IISLoggingDisabledViaAppCmd** (sigma, high): The specific `appcmd.exe` command line to disable IIS logging is highly indicative of an adversary covering their tracks.
- **ModSecurityWAFUninstalledViaAppCmd** (sigma, high): The `appcmd.exe` command to uninstall the ModSecurity WAF is a specific, high-confidence defense evasion indicator.
- **WScriptOrShellCOMObjectDisabledViaRegExe** (sigma, high): Using `reg.exe` to delete specific COM object CLSIDs or names is a destructive and unusual defense evasion technique.
