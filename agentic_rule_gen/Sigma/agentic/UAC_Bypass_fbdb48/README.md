# UAC Bypass

Source: https://www.elastic.co/security-labs/threat-command/exploring-windows-uac-bypasses-techniques-and-detection-strategies

This threat profile covers techniques used to bypass Windows User Account Control (UAC) for silent privilege escalation. Malware achieves this by hijacking the execution flow of auto-elevating applications through methods like registry manipulation, DLL hijacking, and abuse of elevated COM interfaces. Detections can focus on the specific primitives used or on broader behavioral patterns, such as tracking process token security attributes to identify descendants of auto-elevated processes.

- **UacBypassDllMasqueradingInSystem32Path** (sigma, high): This rule detects a DLL loaded from a path containing '\System32\' but not from the real C:\Windows\System32, a specific DLL hijacking technique for UAC bypass.
- **UacBypassDismHostExecutionFromNonSystemLocation** (sigma, high): This rule detects `DismHost.exe` running from outside its legitimate `C:\Windows\System32\` directory, a strong indicator of its abuse in a UAC bypass.
- **UacBypassFileCreationInExeDotLocalFolder** (sigma, high): This rule detects file creation in a `.exe.local` subdirectory of System32, a very specific and high-confidence indicator of a UAC bypass technique.
- **UacBypassWindirEnvironmentVariableHijack** (sigma, high): This rule detects the setting of the `windir` environment variable in the HKCU hive, a specific and reliable indicator of a known UAC bypass.
- **UacBypassSilentCleanupTaskExecution** (sigma, medium): This rule detects manual execution of the `SilentCleanup` task from a shell, a common preparatory step for a known UAC bypass.
