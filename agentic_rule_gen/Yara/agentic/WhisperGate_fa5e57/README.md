# WhisperGate

Source: https://www.elastic.co/security-labs/threat-command/operation-bleeding-bear

WhisperGate is a multi-stage destructive malware used in targeted attacks. The first stage wipes the Master Boot Record (MBR), rendering the system inoperable. A subsequent .NET-based stage, downloaded via Discord, disables Windows Defender and uses process hollowing to inject a file corruptor payload that overwrites and renames files on all connected drives.

- **MAL_WhisperGate_Stage1_Oct2026** (yara, high): Keys on the unique Bitcoin address found in the Stage 1 MBR wiper's ransom note.
- **WhisperGate_MBR_Wiper_Activity** (sigma, high): This rule detects direct write access to the physical drive, an indicator of MBR wiping as performed by WhisperGate. While single-field, the target is so specific and the potential impact so high that it warrants a critical alert.
- **WhisperGate_Disables_Windows_Defender_By_Excluding_C_Drive** (sigma, high): This rule targets a specific and highly malicious PowerShell command used by WhisperGate to disable Windows Defender. The combination of `Set-MpPreference`, `-ExclusionPath`, and `'C:\'` is a very strong indicator of compromise.
- **WhisperGate_Stops_Windows_Defender_Service_via_AdvancedRun** (sigma, high): This rule detects a highly specific command-line pattern where the `AdvancedRun.exe` tool is used to execute `sc.exe` to stop the `WinDefend` service, matching observed WhisperGate behavior precisely.
- **WhisperGate_Deletes_Windows_Defender_Directory_via_AdvancedRun** (sigma, high): This rule detects a very specific command-line where `AdvancedRun.exe` is used to run PowerShell to recursively delete the Windows Defender directory, a clear and high-confidence indicator of defense evasion.
- **WhisperGate_VBS_Execution_From_Temp_Directory** (sigma, medium): This rule detects a common malware pattern used by WhisperGate: `wscript.exe` executing a `.vbs` file from the user's temporary directory. This combination is a well-known indicator of suspicious activity.
