# Unspecified

Source: https://blog.virustotal.com/2026/10/process-trees-in-livehunt-yara-rules.html

This threat profile describes techniques used by various malware to abuse process creation chains for execution and persistence. Key behaviors include Office applications leading to shell execution via DCOM and mshta.exe, creating persistence with scheduled tasks that run dropped files, and using LOLBINs like MSBuild.exe to steal browser credentials. Detections focus on identifying suspicious parent-child or ancestor-child process relationships.

- **SUSP_Execution_Technique_Strings_Oct26** (yara, medium): This rule keys on a combination of unique filenames and suspicious command-line arguments found in malware droppers and payloads as described in the report. The condition requires either a strong anchor or a robust combination of medium and supporting indicators to ensure precision.
- **MshtaSpawningShellOrScriptingProcess** (sigma, high): This rule detects the suspicious parent-child relationship where mshta.exe spawns a shell or script interpreter, a common malware execution pattern.
- **SvchostDCOMLaunchSpawningMshta** (sigma, high): This rule precisely identifies DCOM-based execution of mshta.exe by checking for the 'dcomlaunch' argument in the parent svchost.exe process.
- **MasqueradingSystemExecutableInNonStandardSystem32Subdirectory** (sigma, high): This rule keys on highly specific and anomalous file paths used for malware masquerading, making it a critical and high-confidence indicator.
- **ScheduledTaskCreationWithAdobeSecurityManagerName** (sigma, high): This rule detects a specific, non-standard scheduled task name 'AdobeSecurityManager' used by malware for persistence, making it a high-fidelity indicator.
- **NonBrowserProcessCreatingLoginDataTmp** (sigma, high): This rule detects a key step in browser credential theft by identifying the creation of 'Login Data.tmp' by any process that is not a known web browser.
