# REF0657

Source: https://www.elastic.co/security-labs/threat-command/unmasking-financial-services-intrusion-ref0657

REF0657 is an intrusion set observed targeting a financial services organization, characterized by a 'smash-and-grab' style. The actor leveraged Microsoft SQL Server (xp_cmdshell) for initial execution, followed by a wide array of open-source tools for proxying, lateral movement, and credential dumping. The final payload was Cobalt Strike, delivered via DLL side-loading, with data exfiltration conducted using a masqueraded MEGA command-line utility.

- **REF0657_Persistence_Via_Mixed_Vendor_Run_Key** (sigma, high): This rule detects a highly specific persistence mechanism combining a Run key value name ('TrendMicro') with a path that suspiciously mixes two different security vendor names ('McAfee' and 'TrendMicro').
- **REF0657_Cobalt_Strike_Sideload_DLL_Drop** (sigma, high): This rule is precise because it detects the creation of a commonly abused DLL ('msvcp140.dll') within a highly anomalous file path that combines the names of two unrelated security vendors.
- **Masqueraded_Mega_Client_Exfiltration** (sigma, high): This rule detects a specific command-line pattern for the MEGAcmd tool ('copy' and 'mega_temp:') being executed by a process named 'ms_edge.exe' running from a non-standard path.
- **Microsoft_SQL_Server_Spawning_Command_Shell** (sigma, high): This rule is based on the highly suspicious parent-child process relationship between the SQL Server ('sqlservr.exe') and the command-line interpreter ('cmd.exe'), a classic sign of xp_cmdshell execution.
- **Rakshasa_Proxy_Tool_Execution** (sigma, high): This rule is precise by combining the executable path ('Users\Public\Downloads\ra.exe') with a specific command-line switch ('-d') used by the Rakshasa proxy tool.
