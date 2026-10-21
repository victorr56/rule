# IcePeony (IceCache, IceEvent, StaX)

Source: http://nao-sec.org/2024/10/IcePeony-with-the-996-work-culture.html

IcePeony is a China-nexus APT active since at least 2023 that gains access via SQL injection against public web servers, then deploys webshells and two custom malware families: the IIS module IceCache (Go, derived from reGeorge/reGeorgGo) and the passive service backdoor IceEvent, which share XOR-encoded C2 protocol and PDB paths under user 'power'. The actor uses open-source tooling (sqlmap, ProxyChains, Mimikatz, Diamorphine, craXcel, WmiExec, suo5) and a customized Stowaway variant called StaX. Detection can key on PDB paths, HTTP X-Cmd/X-Token headers and the 16-byte XOR key shared by both malware families.

- **APT_IcePeony_IceCache_IceEvent_Oct2026** (yara, high): The rule keys on unique PDB paths, a Go Build ID, and a C2 token specific to IceCache and IceEvent.
- **APT_IcePeony_StaX_Oct2026** (yara, high): This rule detects the StaX backdoor using a highly unique hardcoded key and custom function names.
- **IcePeony_IceCache_IceEvent_C2_Headers** (sigma, high): This rule detects the unique 'X-Cmd: EXEC' and 'X-Token' headers used by the IceCache and IceEvent malware for C2.
- **IcePeony_iisClient_Execution** (sigma, high): This rule detects the execution of the actor's custom 'iisClient' tool combined with specific command-line arguments.
- **IcePeony_C2_DNS** (sigma, high): This rule is a high-confidence indicator list of DNS queries for domains exclusively used by IcePeony C2 infrastructure.
- **IcePeony_Lateral_Movement_ProxyChains_sshpass** (sigma, medium): This rule detects a specific combination of tools ('proxyChains', 'sshpass', 'StrictHostKeyChecking=no') used by the actor for lateral movement.
- **IcePeony_Diamorphine_Rootkit_Download** (sigma, high): This rule detects the download of a specific rootkit ('Diamorphine.tgz') using common command-line download tools.
