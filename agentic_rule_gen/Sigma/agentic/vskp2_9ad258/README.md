# vskp2

Source: https://securelist.com/storm-2603-fileless-toolshell-attack/121467/

Storm-2603 exploited SharePoint vulnerabilities to deploy a fileless .NET webshell, tracked as vskp2, directly into the w3wp.exe memory space. The webshell uses a custom VirtualPathProvider for runtime persistence and acts as a proxy to pivot into the internal network. Post-exploitation activity involved abusing legitimate tools like Velociraptor, Zoho Assist, and Cloudflare Tunnel for access and command execution, with the ultimate goal of deploying Warlock ransomware.

- **Storm2603_PostExploitation_IIS_Spawn_MsiExec** (sigma, high): This rule detects an IIS worker process spawning `msiexec.exe`, a rare and suspicious process lineage observed in Storm-2603's post-exploitation phase.
- **Storm2603_VulnerableDriver_rsndispot_sys** (sigma, high): This rule detects the creation of a specific vulnerable driver file by path, a high-confidence indicator of Storm-2603 activity.
- **Storm2603_MsiExec_Tool_Installation** (sigma, high): This rule targets specific command lines used to download Storm-2603's malicious MSI packages, providing a high-confidence detection.
- **Storm2603_C2_IPs** (sigma, high): This rule detects network connections to a list of known malicious IP addresses associated with the Storm-2603 campaign.
- **Storm2603_Payload_URLs** (sigma, high): This rule detects web requests to the full, specific URLs used by Storm-2603 to host malicious MSI installers.
