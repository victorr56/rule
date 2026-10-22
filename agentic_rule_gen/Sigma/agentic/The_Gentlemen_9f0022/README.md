# The Gentlemen

Source: https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps

The Gentlemen is a RaaS operation observed using scheduled tasks for execution and persistence. Affiliates use PowerShell to disable Microsoft Defender and add broad exclusions before deploying the encryptor. Post-compromise, they clear Security, System, and Application event logs and may establish persistence via a SOCKS proxy client.

- **MAL_TheGentlemen_Encryptor_Oct2026** (yara, low): This rule detects a specific sample of The Gentlemen encryptor via its SHA256 hash, as no other stable indicators were available.
- **TheGentlemenPersistenceViaScheduledTask** (sigma, high): This rule detects the specific command line used by The Gentlemen affiliates to create a persistence task, matching the unique task name and executable path.
- **TheGentlemenSocksProxyClientExecution** (sigma, high): This rule is precise because it combines a masquerading executable path (`C:\Windows\Temp\svchost32.exe`) with specific command-line arguments.
- **TheGentlemenRansomNoteCreation** (sigma, high): This rule detects the creation of a ransom note with a name unique to The Gentlemen ransomware, which is a high-fidelity indicator of compromise.
- **TheGentlemenDisablesMicrosoftDefender** (sigma, high): This rule detects the specific combination of PowerShell commands used to disable multiple facets of Microsoft Defender, making it a strong indicator of malicious intent.
- **TheGentlemenSocksProxyC2Connection** (sigma, medium): This rule detects network connections to IP addresses specifically listed as C2 infrastructure for The Gentlemen ransomware.
