# Kremlin RATs

Source: https://www.group-ib.com/blog/rats-nigeria/

A Nigerian threat actor, active since at least 2019, distributes various RATs including NetWire, AgentTesla, and WSHRAT through phishing campaigns. The actor favors Office exploits like CVE-2017-0199 and CVE-2017-11882 for initial access, and uses DDNS domains often containing 'kremlin', 'putin', or 'crimea' for C2 infrastructure.

- **APT_Nigerian_KremlinRATs_Campaign_Oct2026** (yara, medium): This rule detects a combination of C2-related domains, URLs, and specific filenames used across the actor's campaigns.
- **WSHRAT_C2_Check-in** (sigma, high): The combination of the unique 'WSHRAT' user agent and the '/is-ready' URI path is a high-fidelity signature for WSHRAT C2 communication.
- **KremlinRATs_Themed_C2_Domain_Query** (sigma, high): This rule detects a specific C2 domain naming pattern (`kremlin` + `duckdns.org`) consistently used by the threat actor.
- **CVE-2017-11882_Exploitation_Artifact_Drop** (sigma, high): This rule detects the creation of a specifically named file (`wd32PrvSE.wmf`) by a process associated with Office or the Equation Editor exploit (CVE-2017-11882).
- **KremlinRATs_C2_Payload_Domains** (sigma, high): This rule lists known C2, payload, and exfiltration domains associated with this threat actor, providing a high-confidence indicator of compromise.
