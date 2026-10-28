# rope.pyz

Source: https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack

TeamPCP compromised the `durabletask` PyPi package to distribute a Linux worm. The payload, `rope.pyz`, steals credentials for various cloud services and password managers, and propagates using AWS SSM and Kubernetes. It exfiltrates data to hardcoded C2 servers and uses specific file paths as infection markers.

- **Linux_TeamPCP_RopePyz_Execution** (sigma, high): This rule detects the specific command line used to execute the TeamPCP payload, combining the interpreter with the malicious script path.
- **Linux_TeamPCP_RopePyz_Infection_Markers** (sigma, high): This rule detects the creation of highly specific hidden files used by the malware to mark an infected system.
- **Linux_TeamPCP_RopePyz_State_File_Creation** (sigma, high): This rule detects a highly specific file path created by the malware to track its lateral movement activities via AWS SSM.
- **TeamPCP_RopePyz_C2_DNS_Query** (sigma, high): This rule detects DNS queries to actor-controlled C2 domains, which are a strong indicator of compromise.
- **TeamPCP_RopePyz_C2_Connection** (sigma, high): This rule detects network connections to a known actor-controlled C2 IP address, a strong indicator of compromise.
