# DarkVigil

Source: https://www.welivesecurity.com/en/eset-research/slippynunchucks-hijacks-sogou-input-methods-brand-promotion-mechanism-to-distribute-malware/

SlippyNunchucks deploys the DarkVigil malware by hijacking DNS requests from the Sogou Input Method to serve a malicious configuration. This configuration causes a legitimate, signed Adobe binary to be downloaded and used to side-load the DarkVigil DLL implant. The .NET-based implant uses the Duplex Message Transport Protocol (DMTP) for C2 communications and plugin orchestration.

- **SlippyNunchucks_Malware_Execution_Via_SogouComMgr** (sigma, high): This rule keys on a highly specific command line used to trigger the DLL side-loading of the DarkVigil payload; the combination of process and arguments is unique to this threat.
- **SlippyNunchucks_Configuration_Update_Via_SGTool** (sigma, high): This rule detects the specific command line used to initiate the malicious configuration download, a key early step in the infection chain.
- **SlippyNunchucks_DarkVigil_DLL_Drop** (sigma, high): This rule detects the malicious `libcef.dll` being dropped into a specific path used by the actor, which is a strong indicator of compromise.
- **SlippyNunchucks_Plugin_Storage_in_Registry** (sigma, medium): This rule detects a registry pattern used by the malware to store components, a specific behavior related to its operation on the host.
- **SlippyNunchucks_Hijacking_Domain_DNS_Query** (sigma, high): This rule keys on a DNS query for an attacker-controlled domain specifically registered to impersonate a legitimate service.
- **SlippyNunchucks_C2_and_Staging_IP_Connection** (sigma, high): This rule detects network connections to a list of known malicious IP addresses used by the actor for staging and C2.
