# NETWIRE

Source: https://www.elastic.co/security-labs/blog/netwire-dynamic-configuration-extraction

NETWIRE is a commodity RAT that uses RC4 to encrypt its configuration, which is stored in the PE file's .data section. Persistence can be achieved through methods like Run keys or Active Setup. The configuration contains C2 servers, a unique Host ID, and paths for keylogging data.

- **MAL_NETWIRE_Gen_Oct2026** (yara, medium): The rule detects NETWIRE using strong anchors: two 22-byte unique hex patterns and three highly distinctive format strings.
- **NetWireRegistryKey** (sigma, high): This rule detects the creation of the hardcoded `SOFTWARE\NetWire` registry key, a high-fidelity indicator for this malware family.
- **NetWireC2IPs** (sigma, high): This rule detects network connections to a list of specific C2 IP addresses used by NetWire RAT.
