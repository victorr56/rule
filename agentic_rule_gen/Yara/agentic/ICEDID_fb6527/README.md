# ICEDID

Source: https://www.elastic.co/security-labs/threat-command/icedids-network-infrastructure-is-alive-and-well

ICEDID, also known as Bokbot, is a modular trojan often used to deliver secondary payloads like Cobalt Strike. Initial access is typically via phishing with a LNK file executing a loader DLL, which drops an encrypted payload as license.dat. The malware notably uses TLS certificate pinning, checking for a specific self-signed certificate subject and issuer ('CN=localhost, ... O=Internet Widgits Pty Ltd'), to validate its C2 infrastructure.

- **MAL_IcedID_Gen_Oct2026** (yara, medium): The rule keys on a highly specific hardcoded TLS certificate subject string and a code pattern related to its C2 communication, ensuring high precision.
- **ICEDID_C2_TLS_Certificate** (sigma, high): The rule keys on the highly specific Subject/Issuer fields of the self-signed TLS certificate used by ICEDID C2 servers.
- **ICEDID_Loader_Execution_via_Rundll32** (sigma, high): The rule detects a specific command line pattern combining rundll32.exe, a unique DLL name, and a specific export function.
- **ICEDID_C2_DNS_Query** (sigma, high): The rule is based on a specific C2 domain name identified as part of ICEDID infrastructure.
- **ICEDID_C2_Connection** (sigma, high): The rule is based on a specific C2 IP address identified as part of ICEDID infrastructure.
