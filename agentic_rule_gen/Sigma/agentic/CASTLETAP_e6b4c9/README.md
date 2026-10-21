# CASTLETAP

Source: https://www.wiz.io/blog/agentless-threat-hunting-fortigate

Threat-hunting profile for exploitation and post-exploitation of internet-facing FortiGate firewalls, covering credential stuffing, rogue super_admin account creation, certificate manipulation, NAT/port-forward backdoors, full-config exfiltration, and FortiManager script abuse. Hunting relies on FortiGate local logs (log IDs 32001/32002/32003, 44546/44547/44548, 41987/41990, 32095, 32052) and FortiManager CDB object-change events to correlate logins with config changes. UNC3886 used FortiManager script deployment to drop the CASTLETAP backdoor (/bin/fgfm) with ICMP port-knocking C2 visible only in local traffic logs.

- **UNC3886_CASTLETAP_Backdoor_Execution** (sigma, high): This rule detects the execution of the CASTLETAP backdoor by its unique and specific file path, which is a critical indicator of compromise.
- **UNC3886_FortiGate_Rogue_Cert_Gen** (sigma, high): This rule keys on a highly specific command line for rogue certificate generation, including unique strings like 'Attacker Org' and 'attacker.local'.
- **UNC3886_Malicious_SSO_Email_In_CLI** (sigma, high): This rule detects known UNC3886-associated email addresses in command lines, a strong indicator of rogue administrator account creation.
- **UNC3886_FortiGate_Config_Exfil** (sigma, medium): This rule combines a specific, sensitive command ('show full-configuration') with plausible parent processes on a Linux-based appliance, indicating potential configuration theft.
- **UNC3886_Associated_Credential_Stuffing_IP** (sigma, high): This rule detects connections to a list of IP addresses specifically identified as infrastructure for UNC3886 credential stuffing campaigns.
- **UNC3886_Associated_Email_Domains** (sigma, medium): This rule detects DNS lookups for email domains known to be used by UNC3886 for creating rogue administrator accounts.
