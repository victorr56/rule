# Lindnor

Source: https://www.security.com/threat-intelligence/lindnor-new-backdoor-anubis-ransomware

The Hawkmoth threat actor deployed a new custom backdoor, Lindnor, in an attack leading to Anubis ransomware. Lindnor masquerades as legitimate software, collects system information, and communicates with C2 servers over port 443. The attackers also used numerous security-disabling tools, favoring a Bring Your Own Vulnerable Driver (BYOVD) approach and configuring AnyDesk to run in Safe Mode for persistent access.

- **Hawkmoth_AnyDesk_Safe_Mode_Persistence** (sigma, high): This rule detects the specific registry key and value set to enable AnyDesk persistence in Safe Mode, a high-confidence indicator of compromise.
- **Hawkmoth_AnyDesk_Safe_Mode_Persistence_Command** (sigma, high): This rule detects the exact command line used to enable AnyDesk persistence in Safe Mode, providing high-precision detection of the attacker's action.
- **Hawkmoth_BYOVD_Vulnerable_Driver_Load** (sigma, high): This rule keys on the loading of specific vulnerable driver filenames, a strong indicator of a Bring Your Own Vulnerable Driver (BYOVD) attack.
- **Hawkmoth_Lindnor_Tooling_Execution** (sigma, high): This rule keys on a list of specific executable filenames used by the Hawkmoth actor's tooling, providing broad coverage for multiple malware components.
- **Hawkmoth_Lindnor_C2_DNS_Query** (sigma, high): This rule detects network callouts to specific C2 domains associated with the Lindnor backdoor, indicating a potential implant on the host.
