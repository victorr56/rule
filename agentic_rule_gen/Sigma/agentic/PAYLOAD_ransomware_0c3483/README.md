# PAYLOAD ransomware

Source: https://securelist.com/tr/payload-ransomware-via-group-policy/121335/

PAYLOAD ransomware operators hijacked Active Directory Group Policy, authoring a domain-root GPO named PAYLOAD that dropped ransom notes, replaced wallpaper/lock screen, enforced a logon banner and disabled local administrator accounts domain-wide without any malicious binary on endpoints. A second GPO ('win Firewall Off') disabled Windows Firewall, and data was exfiltrated before a one-day delayed detonation on reboot. Detection depends on directory service change auditing (5136/5137/5141) and SYSVOL integrity monitoring rather than file/process indicators.

- **PAYLOAD_Ransomware_GPO_Creation_In_SYSVOL** (sigma, high): This rule detects the creation of the malicious GPO folder in SYSVOL by its unique, actor-specific GUID, making it a high-fidelity indicator.
- **PAYLOAD_Ransomware_Logon_Banner_Set_Via_GPO** (sigma, high): This rule detects the highly specific text of the PAYLOAD ransom message being written to the system's legal notice registry values.
- **PAYLOAD_Ransomware_Artifacts_Staged_In_SYSVOL** (sigma, medium): This rule detects specific filenames used by the actor being created in a sensitive SYSVOL location, combining path context and name for precision.
- **PAYLOAD_Ransomware_C2_Communication** (sigma, medium): This rule detects network connections to a list of IP addresses that were explicitly listed as IOCs for the PAYLOAD ransomware campaign.
