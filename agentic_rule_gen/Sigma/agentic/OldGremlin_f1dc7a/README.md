# OldGremlin

Source: https://www.group-ib.com/blog/oldgremlin/

OldGremlin is a Russian-speaking threat actor notable for targeting Russian entities, violating the unspoken rule of not attacking within post-Soviet countries. They conduct spear-phishing campaigns using custom backdoors (TinyNode, TinyPosh) for initial access, leverage Cobalt Strike for lateral movement, and deploy their custom ransomware, TinyCryptor, for financial gain. The group is classified as a 'Big Game Hunting' operator.

- **OldGremlin_Ransomware_Deployment_Via_PsExec** (sigma, high): This rule detects a specific process lineage where the PsExec service executable `PSEXESVC.exe` launches the OldGremlin ransomware `TinyCryptor.exe`, a highly specific indicator of compromise.
- **OldGremlin_Malware_Process_Creation** (sigma, high): This rule detects the execution of processes matching the names of OldGremlin's custom malware suite, which are specific enough to provide a high-confidence signal.
- **OldGremlin_Persistence_Via_HKCU_Security_Key** (sigma, medium): This rule keys on the creation of a registry key at `HKCU\Software\Microsoft\Windows\Security`, an unconventional path observed being used by OldGremlin.
- **OldGremlin_Persistence_Via_HKCU_Registered_Key** (sigma, medium): This rule detects the creation of a registry key at `HKCU\Software\Classes\Registered`, an unusual path for persistence or configuration used by OldGremlin.
- **OldGremlin_C2_Domain_Query** (sigma, high): This rule detects DNS queries for `rbcholding.press`, a specific C2 domain associated with OldGremlin operations.
- **OldGremlin_C2_Network_Connection** (sigma, high): This rule detects network connections to a list of specific IP addresses identified as C2 servers for the OldGremlin group.
