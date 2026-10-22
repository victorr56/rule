# INC Ransomware

Source: https://socradar.io/blog/inc-gentlemen-ransomware-ai-infrastructure/

Affiliates of INC and The Gentlemen ransomware groups operated an AI-driven intrusion ecosystem featuring custom tooling like the Phantom framework, Ghost C2, and RevSocks. The operation, exposed via an open C2 server, relied on exploiting edge devices like FortiClient EMS and SimpleHelp, with AI managing reconnaissance, command generation, and data triage. The final payload was the INC Ransomware, with dozens of builds staged for deployment.

- **MAL_IncRansomware_Gen_Oct2026** (yara, medium): The rule keys on two unique, long strings and a fallback combination of three specific indicators: the ransom note name, the encrypted file extension, and an IOCTL constant used for shadow copy deletion.
- **INC_Gentlemen_C2_DNS_Query** (sigma, high): This rule keys on a list of actor-controlled C2 and data leak site domains.
- **INC_Gentlemen_C2_Network_Connection** (sigma, high): This rule keys on a list of actor-controlled C2 and infrastructure IP addresses.
- **INC_Ransomware_Persistence_Scheduled_Task** (sigma, high): This rule detects the specific command line used to create a persistence scheduled task.
- **INC_Ransomware_Note_Creation** (sigma, high): This rule keys on the specific ransom note filename `INC-README.txt`.
- **INC_Ransomware_File_Encryption** (sigma, high): This rule keys on the ransomware-specific file extension `.INC` added to encrypted files.
