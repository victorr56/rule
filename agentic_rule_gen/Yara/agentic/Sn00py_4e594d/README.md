# Sn00py

Source: https://securelist.com/citrus-ransomware/121879/

Citrus is a threat group deploying Sn00py ransomware for impact. They gain initial access via compromised contractor accounts, use tools like Impacket and Xray for lateral movement and C2, and leverage LLMs to generate scripts for enumeration and GPO deployment.

- **MAL_Sn00py_Ransomware_Nov2026** (yara, high): This rule detects the Sn00py ransomware binary through a unique console message and parts of a hardcoded public key, providing high-confidence detection.
- **APT_Citrus_LLM_Gen_Script_Nov2026** (yara, medium): This rule detects scripts used by Citrus based on highly specific comments that indicate generation by a large language model.
- **APT_Citrus_Activity_Nov2026** (yara, medium): This rule detects various Citrus group activities by keying on a highly specific certificate attribute used in an exploit, or a combination of other unique strings.
- **Sn00py_Ransomware_Note** (sigma, high): This rule detects the specific ransom note filename for Sn00py ransomware, which is a high-confidence indicator of compromise.
- **Citrus_Scheduled_Task_Creation** (sigma, high): This rule detects the creation of scheduled tasks via registry modifications using a list of highly specific task names associated with the Citrus group.
- **Citrus_Domain_Admin_Discovery** (sigma, high): This rule detects a specific discovery command line containing the Cyrillic string for "Domain Admins", which is a strong behavioral indicator for this actor.
- **Citrus_GPO_Deployment_Script_Drop** (sigma, high): This rule detects a specific file path pattern for a malicious GPO deployment script dropped by a self-extracting archive, a unique TTP of this actor.
- **Citrus_C2_Network_Connection** (sigma, high): This rule detects network connections to IP addresses specifically identified as C2 infrastructure for the Citrus group.
