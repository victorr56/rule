# Ransomware (VT Encrypts-Files Examples)

Source: https://blog.virustotal.com/2026/11/catching-ransomware-introducing.html

This report introduces a new VirusTotal tag, `encrypts-files`, for high-confidence identification of ransomware behavior based on verified user file encryption. It uses examples from various families, including the .k404 campaign, INC Ransom, BlackWizardLock, and Heartbreaker, to illustrate the detection methodology. Artifacts include specific encrypted file extensions, ransom note names, and persistence mechanisms observed in sandbox environments.

- **MAL_BlackWizardLock_Ransomware_Nov2026** (yara, medium): This rule detects BlackWizardLock by requiring three specific but short strings: the encrypted file extension, a temporary filename pattern, and a contact handle.
- **MAL_K404_Ransomware_Nov2026** (yara, medium): This rule detects K404 ransomware components by a unique, long filename which can act as a strong anchor, despite being from prose.
- **MAL_LKD_Ransomware_Nov2026** (yara, medium): This rule detects LKD ransomware by its unique, long ransom note filename, which acts as a strong anchor despite being sourced from prose.
- **K404RansomwareExecution** (sigma, high): This rule detects the execution of a specific ransomware payload from its known installation path.
- **HeartbreakerRansomwareFileEncryption** (sigma, high): This rule detects a file extension uniquely used by the Heartbreaker macOS ransomware, a critical indicator of compromise.
- **BlackWizardLockRansomwareStagingFile** (sigma, high): This rule detects a temporary filename pattern specifically used by BlackWizardLock ransomware before encryption.
