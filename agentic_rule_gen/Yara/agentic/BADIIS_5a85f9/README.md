# BADIIS

Source: https://www.elastic.co/security-labs/threat-command/badiis-to-the-bone-new-insights-to-global-seo-poisoning-campaign

BADIIS is a malicious IIS module used by the Chinese-speaking cybercrime group REF4033 (UAT-8099) in a large-scale SEO poisoning campaign. The malware compromises Windows web servers to manipulate search engine rankings and redirect users to a network of illicit websites, including gambling platforms and cryptocurrency phishing sites. The campaign primarily targets the APAC region but has a global footprint.

- **APT_REF4033_BADIIS_Installer_Oct2026** (yara, high): This rule targets the BADIIS installer using a highly specific PDB path, which serves as a strong and unique indicator for this malware component.
- **APT_REF4033_BADIIS_ServiceDLL_Oct2026** (yara, high): This rule detects the BADIIS ServiceDLL. It keys on strong anchors like a hardcoded 16-byte SM4 key and unique configuration URLs, which can fire the rule alone, or a combination of the specific DLL name and older C2 domains.
- **BADIIS_Service_Security_Descriptor_Modification** (sigma, high): This rule detects a highly specific command line used by BADIIS to set permissions on its malicious service, combining the process name, subcommand, service name, and a unique SDDL string.
- **BADIIS_IIS_Module_Loaded** (sigma, high): This rule is precise by correlating the IIS worker process `w3wp.exe` with the loading of specific and uniquely named malicious DLLs associated with BADIIS.
- **BADIIS_Service_DLL_Dropped_In_Ringtones_Folder** (sigma, high): This rule leverages a highly anomalous and specific file path used by BADIIS to drop its service DLL, making false positives extremely improbable.
- **BADIIS_Masquerading_Driver_File_Creation** (sigma, high): This rule detects the creation of files with specific names that are close to legitimate system files but are uniquely associated with BADIIS activity.
- **BADIIS_SEO_Poisoning_Content_Request** (sigma, high): This rule detects requests for specific URI paths and filenames used by BADIIS to retrieve configuration and content for its SEO poisoning campaign.
