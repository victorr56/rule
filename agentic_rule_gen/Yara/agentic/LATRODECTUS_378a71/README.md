# LATRODECTUS

Source: https://www.elastic.co/security-labs/threat-command/spring-cleaning-with-latrodectus

LATRODECTUS is a lightweight malware loader, considered a potential replacement for ICEDID, that is gaining adoption in financially-motivated campaigns. It uses a small set of command handlers for system enumeration and payload execution, persists via a scheduled task, and uses RC4-encrypted C2 communications. It also contains functionality to download and execute ICEDID itself.

- **MAL_LATRODECTUS_Loader_Oct2026** (yara, medium): The rule keys on unique and supporting strings from the report's analysis, including campaign names, filenames, internal command names, and hardcoded values.
- **LATRODECTUS_Persistence_Scheduled_Task** (sigma, high): This rule detects the creation of a scheduled task with the hardcoded name "Updater" used by LATRODECTUS for persistence.
- **LATRODECTUS_AV_Discovery_Command** (sigma, high): This rule keys on a highly specific and complex command line used by LATRODECTUS for antivirus product enumeration.
- **LATRODECTUS_ICEDID_Loader_Execution** (sigma, high): This rule detects the execution of rundll32.exe with the highly specific `-zzzz=` command-line argument used by LATRODECTUS.
- **LATRODECTUS_C2_Network_Patterns** (sigma, high): This rule combines a highly specific User-Agent string and unique URI patterns associated with LATRODECTUS C2 activity.
- **LATRODECTUS_C2_Domain_Queries** (sigma, high): This rule detects DNS queries for known LATRODECTUS command and control domains, which are strong indicators of compromise.
