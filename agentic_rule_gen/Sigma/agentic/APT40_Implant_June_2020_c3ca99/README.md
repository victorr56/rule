# APT40 Implant June 2020

Source: https://www.elastic.co/security-labs/threat-command/advanced-techniques-used-in-malaysian-focused-apt-campaign

APT40 targets Malaysian entities using a phishing document that leverages remote template injection to execute macro code. The macro drops and runs DLLs that perform DLL side-loading to execute a second-stage backdoor. The backdoor establishes persistence via a Run key and communicates with a C2 server using AES-encrypted traffic.

- **APT40_Persistence_ntkd_Run_Key** (sigma, high): This rule targets the highly specific registry value name 'ntkd' used by APT40 for persistence, making it a high-confidence indicator.
- **APT40_SideLoad_LogiMailApp** (sigma, high): This rule detects a specific DLL side-loading combination used by APT40, correlating the parent process with the loaded DLL for high precision.
- **APT40_C2_Domains_June_2020** (sigma, high): This rule keys on specific, actor-controlled dynamic DNS domains used for C2, which are high-confidence indicators of compromise.
- **APT40_Second_Stage_Payload_Drop** (sigma, high): This rule detects the creation of a file with a highly unusual and specific name, `~liseces1.pcs`, used as a second-stage payload by APT40.
- **APT40_Implant_Drop_Public_Folder** (sigma, medium): This rule detects specific filenames created in the C:\Users\Public folder, a combination indicative of the APT40 implant's initial drop.
