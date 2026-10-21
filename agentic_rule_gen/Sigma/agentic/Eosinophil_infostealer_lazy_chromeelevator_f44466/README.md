# Eosinophil infostealer (lazy/chromeelevator)

Source: https://blog.virustotal.com/2026/01/malicious-infostealer-january-26.html

A January 2026 campaign distributes ZIP archives impersonating Malwarebytes (and other software) installers that use DLL sideloading of a malicious CoreMessaging.dll to drop final-stage infostealers. The malicious DLLs are identifiable by shared metadata signature strings and unusual alphanumeric export names. Dropped payloads exfiltrate browser credentials, MFA and cryptocurrency wallet data.

- **MAL_Eosinophil_CoreMessaging_Sideload_Jan2026** (yara, high): The rule keys on highly unique export names and metadata strings from the malicious CoreMessaging.dll.
- **Eosinophil_Sideloading_CoreMessaging** (sigma, high): This rule detects the core DLL sideloading behavior by matching `CoreMessaging.dll` loaded from outside its legitimate `System32` path.
- **Eosinophil_Payload_Execution** (sigma, medium): This rule uses a regular expression to detect the execution of payloads with a specific random naming convention from the `C:\Windows` directory.
- **Eosinophil_Lure_File** (sigma, medium): This rule detects the creation of the specific lure ZIP filename pattern used to distribute the malware.
