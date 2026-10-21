# FINALDRAFT

Source: https://www.elastic.co/security-labs/threat-command/fragile-web-ref7707

REF7707 is a campaign utilizing a novel malware suite including FINALDRAFT, GUIDLOADER, and PATHLOADER. The actor abuses legitimate cloud services like Microsoft Graph API for C2 and uses LOLBins like a renamed CDB.exe for execution and persistence. The malware has both Windows and Linux variants and has been observed targeting entities in South America and Southeast Asia.

- **REF7707_FINALDRAFT_CDB_Execution** (sigma, high): This rule detects the core FINALDRAFT execution command line, which is highly specific to this malware.
- **REF7707_FINALDRAFT_Persistence_Scheduled_Task** (sigma, high): This rule detects a highly specific command line used to create a persistence task for FINALDRAFT.
- **REF7707_Diskshadow_Credential_Access** (sigma, high): This rule detects a specific diskshadow command line using a non-standard script path for credential theft.
- **REF7707_Certutil_Tool_Download** (sigma, high): This rule detects the specific use of certutil to download a malicious file to a known path.
- **REF7707_C2_Domains** (sigma, high): This rule detects DNS queries for domains exclusively used by the REF7707 threat actor.
- **REF7707_C2_IPs** (sigma, high): This rule detects network connections to IP addresses exclusively used by the REF7707 threat actor.
