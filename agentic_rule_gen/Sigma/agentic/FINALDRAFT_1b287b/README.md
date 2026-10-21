# FINALDRAFT

Source: https://www.elastic.co/security-labs/threat-command/finaldraft

FINALDRAFT is a modular post-exploitation toolkit with Windows and Linux variants, attributed to the REF7707 activity cluster. It primarily uses the Microsoft Graph API to communicate via Outlook email drafts for command and control. The malware supports various commands for process injection, file system manipulation, and data proxying, and can load additional modules for network enumeration and pass-the-hash attacks.

- **APT_FINALDRAFT_PATHLOADER_Oct2026** (yara, high): This rule targets the FINALDRAFT PATHLOADER component using highly specific, actor-unique C2 configuration strings and URI paths found in the binary.
- **APT_FINALDRAFT_Core_Oct2026** (yara, medium): This rule detects core FINALDRAFT components using a unique named pipe GUID as a strong indicator, or a combination of several other specific strings like a hardcoded password, export names, and filenames.
- **FINALDRAFT_Named_Pipes** (sigma, high): This rule detects highly specific named pipes (GUIDs) created by different FINALDRAFT modules.
- **FINALDRAFT_C2_Domains** (sigma, high): This rule detects DNS queries for a list of typo-squatted C2 domains unique to FINALDRAFT.
- **FINALDRAFT_Linux_Token_File** (sigma, medium): This rule detects file creation at unusual paths used by the FINALDRAFT Linux variant to cache OAuth tokens.
- **FINALDRAFT_Windows_Token_Registry** (sigma, medium): This rule uses a regular expression to detect registry writes to the specific key path FINALDRAFT uses for token storage.
- **FINALDRAFT_DLL_Load** (sigma, medium): This rule detects the loading of a specifically named DLL used in older FINALDRAFT versions.
- **FINALDRAFT_PATHLOADER_URI** (sigma, high): This rule detects a highly specific and random-looking URI path used by the FINALDRAFT-associated PATHLOADER.
