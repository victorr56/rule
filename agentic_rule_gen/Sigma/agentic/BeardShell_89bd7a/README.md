# BeardShell

Source: https://www.welivesecurity.com/en/eset-research/sednit-reloaded-back-trenches/

Sednit (APT28) has resurged with a modern toolkit featuring the custom BeardShell backdoor and a heavily modified version of the open-source Covenant framework. These implants are deployed in tandem, using different legitimate cloud services like Icedrive and Filen for resilient C2. The new tools show code lineage to older Sednit malware like Xagent and Xtunnel, indicating continuity in the group's development team.

- **Sednit_BeardShell_Implant_Load** (sigma, high): This rule detects the specific combination of a parent process guardrail and a misspelled but legitimate-looking DLL used by the BeardShell implant.
- **Sednit_SlimAgent_Implant_Load** (sigma, medium): This rule detects the suspicious loading of an IIS-related DLL (`eapphost.dll`) into the `explorer.exe` process, a known TTP for SlimAgent.
- **Sednit_SlimAgent_Component_File_Creation** (sigma, high): This rule keys on the highly specific and suspicious internal component name `RemoteKeyLogger.dll`, which is indicative of malicious tooling.
