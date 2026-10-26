# REF2924

Source: https://www.elastic.co/security-labs/threat-command/update-to-the-REF2924-intrusion-set-and-related-campaigns

REF2924 is an intrusion set associated with Winnti Group and ChamelGang, utilizing a trio of malware families. DOORME is a native IIS module backdoor, SIESTAGRAPH is a .NET implant that uses Microsoft Graph API for C2, and SHADOWPAD is a modular loader. The malware exhibits advanced obfuscation and persistence techniques, targeting telecommunications and government entities with apparent national strategic interests.

- **MAL_DOORME_Winnti_Oct2026** (yara, high): This rule detects DOORME using multiple highly specific artifacts, including a custom Base64 alphabet, cryptographic constants, and RTTI, any one of which is sufficient for a high-confidence match.
- **MAL_SHADOWPAD_Winnti_Oct2026** (yara, high): This rule detects SHADOWPAD using long, unique obfuscated strings and a custom format string as strong indicators, or a combination of three weaker but characteristic strings.
- **MAL_SIESTAGRAPH_Winnti_Oct2026** (yara, high): This rule for the SIESTAGRAPH .NET implant uses a unique typelib GUID as its primary detection vector, backed by a specific string combination related to its MS Graph API C2 channel.
- **Winnti_SHADOWPAD_Execution_from_OfficeDriver_Path** (sigma, high): This rule keys on the specific, non-standard full path where SHADOWPAD stages a masqueraded svchost.exe.
- **Winnti_DOORME_Backdoor_Authentication_Cookie** (sigma, high): This rule keys on a unique cookie string used by the DOORME backdoor for authentication.
- **Winnti_SHADOWPAD_Side-Loading_via_BDReinit.exe** (sigma, high): This rule keys on a specific DLL side-loading pattern: a vulnerable app loading a malicious DLL.
- **Winnti_SHADOWPAD_Payload_File_Creation** (sigma, high): This rule keys on the creation of the specific payload file by the specific loader process.
- **Post-Exploitation_Behaviour_Following_SHADOWPAD_Side-Load** (sigma, medium): This rule keys on the specific parent-child process relationship indicative of post-side-loading execution.
