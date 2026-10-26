/* Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $x, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
rule MAL_GHOSTPULSE_Loader_Oct2026
{
    meta:
        description = "Detects GHOSTPULSE (aka HIJACKLOADER) malware based on unique code patterns."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/tricks-and-treats"
        date = "2026-10-26"
        hash1 = "57ebf79c384366162cb0f13de0de4fc1300ebb733584e2d8887505f22f877077"
        hash2 = "b54d9db283e6c958697bfc4f97a5dd0ba585bc1d05267569264a2d700f0799ae"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = { 49 63 D0 42 8B 0C 0A 41 03 CA 89 0C 1A 8B 05 ?? ?? ?? ?? 44 03 C0 8B 05 ?? ?? ?? ?? 44 3B C0 }  // source: strings_listing
        $x2 = { 48 89 01 48 8B 84 24 D8 00 00 00 48 8B 4C 24 78 8B 49 0C 89 08 C7 44 24 44 00 00 00 00 }  // source: strings_listing
        $x3 = { 48 83 EC 18 C7 04 24 00 00 00 00 8B 04 24 48 8B 4C 24 20 0F B7 04 41 85 C0 74 0A 8B 04 24 FF C0 89 04 24 EB E6 C7 44 24 08 00 00 00 00 8B 04 24 FF C8 8B C0 48 8B 4C 24 20 0F B7 04 41 83 F8 5C }  // source: strings_listing

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        1 of ($x*)
}
