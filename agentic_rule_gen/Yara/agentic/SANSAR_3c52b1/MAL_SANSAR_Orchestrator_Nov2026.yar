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
rule MAL_SANSAR_Orchestrator_Nov2026
{
    meta:
        description = "Detects the SANSAR cryptominer orchestrator based on a unique code sequence and version string."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        date = "2026-11-20"
        hash1 = "00c9ac44291f83c72d54302e99d155a3e26d02225a3e516764d5833a99657c9e"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x2"

    strings:
        $x1 = { 8A 0A 88 4C 24 ?? 44 8A 5C 24 ?? 8D 48 01 44 89 DB D2 EB 34 07 89 C1 41 D2 E3 41 08 DB 89 F0 83 E0 1F 46 32 1C 10 44 88 1C 37 48 FF C6 48 FF C2 }  // source: strings_listing
        $x2 = "sansar-client v0.1.3" ascii  // source: prose

    condition:
        uint32(0) == 0x464c457f and
        filesize < 20MB and
        1 of ($x*)
}
