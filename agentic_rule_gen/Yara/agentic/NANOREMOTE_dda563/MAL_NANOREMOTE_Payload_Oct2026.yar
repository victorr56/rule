/*
 Self-check
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
rule MAL_NANOREMOTE_Payload_Oct2026
{
    meta:
        description = "Detects the NANOREMOTE payload based on unique keys, strings, and C2 artifacts. The rule can be triggered by one of several strong unique strings, or a combination of four supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/nanoremote"
        date = "2026-10-29"
        hash1 = "57e0e560801687a8691c704f79da0c1dbdd0f7d5cc671a6ce07ec0040205d728"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, s1, s2, s3, s4, s5, s6"

    strings:
        // Strong unique strings (>= 16 bytes)
        $x1 = "558bec83ec40535657833d7440001c00" ascii  // source: explicit_literal
        $x2 = "%d%02d%02d%02d%02d%02d_sv.dmp" ascii  // source: explicit_literal

        // Supporting strings
        $s1 = "NanoRemote/1.0" ascii  // source: explicit_literal
        $s2 = "/api/client" ascii  // source: explicit_literal
        $s3 = "|*|" ascii  // source: explicit_literal
        $s4 = "|-|" ascii  // source: explicit_literal
        $s5 = "WinREVersion" ascii wide  // source: prose
        $s6 = "ProductName" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
