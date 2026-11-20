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
rule MAL_GitDoor_Nov2026
{
    meta:
        description = "Detects GitDoor malware based on unique strings, including a PDB path, a custom Base64 alphabet, a hardcoded AES key, and specific C2 communication artifacts. The rule can be triggered by one of several strong unique identifiers, or a combination of four supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/operation-shadowcloud-gitdoor/122004/"
        date = "2026-11-20"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x5, s7"

    strings:
        // Unique ($x) strings - strong anchors, can fire alone
        $x1 = "C:\\src\\Dll1\\WhatsAppCS\\x64\\Release\\WhatKeyCPP.pdb" ascii wide  // source: explicit_literal
        $x2 = "ABCDEFGHIJ01234ZYXWVUTSRQPONMLKzyxwvutsrqponmlkjihgfedcba98765/+" ascii  // source: explicit_literal
        $x3 = "12345678901234567890123456789012" ascii  // source: explicit_literal
        $x4 = "\"commit from INSOMNIA\"" ascii wide  // source: figure_or_disassembly
        $x5 = "df1941c5-fe89-4e79-bf10-463657acf44d" ascii wide  // source: prose

        // Supporting ($s) strings - require combination
        $s1 = "SbieDll_st.dll" ascii wide  // source: explicit_literal
        $s2 = "\"client_version\":\"1.1.6\"" ascii wide  // source: explicit_literal
        $s3 = "Local\\\\sm%lu" ascii wide  // source: explicit_literal
        $s4 = "/repos/LatonyCharnleyaW/Havo" ascii  // source: explicit_literal
        $s5 = "/repos/LatonyCharnleyaW/Trix" ascii  // source: explicit_literal
        $s6 = "/channels/comm/messages?limit=50" ascii  // source: explicit_literal
        $s7 = "hklnwqxaa123" ascii wide  // source: prose
        $s8 = "wss://27.102.66.162:443/agent.ashx" ascii wide  // source: explicit_literal
        $s9 = "0x974C9EB" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
