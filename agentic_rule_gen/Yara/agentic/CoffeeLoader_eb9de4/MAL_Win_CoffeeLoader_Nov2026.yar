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
rule MAL_Win_CoffeeLoader_Nov2026
{
    meta:
        description = "Detects CoffeeLoader malware based on unique cryptographic keys, network indicators, and other constants. The rule can be triggered by one of several unique keys/strings, or a combination of a magic constant and other supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/retadup-delivers-coffeeloader/121908/"
        date = "2026-11-20"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, x2, x3, c1, s1, s2"

    strings:
        // Strong anchors, >= 16 chars
        $x1 = "RUNTMSAAAAC2gVlbqvpsSutLE0/4ogdQ20Uw4qQyQQCw7448NvjMOaYWr+mlrvWiDCg79jWIhjiIuGuqxTb9VMsuceH4WyA5" ascii wide  // source: explicit_literal
        $x2 = "A21251838432306F2CD2540593656B9E" ascii wide  // source: explicit_literal
        $x3 = "2026F751079659CF71C7BA64B345C12A" ascii wide  // source: explicit_literal
        $x4 = "/payload?md5=00000000000000000000000000000000" ascii wide  // source: figure_or_disassembly

        // Constants
        $c1 = { 71 78 D5 D1 }  // source: explicit_literal, 0xD1D57871 little-endian

        // Supporting
        $s1 = "SetCodecs" ascii wide  // source: explicit_literal
        $s2 = "b79faace.dll" ascii wide  // source: explicit_literal
        $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        (
            1 of ($x*) or
            ($c1 and 2 of ($s*))
        )
}
