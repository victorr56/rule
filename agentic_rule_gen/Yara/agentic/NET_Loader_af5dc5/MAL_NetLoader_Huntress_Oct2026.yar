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
rule MAL_NetLoader_Huntress_Oct2026
{
    meta:
        description = "Detects .NET loader described by Huntress, which can be identified by specific encryption artifacts, obfuscated names, and URL paths. The condition requires one strong anchor or three supporting strings to fire."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/malspam-to-loader-delivery-chain-analysis"
        date = "2026-10-17"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, x2, s1, s3, s4, s5, s6"

    strings:
        // Strong anchors (>=16 bytes, distinctive)
        $x1 = "lHxoBf+5Ft6YrDx4FyDWwg==" ascii wide  // source: explicit_literal
        $x2 = "/GpazlLUWIJ_14_05_Meus_ArquivosDeTexto/03.txt" ascii wide  // source: prose

        // Supporting strings
        $s1 = "nFukcUaa5h0=" ascii wide  // source: explicit_literal
        $s2 = "VirteyQDs64x" ascii wide  // source: figure_or_disassembly
        $s3 = "ClassLibrary3.Class1" ascii wide  // source: prose
        $s4 = "Update Drivers NVIDEO_" ascii wide  // source: prose
        $s5 = "/c84da/bl.txt" ascii wide  // source: prose
        $s6 = "any.run" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB
        and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
