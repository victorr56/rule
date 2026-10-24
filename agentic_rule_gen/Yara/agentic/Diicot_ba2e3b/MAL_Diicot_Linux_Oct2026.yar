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
rule MAL_Diicot_Linux_Oct2026
{
    meta:
        description = "Detects Diicot malware targeting Linux systems. The rule matches on ELF files containing a highly specific error message, hardcoded cloud kernel versions, or unique C2 paths. A match requires one strong anchor string, or a combination of several other characteristic strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.wiz.io/blog/diicot-threat-group-malware-campaign"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "$x2, $x4, $s1, $s2, $s5, $s8"

    strings:
        // Strong anchors (>=16 bytes, highly specific). One is sufficient.
        $x1 = "/root/skema/brute-spreader.go:218: E de la crontab uid0" ascii // source: figure_or_disassembly
        $x2 = "4.14.47-64.38.amzn2.x86_64" ascii // source: explicit_literal
        $x3 = "/.NzJjOTY/.diicot" ascii // source: strings_listing
        $x4 = "4.15.0-1013-azure" ascii // source: explicit_literal

        // Supporting strings. Require combinations.
        $s1 = "brute-spreader.go" ascii // source: prose
        $s2 = "x86_64-linode105" ascii // source: explicit_literal
        $s3 = "/.NzJjOTY/.balu" ascii // source: strings_listing
        $s4 = "/.NzJjOTY/kuak" ascii // source: strings_listing
        $s5 = "brute-retea" ascii // source: prose
        $s6 = "/save-data" ascii // source: figure_or_disassembly
        $s7 = "awsgui" ascii // source: strings_listing
        $s8 = "curl/7.68.0" ascii // source: explicit_literal

    condition:
        uint32(0) == 0x464c457f and filesize < 10MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
