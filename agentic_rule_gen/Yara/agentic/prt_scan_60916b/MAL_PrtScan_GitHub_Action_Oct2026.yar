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
rule MAL_PrtScan_GitHub_Action_Oct2026 {
    meta:
        description = "Detects prt-scan malware, a supply chain attack payload targeting GitHub Actions. A match requires a PE/ELF/Mach-O header and is triggered by one unique string or four supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.wiz.io/blog/six-accounts-one-actor-inside-the-prt-scan-supply-chain-campaign"
        date = "2024-05-29"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "$x3, $x4, $x5, $s3"

    strings:
        // Strong anchors (unique, >=16 chars)
        $x1 = "/contents/.github/workflows/.prt_tmp_" ascii  // source: figure_or_disassembly
        $x2 = "secrets\\\\.([A-Za-z_][A-Za-z0-9_]*)" ascii  // source: figure_or_disassembly
        $x3 = "@codfish/eslint-config" ascii  // source: prose
        $x4 = "@codfish/actions" ascii  // source: prose
        $x5 = ".PHONY: __prt_exfil" ascii // source: prose

        // Supporting strings
        $s1 = "DEEPSEEK" ascii  // source: figure_or_disassembly
        $s2 = "COHERE" ascii  // source: figure_or_disassembly
        $s3 = "0.0.0-PR-" ascii  // source: prose
        $s4 = "/actions/organization-secrets" ascii  // source: figure_or_disassembly
        $s5 = "/repos/$REPO/labels" ascii  // source: figure_or_disassembly

    condition:
        (
            uint16(0) == 0x5a4d or // PE
            uint32(0) == 0x464c457f or // ELF
            uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe // Mach-O
        )
        and filesize < 500KB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
