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
rule APT_UnnamedIAB_PHP2Shell_Toolkit_Nov2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-11-20"
        description = "Detects scripts and tools from a custom toolkit used by an IAB to exploit PHP2Shell vulnerabilities. Detection is based on combinations of unique strings and filenames. The rule fires on a combination of at least two unique script names/strings, or four other specific fragments."
        reference = "https://socradar.io/blog/php2shell-ai-agents-credential-harvesting/"
        hash1 = "d01948e930848dd139915f646760e6dba61caf3eec222d5479518c19b5076ad2"
        hash2 = "484e92ae0ceaa888459d2ad5260274923c58d8e8db5a5ff244cf7f9f90f3a1da"
        hash3 = "84f161021452e58ce65dec9fee14dd77f4968fe54d284c4059c373388a31f594"
        hash4 = "88b5ed6aa763acf5d11119d4cb53d9601533ab35371a4f5cb932991b19bfdef0"
        hash5 = "452776d0507e33e71982b0f2d7f928b1f2d60f852195b1d9aac6a5d71c019060"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        tlp = "WHITE"
        unverified_strings = "a1, a2, s1, s3, s4"

    strings:
        // Medium-strength anchors
        $a1 = "keep working autonomously until a real payout is executed" ascii  // source: explicit_literal
        $a2 = "exploit_default.py" ascii  // source: explicit_literal
        $a3 = "c2_watchdog.py" ascii  // source: figure_or_disassembly

        // Supporting strings
        $s1 = "collect.sh" ascii  // source: explicit_literal
        $s2 = "c2.py" ascii  // source: figure_or_disassembly
        $s3 = "maq" ascii  // source: explicit_literal
        $s4 = "omp" ascii  // source: explicit_literal
        $s5 = "?k=" ascii  // source: figure_or_disassembly
        $s6 = "&c=" ascii  // source: figure_or_disassembly
        $s7 = "&s=" ascii  // source: figure_or_disassembly

    condition:
        filesize < 5MB and
        (
            2 of ($a*) or
            4 of ($s*)
        )
}
