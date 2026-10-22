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
rule MAL_SUDDENICON_macOS_Oct2026 {
    meta:
        description = "Detects SUDDENICON macOS components. This rule triggers on a unique RC4 key or the co-occurrence of three specific filenames."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-users-protected-from-suddenicon-supply-chain-attack"
        date = "2026-10-22"
        hash1 = "92005051ae314d61074ed94a52e76b1c3e21e7f0e8c1d1fdd497a006ce45fa61"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1"

    strings:
        $x1 = "3jB(2bsG#@c7" ascii  // source: explicit_literal

        $s1 = "UpdateAgent" ascii  // source: figure_or_disassembly
        $s2 = ".main_storage" ascii  // source: figure_or_disassembly
        $s3 = ".session-lock" ascii  // source: figure_or_disassembly

    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcffaedfe) and
        filesize < 20MB and
        (
            $x1 or
            3 of ($s*)
        )
}
