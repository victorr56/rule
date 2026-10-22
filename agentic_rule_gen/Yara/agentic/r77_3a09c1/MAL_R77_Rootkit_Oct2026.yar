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
rule MAL_R77_Rootkit_Oct2026
{
    meta:
        description = "Detects components of the r77 open-source rootkit. The rule requires three of several strings related to its configuration and component names."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-security-labs-steps-through-the-r77-rootkit"
        date = "2026-10-22"
        hash1 = "916c805b0d512dd7bbd88f46632d66d9613de61691b4bd368e4b7cb1f0ac7f60"
        hash2 = "9fb38412cac94255a3abbec80f15620098a0c85247690850c302a9ff060b5c0c"
        hash3 = "91c6e2621121a6871af091c52fafe41220ae12d6e47e52fd13a7b9edd8e31796"
        hash4 = "96849108e13172d14591169f8fdcbf8a8aa6be05b7b6ef396d65529eacc02d89"
        hash5 = "a7e31abe10be6bca44f0a846d631e578efe78c14f6bf1cf834cfb15469fc1d3a"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2, s3, s4, s5"

    strings:
        $s1 = "$77config" ascii wide      // source: prose
        $s2 = "svc32" ascii wide          // source: explicit_literal
        $s3 = "svc64" ascii wide          // source: explicit_literal
        $s4 = "$77_Install" ascii wide   // source: prose
        $s5 = "$77_Loader" ascii wide    // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        3 of them
}
