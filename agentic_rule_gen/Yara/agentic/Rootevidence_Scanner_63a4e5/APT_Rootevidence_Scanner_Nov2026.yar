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
rule APT_Rootevidence_Scanner_Nov2026
{
    meta:
        description = "This rule detects the Rootevidence scanner. It triggers on PE, ELF, or Mach-O files containing either the unique User-Agent or the specific URL-encoded path. For other file types, such as scripts, it requires both strings to be present."
        author = "ioc-yara-daily (agentic)"
        reference = "https://isc.sans.edu/diary/rss/33492"
        date = "2026-11-06"
        malware_family = "Rootevidence Scanner"
        threat_actor = "Rootevidence"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "/%77ebui_wsma_https" ascii // source: figure_or_disassembly
        $x2 = "RootEvidence/1.0" ascii // source: figure_or_disassembly

    condition:
        filesize < 20MB and
        (
            (
                // Detects in common binary formats
                (
                    uint16(0) == 0x5a4d or // PE
                    uint32(0) == 0x464c457f or // ELF
                    uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or // Mach-O
                    uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe    // Mach-O Fat/Universal
                )
                and 1 of ($x*)
            )
            or
            (
                // Stricter detection for scripts or other file types
                2 of ($x*)
            )
        )
}
