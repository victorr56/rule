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
rule MAL_FakeGTA6_Installer_Oct2026 {
    meta:
        description = "Detects a fake GTA6 installer that drops multiple malware families. The rule can be triggered by a unique email address, or a combination of a Russian installer title and a fake error message."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/fake-gta6-download-malware-analysis"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
    strings:
        $x1 = "kanalwsegokrytow0555@gmail.com" ascii wide // source: figure_or_disassembly
        $a1 = { D1 83 D1 81 D1 82 D0 B0 D0 BD D0 BE D0 B2 D1 89 D0 B8 D0 BA 20 D0 B3 D1 82 D0 B0 20 36 } // "установщик гта 6" // source: figure_or_disassembly
        $s1 = "License not found" ascii wide // source: figure_or_disassembly
    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        ($x1 or ($a1 and $s1))
}
