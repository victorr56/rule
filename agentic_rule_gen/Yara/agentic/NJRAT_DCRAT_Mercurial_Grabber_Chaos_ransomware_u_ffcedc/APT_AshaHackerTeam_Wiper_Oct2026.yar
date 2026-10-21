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
rule APT_AshaHackerTeam_Wiper_Oct2026 {
    meta:
        description = "Detects a wiper, based on Chaos ransomware, used by the 'ASHA HACKER TEAM' as part of a fake GTA6 campaign. The rule triggers on unique strings from the ransom note and the desktop wallpaper text."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/fake-gta6-download-malware-analysis"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
    strings:
        $x1 = "hello, your files has been encrypted by ach from achvzlom" ascii wide // source: figure_or_disassembly
        $x2 = { D0 92 D0 AB 20 D0 92 D0 97 D0 9B D0 9E D0 9C D0 90 D0 9D D0 AB 20 D0 A5 D0 90 D0 9A D0 95 D0 A0 D0 A1 D0 9A D0 9E D0 99 20 D0 9A D0 9E D0 9C D0 90 D0 9D D0 94 D0 9E D0 99 20 D0 90 D0 A8 D0 90 21 } // source: figure_or_disassembly
    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        1 of ($x*)
}
