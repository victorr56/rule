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
rule MAL_CyberStrikeAI_Agent_Nov2026
{
    meta:
        description = "Detects the CyberStrikeAI agent for Windows and Linux. The rule requires at least three supporting indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/tr/cyberstrikeai-attacks/121715/"
        date = "2026-11-02"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s4, s5, s6"

    strings:
        // Supporting strings
        $s1 = "CyberStrikeAI" ascii  // source: figure_or_disassembly
        $s2 = "svchosts.exe" ascii wide  // source: figure_or_disassembly
        $s3 = "p1.ps1" ascii wide  // source: figure_or_disassembly
        $s4 = "vcs.modified=true" ascii  // source: prose
        $s5 = "SystemUpdate" ascii wide  // source: prose
        $s6 = "dnslog.cn" ascii  // source: prose

    condition:
        (
            uint16(0) == 0x5a4d or // PE
            uint32(0) == 0x464c457f // ELF
        ) and
        filesize < 20MB and
        3 of ($s*)
}
