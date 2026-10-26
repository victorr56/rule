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
rule MAL_CikaBika_Bot_Oct26
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/darktrace-releases-2024-half-year-threat-insights-2"
        date = "2026-10-26"
        description = "Detects CikaBika Bot RAT based on hardcoded C2 commands and other strings. The condition requires 4 supporting strings to trigger."
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        malware_family = "CikaBika Bot"
        unverified_strings = "s4, s5, s6, s7"

    strings:
        $s1 = "!sysinfo" ascii wide // source: figure_or_disassembly
        $s2 = "!download" ascii wide // source: figure_or_disassembly
        $s3 = "!shell" ascii wide // source: figure_or_disassembly
        $s4 = "tasklist_startup.txt" ascii wide // source: prose
        $s5 = "network_info.txt" ascii wide // source: prose
        $s6 = "!src" ascii wide // source: prose
        $s7 = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" ascii wide // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        4 of ($s*)
}
