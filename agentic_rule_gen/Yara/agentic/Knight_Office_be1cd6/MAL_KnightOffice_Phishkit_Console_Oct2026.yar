/* Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $s, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
rule MAL_KnightOffice_Phishkit_Console_Oct2026
{
    meta:
        description = "Detects the operator console of the Knight Office phishing kit based on unique strings from its web interface."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $s1 = "Sign in to your KNIGHT OFFICE panel" ascii  // source: figure_or_disassembly
        $s2 = "INTELLIGENCE \xE2\x80\xA2 CAPTURE \xE2\x80\xA2 CONTROL" ascii  // source: figure_or_disassembly
        $s3 = "Capture & Management from Single place" ascii  // source: figure_or_disassembly
        $s4 = "Webmail access & auto-refresh" ascii  // source: figure_or_disassembly

    condition:
        // not a PE file, likely script/html
        uint16(0) != 0x5a4d and filesize < 1MB and
        2 of ($s*)
}
