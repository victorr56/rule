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
rule MAL_NetSupportRAT_Campaign_Oct2026
{
    meta:
        description = "Detects a specific configuration of NetSupport RAT used in a targeted campaign, identified by a unique build path."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/defcon-phishing-google-doc-malware"
        date = "2026-10-17"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
    strings:
        $x1 = "C:\\Users\\Administrator\\Desktop\\2RMS\\client32u.ini" ascii wide // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        $x1
}
