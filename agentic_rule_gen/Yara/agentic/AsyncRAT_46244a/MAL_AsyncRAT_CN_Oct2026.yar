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
rule MAL_AsyncRAT_CN_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-17"
        description = "Detects AsyncRAT payloads containing the default self-signed certificate subject. The condition requires only this unique string to fire."
        reference = "https://www.darktrace.com/blog/catching-a-rat-how-darktrace-neutralized-asyncrat"
        malware_family = "AsyncRAT"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "CN=AsyncRAT Server" ascii wide // source: report figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        $x1
}
