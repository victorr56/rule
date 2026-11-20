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
rule MAL_Win_Retadup_Nov2026
{
    meta:
        description = "Detects the Retadup worm based on network indicators. The rule can be triggered by a highly specific C2 URI path or a combination of its C2 domain, user-agent, and a dropped DLL name."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/retadup-delivers-coffeeloader/121908/"
        date = "2026-11-20"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 55
        unverified_strings = "s3"

    strings:
        $x1 = "/FD0C7EE872277F33E3335530299B836A/1/4/1/0/empty" ascii wide  // source: figure_or_disassembly

        $s1 = "noobminer.newblackage.com" ascii wide  // source: figure_or_disassembly
        $s2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) WinHttp/1.6.4.0 (WinHTTP/5.1) like Gecko" ascii wide  // source: figure_or_disassembly
        $s3 = "7z.dll" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        (
            $x1 or
            3 of ($s*)
        )
}
