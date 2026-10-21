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
rule APT_SilverFox_ValleyRAT_Loader_Oct2026
{
    meta:
        description = "Detects the loader component of ValleyRAT, often disguised as libcef.dll. Attributed to the Silver Fox group. A match requires at least one unique string, or a combination of three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/valleyrat-backdoor-adware/121175/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "$x2, $s3"

    strings:
        // Unique strings: long function names related to CEF masquerade (>=16 bytes)
        $x1 = "cef_browser_view_get_for_browser" ascii  // source: report Fig.14 decompilation
        $x2 = "cef_clear_cross_origin_whitelist" ascii  // source: report prose
        $x3 = "cef_browser_view_create" ascii  // source: report Fig.14 decompilation

        // Supporting strings: resource names, exports, and DLLs
        $s1 = "PeLoader" ascii  // source: report Fig.12 decompilation
        $s2 = "IsNTAdmin" ascii  // source: report Fig.11 exports
        $s3 = "advpack.dll" ascii wide  // source: report prose
        $s4 = "RunDLL" ascii  // source: report Fig.11 exports

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
