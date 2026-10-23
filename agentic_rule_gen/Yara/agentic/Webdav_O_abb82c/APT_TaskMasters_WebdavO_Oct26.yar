import "pe"

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
rule APT_TaskMasters_WebdavO_Oct2023
{
    meta:
        description = "Detects Webdav-O RAT used by the TaskMasters APT group. The rule can be triggered by a unique RC4 key, a combination of the 'ServiceMain' export and supporting strings, or a larger combination of supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/task/"
        date = "2023-10-26"
        hash1 = "7874c9ab2828bc3bf920e8cdee027e745ff059237c61b7276bbba5311147ebb6"
        hash2 = "849e6ed87188de6dc9f2ef37e7c446806057677c6e05a367abbd649784abdf77"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1_rc4_key, x2_rc4_key, s1_dll_name, s2_format_u, s3_format_s, s4_test_str, s5_url_path, s6_test_file, s7_c2_domain"

    strings:
        // Strong anchors: 16-byte RC4 keys
        $x1_rc4_key = { 8A 4F 01 47 34 C9 75 F8 2B C8 C1 E9 D2 F3 A5 8B }  // source: explicit_literal
        $x2_rc4_key = { C3 02 03 04 05 DD EE 08 09 10 11 12 1F D2 15 16 }  // source: explicit_literal

        // Supporting strings
        $s1_dll_name = "y_dll.dll" ascii wide  // source: explicit_literal
        $s2_format_u = "##u## %s %s" ascii wide  // source: explicit_literal
        $s3_format_s = "##s## %d" ascii wide  // source: explicit_literal
        $s4_test_str = "Just A Test!" ascii wide  // source: explicit_literal
        $s5_url_path = "/?userinfo" ascii wide  // source: explicit_literal
        $s6_test_file = "/test2.txt" ascii wide  // source: explicit_literal
        $s7_c2_domain = "webdav.yandex.ru" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        (
            1 of ($x*) or
            (pe.exports("ServiceMain") and 3 of ($s*)) or
            4 of ($s*)
        )
}
