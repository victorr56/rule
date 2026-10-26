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
rule MAL_SHADOWPAD_Winnti_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-26"
        description = "Detects SHADOWPAD components used by Winnti Group (REF2924). The rule matches on a highly unique obfuscated string or a custom GUID format string."
        reference = "https://www.elastic.co/security-labs/threat-command/update-to-the-REF2924-intrusion-set-and-related-campaigns"
        malware_family = "SHADOWPAD"
        threat_actor = "Winnti Group"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "{%8.8x-%4.4x-%4.4x-%8.8x%8.8x}" ascii  // source: strings_listing
        $x2 = "Yuv~YuvsYuvhYuv]YuvRYuvGYuv1:tv<Yuvb#tv1Yuv-8tv&Yuv" ascii  // source: strings_listing

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        1 of ($x*)
}
