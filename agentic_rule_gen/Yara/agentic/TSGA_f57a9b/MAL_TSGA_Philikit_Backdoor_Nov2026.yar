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
rule MAL_TSGA_Philikit_Backdoor_Nov2026
{
    meta:
        description = "Detects the TSGA backdoor (a variant of PhiliKit) used by UNC5221. The rule requires three specific strings to be present."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        date = "2026-11-20"
        hash1 = "4171b521fa6441382aa2fa014a08e18ff9a6e0ab6096c9144072bf46b37a2ec8"
        hash2 = "d7549671c7189979f0624ec52dad9ea6a707d23146e3585ab8f8c4720eca0c63"
        hash3 = "ee16e1695711b9d60c62925fcfb2fe1a29c18ae26565bc05410a14e16d2a39d7"
        hash4 = "fb1a6235eb6bce8c9ec8cd8bb85f17c9c2bde8ecb45b7a243a30ceadf26654da"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2, s3"
    strings:
        $s1 = "slot_CPconfigdaemon" ascii  // source: prose
        $s2 = "philistine" ascii  // source: prose
        $s3 = "libdssafe.so" ascii  // source: prose
    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        3 of them
}
