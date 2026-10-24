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
rule APT_FakeSecurity_Raccoon_Variant_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        description = "Detects Raccoon Stealer variants used by the FakeSecurity actor. Detection is based on a combination of a hardcoded Telegram channel name and C2-related strings."
        reference = "https://www.group-ib.com/blog/fakesecurity-raccoon/"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 40
        unverified_strings = "s2, s3, s4, s5"
    strings:
        $s1 = "blintick" ascii wide  // source: figure_or_disassembly
        $s2 = "cloud-server-updater22.co.za" ascii wide  // source: prose
        $s3 = "microsoft-cloud13.co.za" ascii wide  // source: prose
        $s4 = "updateforadobenew.co.za" ascii wide  // source: prose
        $s5 = "/doc/officebuilder" ascii wide  // source: prose
    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and 3 of ($s*)
}
