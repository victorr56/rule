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
rule WEBSHELL_UnitedIslamicCyberForce_Defacement_Oct2026
{
    meta:
        description = "Detects website defacement pages associated with the United Islamic Cyber Force (UICF) hacktivist group. This rule requires the group's name and a campaign hashtag, or at least three distinct campaign hashtags/slogans."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/uicf/"
        date = "2026-10-25"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "s1, s2, s3, s4, s5"

    strings:
        $s1 = "United Islamic Cyber Force, Salami Ala Aqsha" ascii  // source: prose
        $s2 = "#OpFrance" ascii  // source: prose
        $s3 = "#OpIsrael" ascii  // source: prose
        $s4 = "#Free_Palestine" ascii  // source: prose
        $s5 = "#FreeAlaqsa" ascii  // source: prose

    condition:
        // Defacement pages are typically small HTML or text files.
        filesize < 1MB and
        (
            $s1 and 1 of ($s2, $s3, $s4, $s5) or
            3 of ($s*)
        )
}
