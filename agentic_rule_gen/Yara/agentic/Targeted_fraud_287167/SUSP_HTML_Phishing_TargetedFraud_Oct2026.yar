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
rule SUSP_HTML_Phishing_TargetedFraud_Oct2026
{
    meta:
        description = "Detects phishing pages associated with the Targeted Fraud campaign. The rule requires a combination of at least three specific strings, such as unique phrases, domains, or URL paths, to trigger."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/target/"
        date = "2026-10-23"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1, s2, s3, s4, s5, s6, s7"

    strings:
        // All strings are from prose and may not be verbatim literals.
        $s1 = "Dear customer! Congratulations! You are one of the 100 users that we selected to receive the chance to win" ascii  // source: prose
        $s2 = "You have 4 minutes and 27 seconds to answer the following questions" ascii  // source: prose
        $s3 = "finalopnon.click" ascii  // source: prose
        $s4 = "go.lltrsknoob.click" ascii  // source: prose
        $s5 = "/s10xs/" ascii  // source: prose
        $s6 = "/pr/i12/brand/" ascii  // source: prose
        $s7 = "/it/s20i11/" ascii  // source: prose

    condition:
        filesize < 1MB and
        3 of ($s*)
}
