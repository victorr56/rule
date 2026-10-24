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
rule MAL_PerSwaysion_Phishkit_Oct2026
{
    meta:
        description = "This rule detects components of the PerSwaysion phishing kit based on a combination of strings. A match is triggered by at least three indicators, such as specific filenames, font names, or user/version strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/perswaysion/"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s5, s6, s7"

    strings:
        // Supporting strings
        $s1 = "a5e2a323bdb682660c9cd8b06e950f31nbr1581699430.js" ascii  // source: explicit_literal
        $s2 = "e88a1b1823a36c944d71746cdefb5fdc.js" ascii  // source: explicit_literal
        $s3 = "Microsoft YaHei" ascii wide  // source: figure_or_disassembly
        $s4 = "Microsoft JhengHei" ascii wide  // source: figure_or_disassembly
        $s5 = "6.7.6640.0" ascii  // source: prose
        $s6 = "adriangalbincea" ascii  // source: prose
        $s7 = "fash20161" ascii  // source: prose

    condition:
        filesize < 2MB and
        3 of ($s*)
}
