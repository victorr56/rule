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
rule WEBSHELL_NOX_Stealer_Panel_Oct2026
{
    meta:
        description = "Detects web panel artifacts associated with NOX/BOMBAY Stealer C2 infrastructure. This rule is based on prose-described strings and requires all indicators to match."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.virustotal.com/2026/10/internet-scanning-in-vt.html"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "s1, s2, s3"

    strings:
        $s1 = "panel_jwt" ascii  // source: prose, Session logic used by the NOX/BOMBAY panel
        $s2 = "#a855f7" ascii  // source: prose, Tailwind CSS theme colour
        $s3 = "#030308" ascii  // source: prose, Tailwind CSS theme background colour

    condition:
        filesize < 1MB and
        3 of ($s*)
}
