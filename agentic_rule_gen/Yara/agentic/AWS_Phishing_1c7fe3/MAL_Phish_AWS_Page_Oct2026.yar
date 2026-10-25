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
[x] No generic padding is required
[x] No empty meta fields
*/
rule MAL_Phish_AWS_Page_Oct2026
{
    meta:
        description = "Detects web content or documents related to an AWS phishing campaign observed in October 2026. The rule requires at least three indicators to trigger."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.wiz.io/blog/emerging-phishing-campaign-targeting-aws-accounts"
        date = "2026-10-25"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "s1, s2, s3, s4, s5, s6, s7, s8, s9"

    strings:
        // All strings are sourced from the report's prose and may be found in phishing emails, attachments, or the HTML of the landing page.
        // Domains/URLs are not considered strong anchors and require combinations.
        $s1 = "giraffe-viola-p262.squarespace.com/" ascii wide  // source: prose
        $s2 = "cli.re/j9PQ88" ascii wide  // source: prose
        $s3 = "console.aws.consoleportal.tech/IgXlrDYW" ascii wide  // source: prose
        $s4 = "signin.aws.consoleportal.tech/signin" ascii wide  // source: prose
        $s5 = "d35uxhjf90umnp.cloudfront.net/index.js" ascii wide  // source: prose
        $s6 = "webportal.tech" ascii wide  // source: prose
        $s7 = "docshare.tech" ascii wide  // source: prose
        $s8 = "signin.aws.amaonz.com" ascii wide  // source: prose
        $s9 = "signin.aws.hashcrp.in" ascii wide  // source: prose

    condition:
        filesize < 1MB and
        3 of ($s*)
}
