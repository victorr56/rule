/* Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $s, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
rule MAL_Mini_Shai_Hulud_Oct2026
{
    meta:
        description = "Detects malicious scripts from the Mini Shai-Hulud campaign targeting the NPM ecosystem. The condition requires at least two of the unique strings to match."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, x2, x3"

    strings:
        $s1 = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii  // source: explicit_literal
        $s2 = "Shai-Hulud: Here We Go Again" ascii  // source: explicit_literal
        $s3 = "tmp.dpkg_14527.lock" ascii  // source: explicit_literal

    condition:
        filesize < 2MB and
        2 of ($s*)
}
