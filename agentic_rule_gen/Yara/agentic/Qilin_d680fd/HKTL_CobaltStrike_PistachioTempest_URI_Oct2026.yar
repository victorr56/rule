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
rule HKTL_CobaltStrike_PistachioTempest_URI_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/a-busy-agenda-darktraces-detection-of-qilin-ransomware-as-a-service-operator"
        date = "2026-10-17"
        description = "Detects Cobalt Strike activity potentially associated with Pistachio Tempest, based on a combination of specific C2 URI paths observed in their operations. The rule requires three of the specified strings to match."
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "s1, s2, s3"

    strings:
        $s1 = "/asdffHTTPS" ascii  // source: explicit_literal
        $s2 = "/asdfgdf" ascii  // source: explicit_literal
        $s3 = "/asdfgHTTP" ascii  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        3 of ($s*)
}
