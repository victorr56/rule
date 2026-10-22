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
rule MAL_NETWIRE_Gen_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects NETWIRE RAT based on unique code patterns and strings. The rule can be triggered by a single unique code pattern or string, or by a combination of three supporting strings."
        reference = "https://www.elastic.co/security-labs/blog/netwire-dynamic-configuration-extraction"
        score = 60
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        tlp = "WHITE"

    strings:
        // Strong anchors: unique hex patterns and long/distinctive strings
        $x1 = { 0F B6 74 0C 10 89 CF 29 C7 F7 C6 DF 00 00 00 74 09 41 89 F3 88 5C }  // source: artifact-1 hex_pattern
        $x2 = { C9 0F 44 C8 D0 EB 8A 44 24 12 0F B7 C9 75 D1 32 C0 B3 01 8B CE 88 44 }  // source: artifact-2 hex_pattern
        $x3 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" ascii wide  // source: artifact-3 unique_string
        $x4 = "http://%s%%ComSpec" ascii wide  // source: artifact-5 unique_string
        $x5 = "PTLLjPq %6:%S -qq9/G.y" ascii wide  // source: artifact-8 unique_string

        // Supporting strings
        $s1 = "\\Login Data" ascii wide  // source: artifact-4 unique_string
        $s2 = "R-W65: %6:%S" ascii wide  // source: artifact-7 unique_string
        $s3 = "GET %s HTTP/1.1" ascii wide  // source: artifact-6 unique_string

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
