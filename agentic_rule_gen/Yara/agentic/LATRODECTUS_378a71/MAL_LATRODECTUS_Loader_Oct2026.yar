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
rule MAL_LATRODECTUS_Loader_Oct2026 {
  meta:
    description = "Detects the LATRODECTUS loader based on a combination of supporting strings. This rule requires the presence of at least three of these strings."
    author = "ioc-yara-daily (agentic)"
    reference = "https://www.elastic.co/security-labs/threat-command/spring-cleaning-with-latrodectus"
    date = "2026-10-18"
    hash1 = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
    tlp = "WHITE"
    status = "untested"
    test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
    score = 60
    unverified_strings = "s1, s2, s3, s4, s5, s6, s7, s8, s9"

  strings:
    $s1 = "Custom_update" ascii wide  // source: explicit_literal
    $s2 = "/files/bp.dat" ascii wide  // source: explicit_literal
    $s3 = "init -zzzz=" ascii wide  // source: prose
    $s4 = "update_data.dat" ascii wide  // source: prose
    $s5 = "Littlehw" ascii wide  // source: explicit_literal
    $s6 = "desklinks" ascii wide  // source: explicit_literal
    $s7 = "proclist" ascii wide  // source: explicit_literal
    $s8 = "runnung" ascii wide  // source: prose
    $s9 = "0x19660D" ascii wide  // source: explicit_literal

  condition:
    uint16(0) == 0x5a4d and filesize < 5MB and
    3 of ($s*)
}
