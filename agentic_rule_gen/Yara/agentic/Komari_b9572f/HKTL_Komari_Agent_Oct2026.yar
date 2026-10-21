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
rule HKTL_Komari_Agent_Oct2026 {
  meta:
    description = "Detects Komari agent, an open-source monitoring tool abused by threat actors for C2 communications. Detection is based on multiple characteristic API paths and command-line flags."
    author = "ioc-yara-daily (agentic)"
    reference = "https://www.huntress.com/blog/komari-c2-agent-abuse"
    date = "2026-10-18"
    hash1 = "039e659ade3aa8ee7758c11fdb8fbfffd2491920046d638413cea2042f6d584c"
    tlp = "WHITE"
    status = "untested"
    test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
    score = 60
    unverified_strings = "s1, s2, s3, s4, s5, s6"
  strings:
    $s1 = "/api/clients/uploadBasicInfo" ascii  // source: prose
    $s2 = "/api/clients/task/result" ascii  // source: prose
    $s3 = "/api/clients/terminal" ascii  // source: prose
    $s4 = "/api/clients/report" ascii  // source: prose
    $s5 = "--ignore-unsafe-cert" ascii  // source: prose
    $s6 = "--disable-web-ssh" ascii  // source: prose
  condition:
    (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and filesize < 20MB and 3 of ($s*)
}
