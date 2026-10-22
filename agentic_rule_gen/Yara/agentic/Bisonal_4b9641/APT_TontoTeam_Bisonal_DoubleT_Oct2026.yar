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
rule APT_TontoTeam_Bisonal_DoubleT_Oct2026 {
  meta:
    author = "ioc-yara-daily (agentic)"
    date = "2026-10-22"
    description = "Detects the Bisonal.DoubleT backdoor used by Tonto Team. Detection is based on the combination of a Base32 alphabet string and several unique URI paths, error messages, and filenames mentioned in reporting."
    reference = "https://www.group-ib.com/blog/tonto-team/"
    hash1 = "58c1cab2a56ae9713b057626953f8967c3bacbf2cda68ce104bbb4ece4e35650"
    hash2 = "8597e6b9f5f61c68a9ef219513dd43dd36e269b738f849b1dda44b576c865d39"
    hash3 = "dcb854e32d3ca08852371673ed7cd9139af761b8b127113746a527050b5e2b1d"
    malware_family = "Bisonal"
    threat_actor = "Tonto Team"
    tlp = "WHITE"
    status = "untested"
    test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
    score = 50
    unverified_strings = "s2, s3, s4, s5, s6, s7, s8"

  strings:
    $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" ascii  // source: strings_listing
    $s2 = "[!] get pRegSetValueEx error\\n" ascii wide  // source: prose
    $s3 = "/ru/order/index.php" ascii  // source: prose
    $s4 = "/ru/news/index.php" ascii  // source: prose
    $s5 = "/xhome.native.page/datareader.php" ascii  // source: prose
    $s6 = "/siteFiles/index.php" ascii  // source: prose
    $s7 = "offices-update.com" ascii  // source: prose
    $s8 = "dcnx18pwh.wmf" ascii  // source: prose

  condition:
    uint16(0) == 0x5a4d and filesize < 5MB and
    (
      $s1 and 3 of ($s2,$s3,$s4,$s5,$s6,$s7,$s8)
    )
}
