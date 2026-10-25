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
rule MAL_HERMETICWIPER_Wiper_Oct2026 {
  meta:
    author = "ioc-yara-daily (agentic)"
    date = "2026-10-25"
    description = "Detects HERMETICWIPER malware. The rule can fire on unique strings, like a device name or NTFS attribute name, which are considered strong indicators. Alternatively, it matches on a combination of three other strings, such as the signing certificate subject 'Hermetica Digital', a PDB path, and other artifacts."
    reference = "https://www.elastic.co/security-labs/threat-command/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper"
    hash1 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
    hash2 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
    hash3 = "3c557727953a8f6b4788984464fb77741b821991acbf5e746aebdd02615b1767"
    hash4 = "2c10b2ec0b995b88c27d141d6f7b14d6b8177c52818687e4ff8e6ecf53adf5bf"
    status = "untested"
    test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
    score = 60
    tlp = "WHITE"
    unverified_strings = "x1, x2, s3, s4"

  strings:
    $x1 = "\\Device\\EPMNTDRV" ascii wide  // source: prose
    $x2 = "::$INDEX_ALLOCATION" ascii wide  // source: prose

    $s1 = "Hermetica Digital" ascii wide  // source: strings_listing
    $s2 = "tdrv.pdb" ascii  // source: strings_listing
    $s3 = "ShowCompColor" ascii wide  // source: prose
    $s4 = "ShowInfoTip" ascii wide  // source: prose
    $s5 = "%s%.2s" ascii  // source: strings_listing
    $s6 = "ccessdri" ascii  // source: strings_listing

  condition:
    uint16(0) == 0x5a4d and filesize < 5MB and
    (
      1 of ($x*) or
      3 of ($s*)
    )
}
