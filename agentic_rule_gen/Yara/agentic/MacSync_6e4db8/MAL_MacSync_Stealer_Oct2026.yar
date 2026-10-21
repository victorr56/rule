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
rule MAL_MacSync_Stealer_Oct2023 {
  meta:
    description = "Detects the MacSync AppleScript stealer payload, often found within a Mach-O binary. A match requires a unique Russian developer comment, or a combination of three other indicative strings, including the malware's self-identifying name. All strings are from an `explicit_literal` source and are unverified."
    author = "ioc-yara-daily (agentic)"
    reference = "https://www.huntress.com/blog/macsync-stealer-rat-reverse-engineering"
    date = "2023-10-17"
    hash1 = "3db8befc08dc02ab7a76b5193abd81653775e8f3ceac5864c7c2188b2dbd3c54"
    tlp = "WHITE"
    status = "untested"
    test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
    score = 60
    unverified_strings = "x1, s1, s2, s3"
  strings:
    // $x1 is a strong anchor (>16 bytes, very unique) and can fire alone
    $x1 = "Убрана хрупкая SafeSQLiteCopy (часто падала когда Firefox запущен)" ascii  // source: explicit_literal

    $s1 = "MacSync Stealer" ascii  // source: explicit_literal
    $s2 = "1.1.2_release" ascii  // source: explicit_literal
    $s3 = "Full Disk Access required!" ascii  // source: explicit_literal
  condition:
    (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe) and
    filesize < 5MB and
    ($x1 or 3 of ($s*))
}
