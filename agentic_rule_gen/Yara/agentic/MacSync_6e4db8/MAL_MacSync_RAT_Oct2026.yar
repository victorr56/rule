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
rule MAL_MacSync_RAT_Oct2026 {
  meta:
    description = "Detects the MacSync RAT component, which communicates over a raw-IP TLS channel. The rule targets a unique hardcoded encryption token and other build artifacts. A match can be triggered by the unique token alone, or by a combination of two other supporting strings."
    author = "ioc-yara-daily (agentic)"
    reference = "https://www.huntress.com/blog/macsync-stealer-rat-reverse-engineering"
    date = "2026-10-17"
    hash1 = "3ae26ed89d3a1a140edc89ca78513aba2895789ed0d0f64cad6605b6f2347c7e"
    tlp = "WHITE"
    status = "untested"
    test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
    score = 60
    unverified_strings = "\"Mon May 18 08:54:01 2026 UTC\", \"/tmp/openssl-arm64/\""
  strings:
    // $x1 is a strong anchor (>16 bytes, high entropy) and can fire alone
    $x1 = "nLbd5Df6CyCZNFDBpxGtBOlfshEr4jdTJ9ZYwxhVahr1tV2EdeZNG6VdNK2O2" ascii  // source: figure_or_disassembly
    $s1 = "Mon May 18 08:54:01 2026 UTC" ascii  // source: explicit_literal
    $s2 = "/tmp/openssl-arm64/" ascii  // source: explicit_literal
  condition:
    (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcafebabe) and filesize < 20MB and ($x1 or 2 of ($s*))
}
