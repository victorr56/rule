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
rule MAL_Soco404_Payload_Oct2026 {
  meta:
    description = "Detects Soco404 cryptomining payload for Linux and Windows by its unique XMRig wallet address."
    author = "ioc-yara-daily (agentic)"
    reference = "https://www.wiz.io/blog/soco404-multiplatform-cryptomining-campaign-uses-fake-error-pages-to-hide-payload"
    date = "2026-10-23"
    hash1 = "e7fe0a5c6c198be8941d5a1be7c0669688c45751e9bf0d16a0ae6ae1d0e7a957"
    hash2 = "498ecdfce65d739154b39703c63c8f4334066655e1cc8024c2716e280598cacc"
    hash3 = "0086fe6259af25f3b5a12d81080bed61938cc70ebdf480501acc1c10ac39c74a"
    tlp = "WHITE"
    status = "untested"
    test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
    score = 60
    unverified_strings = "x1"
  strings:
    $x1 = "8BmVXbfsnRsiyPfUxsfnyyA9LqXvUsF2DYBX3wUmCEtejnBMyTiXe3XDCvq4REjmviEc5J1gomsnv7e4wYy1c5Pz3VadeyZ" ascii // source: explicit_literal
  condition:
    (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
    filesize < 20MB and
    $x1
}
