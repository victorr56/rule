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
rule MAL_NANOREMOTE_WMLOADER_Oct2026
{
    meta:
        description = "Detects the WMLOADER component of NANOREMOTE based on its unique payload decryption key."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/nanoremote"
        date = "2026-10-29"
        hash1 = "fff31726d253458f2c29233d37ee4caf43c5252f58df76c0dced71c4014d6902"
        hash2 = "999648bd814ea5b1e97918366c6bd0f82b88f5675da1d4133257b9e6f4121475"
        hash3 = "35593a51ecc14e68181b2de8f82dde8c18f27f16fcebedbbdac78371ff4f8d41"
        hash4 = "b26927ca4342a19e9314cf05ee9d9a4bddf7b848def2db941dd281d692eaa73c"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1"

    strings:
        $x1 = "3A5AD78097D944AC" ascii  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        $x1
}
