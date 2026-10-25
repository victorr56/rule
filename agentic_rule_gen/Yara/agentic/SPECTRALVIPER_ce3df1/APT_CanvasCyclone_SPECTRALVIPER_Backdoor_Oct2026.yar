rule APT_CanvasCyclone_SPECTRALVIPER_Backdoor_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-25"
        description = "Detects SPECTRALVIPER backdoor, a component used by Canvas Cyclone (APT32). The rule looks for unique code patterns and a hardcoded AES key. A match is triggered by any one of these unique indicators."
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-charms-spectralviper"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        hash1 = "56d2d05988b6c23232b013b38c49b7a9143c6649d81321e542d19ae46f4a4204"
        hash2 = "d1c32176b46ce171dbce46493eb3c5312db134b0a3cfa266071555c704e6cff8"
        hash3 = "7e35ba39c2c77775b0394712f89679308d1a4577b6e5d0387835ac6c06e556cb"
        hash4 = "4e3a88cf00e0b4718e7317a37297a185ff35003192e5832f5cf3020c4fc45966"
        hash5 = "7b5e56443812eed76a94077763c46949d1e49cd7de79cde029f1984e0d970644"
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
    strings:
        // Hex patterns are strong anchors
        $x1 = { 00 48 89 C6 0F 29 30 0F 29 70 10 0F 29 70 20 0F 29 70 30 0F 29 70 40 0F 29 70 50 48 C7 40 60 00 00 00 00 48 89 C1 E8 } // source: report strings_listing
        $x2 = { 41 0F 45 C0 45 84 C9 41 0F 45 C0 EB BA 48 89 4C 24 08 89 D0 EB B1 48 8B 44 24 08 48 83 C4 10 C3 56 57 53 48 83 EC 30 8B 05 } // source: report strings_listing
        $x3 = { 48 83 EC 28 4C 8B 41 18 4C 8B C9 48 B8 AB AA AA AA AA AA AA AA 48 F7 61 10 48 8B 49 08 48 C1 EA } // source: report strings_listing

        // Unique string values
        $x4 = "H9mktfe2k0ukk64nZjw1ow==" ascii // source: report figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        1 of ($x*)
}
