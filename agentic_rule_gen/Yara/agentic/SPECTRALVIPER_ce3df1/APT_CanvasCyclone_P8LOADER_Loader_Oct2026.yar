rule APT_CanvasCyclone_P8LOADER_Loader_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-25"
        description = "Detects P8LOADER, a PE loader used by Canvas Cyclone (APT32) to deploy SPECTRALVIPER. The rule looks for unique debug strings. A match is triggered by two or more of these strings."
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-charms-spectralviper"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
    /* Self-check
    [x] Every string has a provenance comment
    [x] No source-code identifiers / compiled-away names
    [x] Hash-gated values use the hash constant, not the plaintext
    [x] No substring redundancy within any "N of" group
    [x] No generic string can trigger the rule alone
    [x] Description matches the condition
    [x] Open-source-tool features are not attributed to the actor
    [x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $s, not downgraded
    [x] No generic padding is required by the condition
    [x] No empty meta fields
    */
    strings:
        $s1 = "\\t[+] Create pipe direct std success\\n" ascii // source: report strings_listing
        $s2 = "\\tPEAddress: %p\\n" ascii // source: report strings_listing
        $s3 = "DynamicLoad(%s, %s) %d\\n" ascii // source: report strings_listing
        $s4 = "LoadLibraryA(%s) FAILED in %s function, line %d" ascii // source: report strings_listing

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        2 of them
}
