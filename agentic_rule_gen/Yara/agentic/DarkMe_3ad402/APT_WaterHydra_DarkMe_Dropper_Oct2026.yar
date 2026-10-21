/*
   Self-check
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
rule APT_WaterHydra_DarkMe_Dropper_Oct2026
{
    meta:
        description = "Detects the initial DarkMe dropper (image.pif) by its forged version information. The rule requires the presence of both the fake product name 'Aegis Sentinel Security Suite' and the original filename 'aegis_sentinel.dll'."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/darkme-rat-abandons-exploits"
        date = "2026-10-16"
        hash1 = "394c93dfbb7581c66a23c52b20cd90b31415c0825a2eab7107e60ee3fe693c04"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 50
    strings:
        $s1 = "Aegis Sentinel Security Suite" ascii wide // source: figure_or_disassembly
        $s2 = "aegis_sentinel.dll" ascii wide // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        2 of ($s*)
}
