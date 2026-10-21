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
rule MAL_BITSLOTH_Backdoor_Oct2026
{
    meta:
        description = "Detects the BITSLOTH backdoor, which abuses BITS for C2. The rule targets unique strings, including a hardcoded mutex, specific byte patterns, and C2 URI formats. A match is triggered by one strong unique string, or a combination of at least three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/bits-and-bytes-analyzing-bitsloth"
        date = "2026-10-18"
        hash1 = "4a4356faad620bf12ff53bcfac62e12eb67783bd22e66bf00a19a4c404bf45df"
        hash2 = "dfb76bcf5a3e29225559ebbdae8bdd24f69262492eca2f99f7a9525628006d88"
        hash3 = "4fb6dd11e723209d12b2d503a9fcf94d8fed6084aceca390ac0b7e7da1874f50"
        hash4 = "0944b17a4330e1c97600f62717d6bae7e4a4260604043f2390a14c8d76ef1507"
        hash5 = "0f9c0d9b77678d7360e492e00a7fa00af9b78331dc926b0747b07299b4e64afd"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $s1, $s2, $s3, $s7, $s8, $s9, $s10, $s11"

    strings:
        // Strong anchors (can fire alone)
        $x1 = "Global\\d5ffff77ff77adad657658" ascii wide  // source: explicit_literal
        $x2 = { 81 3D ?? ?? ?? ?? F9 03 00 00 B9 AC 0F 00 00 0F 46 C1 }  // source: strings_listing
        $x3 = { 59 85 C0 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 02 EB ?? 56 EB }  // source: strings_listing

        // Supporting strings
        $s1 = "aghzyxklg" ascii wide  // source: explicit_literal
        $s2 = "ciakfjoab" ascii wide  // source: explicit_literal
        $s3 = "rrrr_url" ascii wide  // source: explicit_literal
        $s4 = "/%s/wu.htm" ascii  // source: strings_listing
        $s5 = "/%s/index.htm?RspID=%d" ascii  // source: strings_listing
        $s6 = "/%s/%08x.rpl" ascii  // source: strings_listing
        $s7 = "WU Client Download" ascii wide  // source: explicit_literal
        $s8 = "WU Client Upload R" ascii wide  // source: explicit_literal
        $s9 = "flengine.dll" ascii wide  // source: prose
        $s10 = "/IF/P.bin" ascii  // source: explicit_literal
        $s11 = "http://updater.microsoft.com/index.aspx" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
