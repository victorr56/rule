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
rule APT_VAPOR_PANDA_BLOODALCHEMY_Oct2026
{
    meta:
        description = "Detects BLOODALCHEMY backdoor and related ARTEX framework strings attributed to VAPOR PANDA. This rule matches on strong unique indicators such as a PDB path or a specific log string, or on a combination of at least three supporting strings like filenames and command fragments."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/"
        date = "2026-10-30"
        hash1 = "49fe70419fd19b81ca8d730a6ef7c1ec71b681d60b390761070d42686c7d2068"
        hash2 = "3fb5a9fb3e2cb1d6208966bd4e55d10282d19c7250d827efa560463d60a12ee4"
        hash3 = "364251838edfcf5ef1107fa692da3c5bd9a540482449f645992830134bf807ab"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $x2, $s1, $s2, $s3, $s4, $s5, $s6"

    strings:
        // --- Unique ($x) - Strong Anchors ---
        $x1 = "D:\\ProjectX\\Merman_New\\" ascii wide  // source: prose, PDB path
        $x2 = { E5 9C A8 E5 9F 9F E9 87 8C E5 AF BB E6 89 BE E6 B2 A1 E6 9C 89 E8 A3 85 E7 8C 8E E9 B9 B0 E7 9A 84 77 69 6E 64 6F 77 73 E6 9C BA E5 99 A8 EF BC 8C E4 BB 8E 74 61 73 6B 6C 69 73 74 E5 92 8C E6 96 87 E4 BB B6 E5 A4 B9 E7 9B AE E5 BD 95 E5 88 A4 E6 96 AD }  // "在域里寻找没有装猎鹰的windows机器..." in UTF-8, source: prose, unique string

        // --- Supporting ($s) ---
        $s1 = "graphics-hook-filter64.dll" ascii wide  // source: prose, file name
        $s2 = "graphics-hook_config.bin" ascii wide  // source: prose, file name
        $s3 = "art18- administration-command" ascii wide  // source: prose, unique string
        $s4 = { E3 80 90 E4 BA BA E7 B1 BB E6 8C 87 E4 BB A4 E3 80 91 }  // "【人类指令】" in UTF-8, source: prose, unique string
        $s5 = { E7 8C 8E E9 B9 B0 }  // "猎鹰" (slang for Falcon EDR) in UTF-8, source: prose, unique string, yara_hint: short (<8 bytes) -> $s/$c only
        $s6 = "artex" ascii wide  // source: prose, unique string, yara_hint: short (<8 bytes) -> $s/$c only

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
