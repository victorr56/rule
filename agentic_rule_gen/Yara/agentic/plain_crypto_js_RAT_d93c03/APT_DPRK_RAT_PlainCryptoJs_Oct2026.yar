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
rule APT_DPRK_RAT_PlainCryptoJs_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-18"
        description = "Detects cross-platform plain-crypto-js RAT used in supply chain attacks and attributed to DPRK. The rule targets binaries (PE, Mach-O, ELF). It triggers on one strong unique string, or on four of several supporting strings."
        reference = "https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package"
        malware_family = "plain-crypto-js RAT"
        threat_actor = "DPRK"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        hash1 = "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd"
        hash2 = "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101"
        hash3 = "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a"
        hash4 = "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf"
        unverified_strings = "x1, s1, s2, s3, s4, s5, s6, s7"

    strings:
        // $x* is a strong unique indicator that can fire the rule alone
        $x1 = "Extension.SubRoutine.Run2()" ascii  // source: explicit_literal

        // $s* are supporting indicators
        $s1 = "OrDeR_7077" ascii wide  // source: explicit_literal
        $s2 = "macWebT" ascii  // source: explicit_literal
        $s3 = "FirstInfo" ascii wide  // source: explicit_literal
        $s4 = "BaseInfo" ascii wide  // source: explicit_literal
        $s5 = "peinject" ascii wide  // source: explicit_literal
        $s6 = "Wow" ascii wide  // source: explicit_literal
        $s7 = "/6202033" ascii  // source: prose

    condition:
        (
            uint16(0) == 0x5a4d or // PE
            uint32(0) == 0x464c457f or // ELF
            uint32(0) == 0xfeedface or // Mach-O
            uint32(0) == 0xfeedfacf or // Mach-O
            uint32(0) == 0xcafebabe or // Mach-O
            uint32(0) == 0xcffaedfe    // Mach-O
        ) and
        filesize < 20MB and
        (
            $x1 or
            4 of ($s*)
        )
}
