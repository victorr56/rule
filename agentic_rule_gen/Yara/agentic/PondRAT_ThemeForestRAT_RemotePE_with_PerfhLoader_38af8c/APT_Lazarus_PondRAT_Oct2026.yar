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
rule APT_Lazarus_PondRAT_Oct2026
{
    meta:
        description = "Detects PondRAT, a simple HTTP(S) RAT used by a Lazarus subgroup across Windows, Linux, and macOS. Detection is based on a unique hardcoded XOR key, a specific User-Agent format, and other C2 communication strings. The rule can be triggered by one of several strong unique strings or a combination of supporting indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.fox-it.com/2025/09/01/three-lazarus-rats-coming-for-your-cheese/"
        date = "2026-10-16"
        hash1 = "6510d460395ca3643133817b40d9df4fa0d9dbe8e60b514fdc2d4e26b567dfbd" // PondRAT Windows
        hash2 = "973f7939ea03fd2c9663dafc21bb968f56ed1b9a56b0284acf73c3ee141c053c" // PondRAT Linux
        hash3 = "f0321c93c93fa162855f8ea4356628eef7f528449204f42fbfa002955a0ba528" // PondRAT macOS
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        // Strong anchors - can fire alone
        $x1 = "774C71664D5D25775478607E74555462773E525E18237947355228337F433A3B" ascii wide  // source: artifact unique_string, XOR key
        $x2 = "%sd.e%sc \\\"%s > %s 2>&1\\\"" ascii wide  // source: artifact unique_string, shell command format
        $x3 = "objc_firstloader" ascii  // source: artifact unique_string, macOS metadata

        // Supporting strings - require combinations
        $s1 = "lkjyhnmiop" ascii  // source: artifact unique_string, scrambled 'tuid' parameter
        $s2 = "odlsjdfhw" ascii  // source: artifact unique_string, scrambled 'fconn' parameter
        $s3 = "fconn" ascii wide  // source: artifact unique_string, check-in parameter, yara_hint: short (<8 bytes) -> $s/$c only
        $s4 = "/cart.php" ascii  // source: report Fig.4, C2 traffic
        $s5 = "User-Agent: Mozilla_2412239104" ascii wide  // source: report Fig.4, C2 traffic

    condition:
        (
            uint16(0) == 0x5a4d or // PE
            uint32(0) == 0x464c457f or // ELF
            uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe // Mach-O
        )
        and filesize < 10MB
        and (
            1 of ($x*) or
            3 of ($s*)
        )
}
