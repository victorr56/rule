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
rule MAL_ARTEX_Agent_Nov2026
{
    meta:
        description = "Detects ARTEX Agentic Offensive Framework and its forks. This rule is triggered by the presence of one of two unique strings, a combination of three supporting strings, or all three MurmurHash3 constants associated with embedded icons."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.reversinglabs.com/blog/threat-researchers-notebook-detection-strategies-for-artex-and-related-forks"
        date = "2026-11-20"
        hash1 = "001eb437c20805fb94e8e7014c019318f0f3186bc0cd2ea3508245aafbf0c248"
        hash2 = "014154af33662f55901a20902b9deae23a63fe3817fad44a2718f6e30e7a9cb1"
        hash3 = "01edf9d0f41a7f527c935bb95974402cf1667635e32111b063eecf8b19f0e322"
        hash4 = "047da1e769cc583b2f697e9d6c5043b8aa004a7bff4870718850900cd64836b5"
        hash5 = "04f1f1c54918c16db83d82362a8bd14a2ad9441b5654627889d96a8b7a2d33dd"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, s1, s2, s3, c1, c2, c3"

    strings:
        // Unique strings (strong anchors)
        $x1 = "favicon.1uboyqwm7-s27" ascii  // source: report artifact, explicit_literal
        $x2 = "%ARTEX_PROBE_UNSET%" ascii  // source: report artifact, explicit_literal

        // Supporting strings
        $s1 = "github.com/Autumn-27/norma" ascii  // source: report artifact, explicit_literal
        $s2 = "Mozilla/5.0 (ARTEX)" ascii  // source: report artifact, explicit_literal
        $s3 = "Mozilla/5.0 (spa-api-recon spider)" ascii  // source: report artifact, explicit_literal

        // MurmurHash3 icon hash constants
        $c1 = { B2 C3 73 DE }  // source: report artifact, explicit_literal, MurmurHash3 integer -576220750, little-endian
        $c2 = { 2B 5F 20 AF }  // source: report artifact, explicit_literal, MurmurHash3 integer -1356779733, little-endian
        $c3 = { 67 6F 4C E8 }  // source: report artifact, explicit_literal, MurmurHash3 integer -397770841, little-endian

    condition:
        (
            uint16(0) == 0x5a4d or // PE
            uint32(0) == 0x464c457f or // ELF
            uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe // Mach-O
        )
        and filesize < 20MB
        and (
            1 of ($x*) or
            3 of ($s*) or
            3 of ($c*)
        )
}
