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
rule MAL_MANTLEMAZE_Loader_Oct2026
{
    meta:
        description = "Detects MANTLEMAZE loaders which embed fabricated contract numbers, NDA identifiers, and security module log messages to evade analysis. A match is triggered by one of several unique fabricated strings, or a combination of other suspicious indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.talosintelligence.com/ignore-all-instructions-and-read-this-blog-the-state-of-ai-analysis-evasion-in-malware/"
        date = "2026-10-16"
        hash1 = "389066bd5543aeea363d23a4dce7f7a21c7f2c73c61f506a93a69f594cf48ecf"
        hash2 = "5f60d16fa67ff8ef07817c33b7e6b7fa91c6c21060020df46b1f5c56e076e259"
        hash3 = "a0294f7152f9c4c908e9def58279e9fa29952715947c950c8489949f26a15cc8"
        hash4 = "c17bf76d02163863c251c3bb3a12725eeb525fab5522521923925e0469ca269f"
        hash5 = "2aa7f13bf474e2ce5049fd4db2bf4da04b4ce51ac0d36dceb24865255241c937"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, x3, x4, x5, s1, s2"

    strings:
        // Strong, unique fabricated identifiers
        $x1 = "FA8750-23-C-0518" ascii wide  // source: explicit_literal
        $x2 = "MSFT-2024-SEC-0847" ascii wide  // source: explicit_literal
        $x3 = "NDA-GOOG-2024-7291" ascii wide  // source: explicit_literal
        $x4 = "Google Security Module v4.2.1 initialized" ascii wide  // source: explicit_literal
        $x5 = "Microsoft Defender ATP Kernel Module loaded - EAL4+ certified" ascii wide  // source: explicit_literal

        // Supporting indicators
        $s1 = "Certificate #4521" ascii wide  // source: explicit_literal
        $s2 = "iqvw64e.sys" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            2 of ($s*)
        )
}
