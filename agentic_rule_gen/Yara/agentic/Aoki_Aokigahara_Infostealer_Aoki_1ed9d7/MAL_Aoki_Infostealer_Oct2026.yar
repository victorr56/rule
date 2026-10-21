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
rule MAL_Aoki_Infostealer_Oct2026
{
    meta:
        description = "Detects Aoki (Aokigahara) infostealer. This rule requires the presence of three specific strings associated with the malware."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.security.com/threat-intelligence/aoki-infostealer-ai-targeting"
        date = "2026-10-16"
        hash1 = "752c8e64af60960b85cf00e4bd34eb459e24b7939464f718ec18494df43b4b69"
        hash2 = "bf037920d39b85572ec7e53b51f09c28198c2c0afbc7c7d6cf639b1f047caebf"
        hash3 = "0adc8e83b2416c275b1283916d70568faddeb6d718eb45f9addfb0938db245b3"
        hash4 = "6655b89b9885483d459c73f2a52e3cec121de5c5956172a8676a0f4c2de94999"
        hash5 = "780bbdbb119befd4eb16e0c2ec0c64e7bedc1b53ce4f85804aea091a6e3af519"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2, s3"

    strings:
        $s1 = "Aokigahara" ascii wide  // source: explicit_literal
        $s2 = "Infostealer.Aoki" ascii wide  // source: explicit_literal
        $s3 = "/gate" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        3 of ($s*)
}
