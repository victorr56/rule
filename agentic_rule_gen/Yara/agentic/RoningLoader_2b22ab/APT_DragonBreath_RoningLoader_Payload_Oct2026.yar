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
rule APT_DragonBreath_RoningLoader_Payload_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/roningloader"
        date = "2026-10-17"
        description = "Detects the final payload of RoningLoader, a Gh0st RAT variant. The rule matches on unique mutexes, registry keys, a window class name, and specific strings related to keylogging and data exfiltration. A match requires one of several unique high-confidence strings."
        hash1 = "3dd470e85fe77cd847ca59d1d08ec8ccebe9bd73fd2cf074c29d87ca2fd24e33"
        hash2 = "fd4dd9904549c6655465331921a28330ad2b9ff1c99eb993edf2252001f1d107"
        hash3 = "fc63f5dfc93f2358f4cba18cbdf99578fff5dac4cdd2de193a21f6041a0e01bc"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, x3, x4"

    strings:
        // Strong anchors (>=16 byte text string or >=8 byte hex pattern)
        $x1 = "Global\\DHGGlobalMutex" ascii wide  // source: explicit_literal, artifact.kind: mutex
        $x2 = "HKEY_CURRENT_USER\\offlinekey\\open" ascii wide  // source: explicit_literal, artifact.kind: registry_key
        $x3 = "ClipboardListener_Class_Toggle" ascii wide  // source: explicit_literal, artifact.kind: unique_string
        $x4 = { 5b e5 89 aa e5 88 87 e6 9d bf 3a 5d }  // "[剪切板:]", source: explicit_literal, artifact.kind: unique_string
        $x5 = { e7 8b 90 e7 8b b8 e7 b3 bb e5 88 97 }  // "狐狸系列", source: figure_or_disassembly, artifact.kind: unique_string

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        1 of ($x*)
}
