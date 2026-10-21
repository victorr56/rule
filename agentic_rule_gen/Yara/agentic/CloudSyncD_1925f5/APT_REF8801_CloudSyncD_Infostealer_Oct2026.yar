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
rule APT_REF8801_CloudSyncD_Infostealer_Oct2026
{
    meta:
        description = "Detects the Windows infostealer component of CloudSyncD, used by REF8801 (Apex Accelerator). This rule detects the malware based on unique cryptographic constants, LCG parameters, and a hardcoded Key Storage Provider key name. A match is triggered if one of these unique strings is found."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages"
        date = "2026-10-16"
        hash1 = "ee8cd9aba420f1b26b5d43e5bcdd6025a277b4946bb5daf76ab45c0e5f7ecd0b"
        hash2 = "ed5cb4af1d2cb067b8d23783ebf05d70278728462ba4f1bf29da0a3a41efc35e"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787" ascii // source: figure_literals Crypto constants and fallback key storage provider (KSP) key names for handling the key envelope.
        $x2 = "E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660" ascii // source: figure_literals Crypto constants and fallback key storage provider (KSP) key names for handling the key envelope.
        $x3 = "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390" ascii // source: figure_literals Crypto constants and fallback key storage provider (KSP) key names for handling the key envelope.
        $x4 = { D5 43 DE B9 C6 74 A8 F7 } // source: artifact hex_pattern, LCG multiplier A in block-shuffle, little-endian
        $x5 = { B7 5B E3 BB C1 02 ED E0 } // source: artifact hex_pattern, LCG increment C in block-shuffle, little-endian
        $x6 = { 7D DD 42 DD 0E BF 0F F4 } // source: artifact hex_pattern, LCG inverse constant A_inverse in block-shuffle, little-endian
        $x7 = { C2 1E EF 49 02 35 B3 3B } // source: artifact hex_pattern, Encoded seed XORed with FNV-1a stub hash, little-endian
        $x8 = "Microsoft Edgekey1" wide // source: figure_literals Crypto constants and fallback key storage provider (KSP) key names for handling the key envelope.

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        1 of ($x*)
}
