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
rule APT_REF8801_Exegis_Loader_Oct2026
{
    meta:
        description = "Detects the Exegis Python-based loader used by REF8801 (Apex Accelerator)."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages"
        date = "2026-10-16"
        hash1 = "ee8cd9aba420f1b26b5d43e5bcdd6025a277b4946bb5daf76ab45c0e5f7ecd0b"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "r08dxeJZc2T41Chy4lUwdsP47j7eIIeEAlQy9Tae_iA=" ascii // source: artifact unique_string, embedded Fernet key
        $x2 = "gAAAAABqrNdEp0nz79CHtN1anvrTmhtcF1_l2ZdRjzvUhD5cmgK07bJaj6E05_Bb0V2lskGwjRUUO7gX0mx6nXmyCLEMQZJXtA==" ascii // source: artifact unique_string, embedded Fernet token

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        1 of ($x*)
}
