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
rule MAL_QBOT_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects QBOT malware based on a unique hardcoded key or a specific scheduled task creation command line."
        reference = "https://www.elastic.co/security-labs/threat-command/exploring-the-qbot-attack-pattern"
        hash1 = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
        hash2 = "636e2904276fe33e10cce5a562ded451665b82b24c852cbdb9882f7a54443e02"
        hash3 = "a2bacde7210d88675564106406d9c2f3b738e2b1993737cb8bf621b78a9ebf56"
        hash4 = "0838cd11d6f504203ea98f78cac8f066eb2096a2af16d27fb9903484e7e6a689"
        score = 60
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        tlp = "WHITE"

    strings:
        $x1 = "jHxastDcds)oMc=jvh7wdUhxcsdt2" ascii wide  // source: artifact unique_string
        $x2 = "schtasks.exe /Create /RU \"NT AUTHORITY\\\\SYSTEM\" /SC ONSTART /TN %u /TR \"%s\" /NP /F" ascii wide  // source: artifact unique_string

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        1 of ($x*)
}
