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
rule MAL_QBOT_Gen_Oct2026
{
    meta:
        description = "Detects QBOT malware based on a unique configuration string."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/blog/qbot-configuration-extractor"
        date = "2026-10-29"
        hash1 = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "jHxastDcds)oMc=jvh7wdUhxcsdt2" ascii  // source: strings_listing

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        $x1
}
