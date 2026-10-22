import "hash"

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
rule MAL_TheGentlemen_Encryptor_Oct2026
{
    meta:
        description = "Detects The Gentlemen ransomware encryptor based on a known file hash."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps"
        date = "2026-10-22"
        hash1 = "f918535f974591ef031bd0f30a8171e3da27a6754e6426a8ba095f83195661c8"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 40

    condition:
        hash.sha256(0, filesize) == "f918535f974591ef031bd0f30a8171e3da27a6754e6426a8ba095f83195661c8"
}
