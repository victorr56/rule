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
rule MAL_PUMAKIT_Linux_Rootkit_Oct2026
{
    meta:
        description = "Detects the PUMAKIT LKM rootkit (puma.ko). The rule triggers on a combination of three specific strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/declawing-pumakit"
        date = "2026-10-26"
        hash1 = "bc9193c2a8ee47801f5f44beae51ab37a652fda02cd32d01f8e88bb793172491"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1"

    strings:
        $s1 = ".puma-config" ascii  // source: explicit_literal
        $s2 = "PUMA %s" ascii  // source: strings_listing
        $s3 = "zarya" ascii  // source: strings_listing

    condition:
        uint32(0) == 0x464c457f and // ELF magic
        filesize < 2MB and
        3 of ($s*)
}
