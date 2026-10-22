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
rule MAL_SLAPSHOT_Go_Tools_Oct26
{
    meta:
        description = "Detects Go-based tools like the nsvmd proxy and vc scanner associated with SLAPSHOT activity by looking for a combination of three indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.rapid7.com/blog/post/ra-netscaler-intrusions-chaining-cve-2026-88771-and-cve-2026-88779"
        date = "2026-10-22"
        hash1 = "8e8b9532ce40eacfe1b4cf2b11241878b70b910aabd90b453b1460df19b51a4d"
        hash2 = "eaf0086237879bbaac00a5874c0e2ff84deede1ba10e6b706e2288fd3a31cdde"
        hash3 = "ffe052fc50271e7739d458b155df790438776032bfd125b974735e1dd9c0b138"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2, s3"

    strings:
        $s1 = "c.v5v.in" ascii // source: explicit_literal
        $s2 = "_dns_candidates.tsv" ascii // source: prose
        $s3 = "_vcenter_verified_all.txt" ascii // source: prose

    condition:
        uint32(0) == 0x464c457f and filesize < 20MB and
        3 of ($s*)
}
