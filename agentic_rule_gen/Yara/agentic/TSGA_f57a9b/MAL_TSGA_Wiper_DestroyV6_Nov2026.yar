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
rule MAL_TSGA_Wiper_DestroyV6_Nov2026
{
    meta:
        description = "Detects the 'destroy_v6' wiper used by UNC5221. The rule requires three specific strings to be present."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        date = "2026-11-20"
        hash1 = "c7d9477309fac6c638a1128442056a242de086996add8cb49cd6496c36003237"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2, s3"
    strings:
        $s1 = "destroy_v6" ascii  // source: prose
        $s2 = "DREAM_ANNEXATION.txt" ascii  // source: prose
        $s3 = "vpxuser" ascii  // source: prose
    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        3 of them
}
