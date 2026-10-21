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
rule MAL_GHOSTENGINE_Scripts_Oct2026
{
    meta:
        description = "Detects GHOSTENGINE PowerShell scripts by unique filenames used for its modules."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/invisible-miners-unveiling-ghostengine"
        date = "2026-10-18"
        hash1 = "7c242a08ee2dfd5da8a4c6bc86231985e2c26c7b9931ad0b3ea4723e49ceb1c1"
        hash2 = "6f3e913c93887a58e64da5070d96dc34d3265f456034446be89167584a0b347e"
        hash3 = "cc4384510576131c126db3caca027c5d159d032d33ef90ef30db0daa2a0c4104"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s2, s3, s4"

    strings:
        $s1 = "*get.png*" ascii  // source: report explicit_literal, String to find other instances
        $s2 = "clearn.png" ascii  // source: report explicit_literal, Cleanup script filename
        $s3 = "backup.png" ascii  // source: report explicit_literal, Backdoor module filename
        $s4 = "kill.png" ascii  // source: report explicit_literal, EDR termination script filename

    condition:
        filesize < 1MB and
        3 of them
}
