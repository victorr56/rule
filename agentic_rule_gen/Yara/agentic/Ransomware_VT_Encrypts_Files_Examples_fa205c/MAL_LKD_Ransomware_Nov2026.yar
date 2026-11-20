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
rule MAL_LKD_Ransomware_Nov2026
{
    meta:
        description = "Detects lkd.exe ransomware based on its unique ransom note name."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.virustotal.com/2026/11/catching-ransomware-introducing.html"
        date = "2026-11-20"
        hash1 = "a8c2402ef3ae115300f5428712ccb0b5461f4a2f14b5bfdfbe08d5ad86bd3087"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 55
        unverified_strings = "x1"
    strings:
        $x1 = "read_me_restore.txt" ascii wide  // source: prose
    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        $x1
}
