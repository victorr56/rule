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
rule MAL_K404_Ransomware_Nov2026
{
    meta:
        description = "Detects components of the K404 ransomware campaign based on a unique associated filename."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.virustotal.com/2026/11/catching-ransomware-introducing.html"
        date = "2026-11-20"
        hash1 = "3dd45ab8e2f9c1af773a75221d792fb78870764419170e9c9c5941160364c700"
        hash2 = "fb0982bb9f5d5700685dcf4e99ff695f4593fbc3e3d0359d4c2baf23c545f354"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 55
        unverified_strings = "x1"
    strings:
        $x1 = "system_update.pyw" ascii wide  // source: prose
    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        $x1
}
