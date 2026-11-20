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
rule MAL_BlackWizardLock_Ransomware_Nov2026
{
    meta:
        description = "Detects BlackWizardLock ransomware based on a combination of file extension, temporary filename, and contact information."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.virustotal.com/2026/11/catching-ransomware-introducing.html"
        date = "2026-11-20"
        hash1 = "98110dedcca5803bc211f2d8dd640de79a2ba2a69d1def2f4970fa7799313f3e"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s2, s3"
    strings:
        $s1 = ".BLWZ" ascii wide  // source: figure_or_disassembly
        $s2 = ".~BLWZ.tmp" ascii wide  // source: prose
        $s3 = "@seedware" ascii wide  // source: prose
    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        3 of ($s*)
}
