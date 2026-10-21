/* Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $s, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
rule HKTL_Hidden_Rootkit_Oct2026
{
    meta:
        description = "Detects components of the 'Hidden' rootkit, also known as HIDDENDRIVER, and its CLI tool. This tool has been used by threat actor REF3927. The rule detects unique configuration strings hardcoded in the binaries. A match requires three or more of these unique strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/tollbooth"
        date = "2026-10-17"
        hash1 = "913431f1d36ee843886bb052bfc89c0e5db903c673b5e6894c49aabc19f1e2fc"
        hash2 = "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $s1 = "Kbj_WinkbjFsDirs" ascii wide  // source: figure_or_disassembly, config string
        $s2 = "Kbj_WinkbjFsFiles" ascii wide  // source: figure_or_disassembly, config string
        $s3 = "Kbj_WinkbjRegKeys" ascii wide  // source: figure_or_disassembly, config string
        $s4 = "Kbj_WinkbjRegValues" ascii wide  // source: figure_or_disassembly, config string
        $s5 = "Kbj_FangxingImages" ascii wide  // source: figure_or_disassembly, config string
        $s6 = "Kbj_BaohuImages" ascii wide  // source: figure_or_disassembly, config string
        $s7 = "Kbj_WinkbjImages" ascii wide  // source: figure_or_disassembly, config string
        $s8 = "Kbj_YinshenMode" ascii wide  // source: figure_or_disassembly, config string

    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and 3 of ($s*)
}
