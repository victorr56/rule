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
rule SUSP_Execution_Technique_Strings_Oct26
{
    meta:
        description = "Detects suspicious PE files containing strings related to various malware execution and persistence techniques. This rule requires a combination of suspicious strings to trigger."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.virustotal.com/2026/10/process-trees-in-livehunt-yara-rules.html"
        date = "2026-10-28"
        hash1 = "fe8357febe314becf31510a7a2ecb0369e312ad58a448292f5f8a09075d7694c"
        hash2 = "77da8a02d71078564409863c358a544e981b9643c8f5f0c1daabc5d5d176e3c75"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "a2, a4, a5, a6, s3, s4"

    strings:
        // Moderately unique strings
        $a1 = "westingcostringforme.vbe" ascii wide  // source: figure_or_disassembly
        $a2 = "Invoke-EnvironmentCheck" ascii wide  // source: prose
        $a3 = "XBRYINEZ.ps1" ascii wide  // source: figure_or_disassembly
        $a4 = "rhpmx63snl.exe" ascii wide  // source: prose
        $a5 = "xd24mgasgb4.exe" ascii wide  // source: prose
        $a6 = "PoItWjNFjv.vbs" ascii wide  // source: prose

        // Supporting strings
        $s1 = "--headless" ascii wide  // source: figure_or_disassembly
        $s2 = "-Embedding" ascii wide  // source: figure_or_disassembly
        $s3 = "Login Data.tmp" ascii wide  // source: prose
        $s4 = "/stext" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            2 of ($a*) and 1 of ($s*) or
            4 of ($s*)
        )
}
