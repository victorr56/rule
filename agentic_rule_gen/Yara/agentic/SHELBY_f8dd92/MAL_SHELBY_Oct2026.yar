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
rule MAL_SHELBY_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/the-shelby-strategy"
        date = "2026-10-17"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        description = "Detects the SHELBY .NET malware family, including SHELBYLOADER and SHELBYC2. A match is triggered by a unique log string, or by a combination of four or more supporting strings like C2 commands, a hardcoded User-Agent, or log messages."
        hash1 = "feb5d225fa38efe2a627ddfbe9654bf59c171ac0742cd565b7a5f22b45a4cc3a"  // JPerf-3.0.0.exe loader
        hash2 = "0354862d83a61c8e69adc3e65f6e5c921523eff829ef1b169e4f0f143b04091f"  // HTTPService.dll (SHELBYLOADER)
        hash3 = "fb8d4c24bcfd853edb15c5c4096723b239f03255f17cec42f2d881f5f31b6025"  // HTTPApi.dll (SHELBYC2)
        hash4 = "5c384109d3e578a0107e8518bcb91cd63f6926f0c0d0e01525d34a734445685c"  // Setup.exe loader
        unverified_strings = "$s1, $s9, $s10"

    strings:
        // Strong anchor, can trigger a match alone
        $x1 = "[WARN] Unusual parent process detected: " ascii wide  // source: strings_listing

        // Supporting strings, require a combination
        $s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" ascii wide  // source: explicit_literal
        $s2 = "File Uploaded Successfully" ascii wide  // source: strings_listing
        $s3 = "/dlextract" ascii wide  // source: strings_listing
        $s4 = "Persist ID: " ascii wide  // source: strings_listing
        $s5 = "https://api.github.com/repos/" ascii wide  // source: strings_listing
        $s6 = "/download" ascii wide  // source: strings_listing
        $s7 = "/upload" ascii wide  // source: strings_listing
        $s8 = "/evoke" ascii wide  // source: strings_listing
        $s9 = "Global\\GHS" ascii wide  // source: prose
        $s10 = "Vivante.txt" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and (
            $x1 or
            4 of ($s*)
        )
}
