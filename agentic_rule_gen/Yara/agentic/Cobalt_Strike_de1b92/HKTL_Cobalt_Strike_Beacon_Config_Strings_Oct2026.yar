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
rule HKTL_Cobalt_Strike_Beacon_Config_Strings_Oct2026
{
    meta:
        description = "Detects Cobalt Strike beacon payloads by identifying hardcoded configuration strings. The rule can be triggered by a single unique Base64-encoded string, or a combination of four supporting configuration values."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/blog/extracting-cobalt-strike-beacon-configurations"
        date = "2026-10-28"
        hash1 = "697fddfc5195828777622236f2b133c0a24a6d0dc539ae7da41798c4456a3f89"
        hash2 = "7475a6c08fa90e7af36fd7aa76be6e06b9e887bc0a6501914688a87a43ac7ac4"
        hash3 = "f9b38c422a89d73ebdab7c142c8920690ee3a746fc4eea9175d745183c946fc5"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        // Unique, strong anchors
        $x1 = "GNEtW6h/g4dQzm0dOkL5NA==" ascii wide  // source: figure_or_disassembly
        $x2 = "IiuPJ9vfuo3dVZ7son6mSA==" ascii wide  // source: figure_or_disassembly

        // Supporting strings
        $s1 = "334850267" ascii wide  // source: figure_or_disassembly
        $s2 = "45000" ascii wide  // source: figure_or_disassembly
        $s3 = "CreateThread 'ntdll!RtlUserThreadStart'" ascii wide  // source: figure_or_disassembly
        $s4 = "NtQueueApcThread-s" ascii wide  // source: figure_or_disassembly
        $s5 = "RtlCreateUserThread" ascii wide  // source: figure_or_disassembly
        $s6 = "2021-12-24" ascii wide  // source: figure_or_disassembly
        $s7 = "37" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
