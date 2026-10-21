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
rule HKTL_SHELLTER_Framework_Oct2026
{
    meta:
        description = "Detects SHELLTER, a commercial evasion framework. The rule triggers on unique strings or code patterns, or a combination of three supporting indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/taking-shellter"
        date = "2026-10-17"
        hash1 = "c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30"
        hash2 = "da59d67ced88beae618b9d6c805f40385d0301d412b787e9f9c9559d00d2c880"
        hash3 = "b3e93bfef12678294d9944e61d90ca4aa03b7e3dae5e909c3b2166f122a14dad"
        hash4 = "7d0c9855167e7c19a67f800892e974c4387e1004b40efb25a2a1d25a99b03a10"
        hash5 = "70ec2e65f77a940fd0b2b5c0a78a83646dec17583611741521e0992c1bf974f1"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x2, x3, s1, s2, s4"

    strings:
        // Strong indicators (unique strings and code patterns)
        $x1 = "fdb00e52-a214-4aa1-8fba-4357bb0072ec" ascii wide  // source: figure_or_disassembly
        $x2 = "--Force-PreloadModules-Basic" ascii wide  // source: explicit_literal
        $x3 = "--Force-PreloadModules-Networking" ascii wide  // source: explicit_literal
        $x4 = "IAntimalware::Scan" ascii wide  // source: figure_or_disassembly
        $x5 = { 48 89 4C 24 08 48 83 EC 18 48 B8 E8 E7 E6 E5 E4 E3 E2 E1 48 89 04 24 48 8B 44 24 20 48 8B 00 81 38 05 00 00 C0 }  // source: strings_listing
        $x6 = { 48 8B 49 30 8B 49 70 8B 40 74 0B C1 25 70 00 00 40 85 C0 75 22 B8 D4 02 00 00 48 05 00 00 FE 7F }  // source: strings_listing
        $x7 = { 48 8B 44 24 ?? 0F BE 00 85 C0 74 ?? 48 8B 44 24 ?? 0F BE 00 89 44 24 ?? 48 8B 44 24 ?? 48 FF C0 48 89 44 24 ?? 8B 04 24 C1 E8 ?? 8B 0C 24 C1 E1 ?? 0B C1 }  // source: strings_listing

        // Supporting indicators
        $s1 = "kern3l32.dll" ascii wide  // source: explicit_literal
        $s2 = "ntll.dll" ascii wide  // source: prose
        $s3 = "KdDebuggerEnabled" ascii wide  // source: figure_or_disassembly
        $s4 = "LZNT1" ascii wide  // source: explicit_literal
        $s5 = "AMSI" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
