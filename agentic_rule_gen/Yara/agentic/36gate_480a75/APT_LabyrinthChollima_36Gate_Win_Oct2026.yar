/*
Self-check
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
rule APT_LabyrinthChollima_36Gate_Win_Oct2026
{
    meta:
        description = "Detects Windows components of the 36Gate malware used in the 3CX supply chain attack. Detection is based on a unique key string or a combination of three other specific strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/3cx-supply-chain-attack/"
        date = "2026-10-22"
        hash1 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
        hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "3jB(2bsG#@c7, AVMonitorRefreshEvent, 3CXDesktopApp/18.11.1197, d3dcompiler_47.dll, ffmpeg.dll"

    strings:
        $x1 = "3jB(2bsG#@c7" ascii  // source: explicit_literal

        $s1 = "AVMonitorRefreshEvent" ascii wide  // source: explicit_literal
        $s2 = "3CXDesktopApp/18.11.1197" ascii  // source: explicit_literal
        $s3 = "d3dcompiler_47.dll" ascii wide  // source: explicit_literal
        $s4 = "ffmpeg.dll" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            $x1 or
            3 of ($s*)
        )
}
