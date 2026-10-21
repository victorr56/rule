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
rule MAL_Lumma_Stealer_ChaCha20_Routines_Oct2026
{
    meta:
        description = "Detects Lumma Stealer based on unique byte patterns from its custom ChaCha20 implementation."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/nightmare-on-0xelm-street"
        date = "2026-10-17"
        hash1 = "26803ff0e079e43c413e10d9a62d344504a134d20ad37af9fd3eaf5c54848122"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = { b8 38 ?? 24 40 0b ?? ?? ?? ?? ?? 00 b? ?? ?? 0? ?? ?? 00 96 f3 a5 }  // source: figure_or_disassembly
        $x2 = { 55 53 57 56 81 ec 1? 01 00 00 8b ?? 24 3? 01 00 00 85 ?? 0f 84 ?? ?? 08 00 00 }  // source: figure_or_disassembly
        $x3 = { 8d 8? e0 ?? 24 40 08 d7 42 4? ?? ff 3? 56 5? 68 ?? ?? ?? 45 00 e8 ?? ?? ?? ff ff }  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d
        and filesize < 20MB
        and 1 of them
}
