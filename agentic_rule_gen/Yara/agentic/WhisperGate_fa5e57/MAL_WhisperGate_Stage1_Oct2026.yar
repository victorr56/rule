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
rule MAL_WhisperGate_Stage1_Oct2026
{
    meta:
        description = "Detects the WhisperGate Stage 1 MBR wiper component. This rule looks for the unique Bitcoin address displayed in the ransom note."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/operation-bleeding-bear"
        date = "2026-10-29"
        hash1 = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv" ascii  // source: report figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        $x1
}
