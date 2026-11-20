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
rule HKTL_Imzimzgo_Mimikatz_Variant_Nov2026
{
    meta:
        description = "Detects a specific variant of Mimikatz, identified by the internal name 'imzimzgo 2.2.0 x64', which was observed being used in GitDoor campaigns."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/operation-shadowcloud-gitdoor/122004/"
        date = "2026-11-20"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 55

    strings:
        $x1 = "imzimzgo 2.2.0 x64" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        $x1
}
