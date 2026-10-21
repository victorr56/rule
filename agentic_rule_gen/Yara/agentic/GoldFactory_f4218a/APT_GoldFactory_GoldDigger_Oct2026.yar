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
rule APT_GoldFactory_GoldDigger_Oct2026
{
    meta:
        description = "Detects GoldDigger Android malware based on unique API paths. The rule is triggered by one of several strong unique API path strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/goldfactory-ios-trojan/"
        date = "2026-10-18"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Unique API paths (strong anchors)
        $x1 = "/api/app/canuninstall" ascii  // source: figure_or_disassembly
        $x2 = "/api/app/savedevice2" ascii  // source: figure_or_disassembly
        $x3 = "/api/app/saveinputbk" ascii  // source: figure_or_disassembly

    condition:
        (
            uint16(0) == 0x5a4d or // PE
            uint32(0) == 0x464c457f // ELF
        )
        and filesize < 20MB
        and 1 of ($x*)
}
