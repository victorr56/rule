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
rule HKTL_Raccoon_Stealer_Gen_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        description = "Detects Raccoon Stealer based on unique hardcoded strings."
        reference = "https://www.group-ib.com/blog/fakesecurity-raccoon/"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x2"
    strings:
        $x1 = "Raccoon Stealer. We steal, You deal!" ascii wide  // source: figure_or_disassembly
        $x2 = "Private key, gate address, and other string values are heavily encrypted" ascii wide  // source: explicit_literal
    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and 1 of ($x*)
}
