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
rule HKTL_libPeConv_Strings_Oct2026
{
    meta:
        description = "Detects files containing strings from the open-source libPeConv library, which is used by NANOREMOTE. Requires a combination of three strings to reduce false positives."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/nanoremote"
        date = "2026-10-29"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 40
        unverified_strings = "s1, s2, s3, s4"

    strings:
        $s1 = "default_func_resolver" ascii  // source: explicit_literal, origin_tool: libPeConv
        $s2 = "hooking_func_resolver" ascii  // source: explicit_literal, origin_tool: libPeConv
        $s3 = "FillImportThunks" ascii  // source: explicit_literal, origin_tool: libPeConv
        $s4 = "ApplyRelocCallback" ascii  // source: explicit_literal, origin_tool: libPeConv

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        3 of them
}
