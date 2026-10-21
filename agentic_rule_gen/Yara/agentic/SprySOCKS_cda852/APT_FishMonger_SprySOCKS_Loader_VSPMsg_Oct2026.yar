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
rule APT_FishMonger_SprySOCKS_Loader_VSPMsg_Oct2026
{
    meta:
        description = "Detects the VSPMsg.dll loader for the SprySOCKS WIN_PLUS variant based on a combination of exported function names and named pipe fragments."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "$a1, $a2, $a3, $s1"

    strings:
        // Medium-strength unique strings
        $a1 = "GetErrorMessageModule" ascii  // source: explicit_literal
        $a2 = "SetErrorMessageModule" ascii  // source: explicit_literal
        $a3 = "fqwhi2d1qaz2" ascii wide  // source: explicit_literal

        // Supporting strings
        $s1 = "VSPMsg" ascii wide  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and (
            2 of ($a*) and $s1
        )
}
