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
rule APT_FishMonger_SprySOCKS_Backdoor_Oct2026
{
    meta:
        description = "Detects the Windows backdoor SprySOCKS, used by the FishMonger (I-SOON) group. This rule covers both WIN_DRV and WIN_PLUS variants."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $x2, $x3, $s1, $s2, $s3"
        hash1 = "d87042512f435017a42168345719875e533c306d8602b938c53a64c489c656d0"
        hash2 = "3992b8d4389148d2871f9859f5188f58c707d727a858db11e9f69b828a2a5e55"

    strings:
        // Strong unique strings (>= 16 chars or GUIDs)
        $x1 = "uXQLESMXGaRMs6BL" ascii wide  // source: explicit_literal
        $x2 = "QFTHEYjzX3RBOMgZ" ascii wide  // source: explicit_literal
        $x3 = "Global\\{DCAA7ED8-521B-4EAB-BE21-65254CF59239}" ascii wide  // source: explicit_literal
        $x4 = "clientid|3926628324--0F8BFBFF000A0671" ascii wide  // source: figure_or_disassembly

        // Supporting unique strings
        $s1 = "fqwhi2d1qaz2" ascii wide  // source: explicit_literal
        $s2 = "prcs-server-run" ascii wide  // source: explicit_literal
        $s3 = "PrcsServer.dll" ascii wide  // source: explicit_literal

        // Network magic values
        $c1 = { bc bc ac ac }  // source: Figure 12. SprySOCKS network-traffic capture..., little-endian
        $c2 = { bc bf ac ac }  // source: Figure 12. SprySOCKS network-traffic capture..., little-endian

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and (
            1 of ($x*) or
            3 of ($s*) or
            (1 of ($c*) and 2 of ($s*))
        )
}
