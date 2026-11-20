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
rule HKTL_Erfrp_GraphDoor_Nov2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/operation-shadowcloud-graphdoor/122005/"
        date = "2026-11-20"
        description = "Detects a specific build of the Erfrp-based proxy plugin used in Operation ShadowCloud."
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        hktl = "Erfrp"
        unverified_strings = "x1"

    strings:
        $x1 = "C:/Users/user/Desktop/pythonrat/proxytest/Erfrp-0.1/frpc.go" ascii  // source: explicit_literal

    condition:
        ( uint16(0) == 0x5a4d or uint32(0) == 0x464c457f ) and filesize < 20MB and
        $x1
}
