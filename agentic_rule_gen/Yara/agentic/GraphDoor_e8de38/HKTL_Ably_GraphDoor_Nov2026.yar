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
rule HKTL_Ably_GraphDoor_Nov2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/operation-shadowcloud-graphdoor/122005/"
        date = "2026-11-20"
        description = "Detects the Ably-based proxy plugin used in Operation ShadowCloud. The rule will fire on a unique connection parameter or a combination of three supporting indicators."
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        hktl = "Ably"
        unverified_strings = "s1"

    strings:
        $x1 = "client=cpp-socks5" ascii wide  // source: figure_or_disassembly

        $s1 = "File proxy server started" ascii wide  // source: explicit_literal
        $s2 = "Local\\pcs%d" ascii wide  // source: figure_or_disassembly
        $s3 = "###!!###" ascii wide  // source: figure_or_disassembly
        $s4 = "wss://main.pusher.ably.net/app/" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
