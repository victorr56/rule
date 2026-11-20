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
rule APT_GraphDoor_Nov2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/operation-shadowcloud-graphdoor/122005/"
        date = "2026-11-20"
        description = "Detects GraphDoor malware. The rule will fire if a strong unique indicator (such as a unique hardcoded string, PDB path, API path, or key) is present, or if four supporting strings are found together."
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        malware_family = "GraphDoor"
        unverified_strings = "x3, x4, s3, s6, s7, s8, s9"

    strings:
        // -- Unique ($x) --
        $x1 = "keylogger###Global\\\\OneDriveStandaloneUpdater" ascii wide  // source: figure_or_disassembly
        $x2 = "bof-process###%d###%d###%s###%s###%d###%s\\\\%s###" ascii wide  // source: figure_or_disassembly
        $x3 = "C:/Users/user/Desktop/armon/server.go" ascii  // source: explicit_literal
        $x4 = "iotrh^%4CFGTj" ascii wide  // source: explicit_literal
        $x5 = "/8f50c589-a4d6-4df4-95bb-2fb7f5983fe5/oauth2/v2.0/token" ascii wide  // source: figure_or_disassembly
        $x6 = "/v1.0/sites/buildersemp.sharepoint.com,bbd13fe9-7971-4091-85b4-19e19a02f0d3,615825b3-4c44-473a-8e85-07a9e27900ab/drives/" ascii wide  // source: figure_or_disassembly
        $x7 = "/v1.0/sites/buildersemp.sharepoint.com,bbd13fe9-7971-4091-85b4-19e19a02f0d3,615825b3-4c44-473a-8e85-07a9e27900ab/lists/dd27e665-bef6-4de1-b28f-280c0af4593f/items" ascii wide  // source: figure_or_disassembly
        
        // -- Supporting ($s) --
        $s1 = "commit from INSOMNIA" ascii wide  // source: figure_or_disassembly
        $s2 = "\\\\.\\pipe\\p%lu" ascii wide  // source: figure_or_disassembly
        $s3 = "adsmload" ascii wide  // source: explicit_literal
        $s4 = "Local\\sm%d" ascii wide  // source: figure_or_disassembly
        $s5 = "https://graph.microsoft.com/.default" ascii wide  // source: figure_or_disassembly
        $s6 = "bof-screenshot###" ascii wide  // source: prose
        $s7 = "scr.ts" ascii wide  // source: prose
        $s8 = "pr.ts" ascii wide  // source: prose
        $s9 = "kl.ts" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
