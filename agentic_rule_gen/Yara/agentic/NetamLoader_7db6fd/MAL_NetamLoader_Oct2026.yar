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
rule MAL_NetamLoader_Oct2026
{
    meta:
        description = "Detects NetamLoader, a multi-stage .NET loading framework. A match requires a strong unique indicator (GUID, key) or a combination of several medium-strength or supporting indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/netamloader/121676/"
        date = "2026-10-29"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "a3, a4, s1, s3, s4, s5, x1, x2"

    strings:
        // Strong unique indicators ($x*), can fire alone
        $x1 = "fdb00e52-a214-4aa1-8fba-4357bb0072ec" ascii wide  // source: explicit_literal
        $x2 = "ab8902b4-09ca-4bb6-b78d-a8f59079a8d5" ascii wide  // source: explicit_literal
        $x3 = "0202097a-5c1e-460d-b5e0-030b9756b242" ascii wide  // source: figure_or_disassembly
        $x4 = "W7BHmIRBRY3FOIfWprbW/ZJh5GbPND3sY+qCBDY7O2A=" ascii  // source: figure_or_disassembly
        $x5 = "9fT04e03tAiZAPogcDWt0w==" ascii  // source: figure_or_disassembly

        // Medium-strength unique indicators ($a*), require combination
        $a1 = "Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" ascii  // source: figure_or_disassembly
        $a2 = "Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" ascii  // source: figure_or_disassembly
        $a3 = "GetExtendedUpdateInfoHandler" ascii wide  // source: explicit_literal
        $a4 = "CmitUpdateAgent" ascii wide  // source: explicit_literal

        // Supporting indicators ($s*), require combination
        $s1 = "(?:([a-zA-Z]+)=)?(.*)" ascii wide  // source: explicit_literal
        $s2 = "System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii  // source: figure_or_disassembly
        $s3 = "m.C()" ascii wide  // source: prose
        $s4 = "DllSurrogate" ascii wide  // source: prose
        $s5 = "COMPlus_ETWEnabled" ascii wide  // source: prose
        $s6 = "/model_v4/" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d
        and filesize < 20MB
        and (
            1 of ($x*) or
            4 of ($s*) or
            (2 of ($a*) and 1 of ($s*))
        )
}
