import "dotnet"

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
rule APT_NightEagle_GhostContainer_dotNET_Oct2026
{
    meta:
        description = "Detects the GhostContainer .NET backdoor used by the NightEagle (APT-Q-95) group. The rule matches on unique hex patterns, C2 domains, a unique DLL name, or a combination of four specific supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1, s2, s3, s4"

    strings:
        $x1 = { 50 61 67 65 4e 61 6d 65 00 73 61 6d 70 6c 65 50 }  // source: artifact hex_pattern, "PageName.sampleP"
        $x2 = { 50 61 74 68 00 66 61 6b 50 61 67 65 4e 61 6d }  // source: artifact hex_pattern, "Path.fakPageNam"
        $x3 = "tfgwd1nc-8443.euw.dev.tunnels.ms" ascii wide  // source: artifact domain
        $x4 = "tfgwd1nc-8443.euw.devtunnels.ms" ascii wide  // source: artifact url
        $x5 = "3ecd1cd627d0340c92901a478a7caad8.dll" ascii wide  // source: artifact figure_or_disassembly

        $s1 = "fakePageName" ascii wide  // source: artifact prose
        $s2 = "App_Web_843e75cf5b63" ascii  // source: artifact prose
        $s3 = "App_Web_8c9b251fb5b3" ascii  // source: artifact prose
        $s4 = "trueconf-broker.exe" ascii wide  // source: artifact explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        dotnet.is_dotnet and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
