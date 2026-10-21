import "dotnet"

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
rule MAL_RogueScreenConnect_Propagation_Component_Oct2023
{
    meta:
        description = "Detects the modified ScreenConnect .NET component responsible for worm-like propagation of VBScript stagers. A match occurs on a unique hardcoded path or on a combination of three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/rogue-screenconnect-installations"
        date = "2023-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Strong anchor
        $x1 = "C:\\\\users\\\\public\\\\Libraries\\\\Default\\\\Lib\\\\lib1" ascii wide  // source: report Fig.12, Fig.13 decompilation

        // Supporting strings related to the malicious file transfer logic
        $s1 = "ScreenConnect.TransferFilesMessage, ScreenConnect.Core" ascii  // source: report Fig.13 decompilation
        $s2 = "RegisterVirtualFiles" ascii  // source: report Fig.12, Fig.13 decompilation
        $s3 = "VirtualStreamSender" ascii  // source: report Fig.12, Fig.13 decompilation
        $s4 = "EnqueueOutgoingMessage" ascii  // source: report Fig.13 decompilation
        $s5 = "ConnectionID" ascii  // source: report Fig.12 decompilation
        $s6 = "ProcessType" ascii  // source: report Fig.12 decompilation

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        dotnet.is_dotnet and
        (
            $x1 or
            3 of ($s*)
        )
}
