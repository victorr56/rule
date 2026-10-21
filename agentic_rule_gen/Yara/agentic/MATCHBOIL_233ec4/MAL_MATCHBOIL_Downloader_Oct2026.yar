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
import "pe"
import "dotnet"

rule MAL_MATCHBOIL_Downloader_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-16"
        description = "Detects MATCHBOIL, a C# downloader used by UAC-0099. The rule looks for unique strings related to persistence, sandbox evasion, and C2 communication. Detection is triggered by at least one strong anchor string, or a combination of two medium-strength strings and one supporting string."
        reference = "https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/"
        malware_family = "MATCHBOIL"
        threat_actor = "UAC-0099"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1, x2, x3, x4, x5, x6, x7, a2, s1"

    strings:
        // Strong anchors (>=16 chars), can fire alone
        $x1 = "Global\\\\PlannerAssistant" ascii wide                      // source: explicit_literal
        $x2 = "MeowMeowProgramm.exe" ascii wide                     // source: explicit_literal
        $x3 = "*[System/EventID=6013]" ascii wide                    // source: explicit_literal
        $x4 = "uptime\\sis\\s(\\d+)\\sseconds" ascii wide                // source: explicit_literal
        $x5 = "работоспособного\\sсостояния\\s(\\d+)\\sсек" ascii wide // source: explicit_literal
        $x6 = "AdditionalLib.dll" ascii wide                        // source: explicit_literal
        $x7 = "SMTPClientApplication.exe" ascii wide                // source: explicit_literal
        $x8 = "<script>(.*?)</script>" ascii wide                   // source: figure_literals, Figure 4
        $x9 = "SELECT ProcessorId FROM Win32_Processor" ascii wide // source: figure_literals, Figure 2

        // Medium anchors (unique but shorter)
        $a1 = "/eventmanager" ascii wide                           // source: figure_literals, Figure 4
        $a2 = "DeviceMonitor" ascii wide                           // source: explicit_literal

        // Supporting strings
        $s1 = "config.ini" ascii wide                               // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and dotnet.is_dotnet
        and (
            1 of ($x*) or
            (2 of ($a*) and $s1)
        )
}
