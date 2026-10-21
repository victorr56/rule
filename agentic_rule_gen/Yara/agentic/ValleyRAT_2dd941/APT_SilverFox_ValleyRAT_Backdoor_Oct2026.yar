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
rule APT_SilverFox_ValleyRAT_Backdoor_Oct2026
{
    meta:
        description = "Detects the ValleyRAT backdoor payload, attributed to the Silver Fox group. This rule requires a combination of at least four strings related to process hollowing, anti-analysis checks, and disabling security features."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/valleyrat-backdoor-adware/121175/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Supporting strings. None are unique enough to be strong anchors.
        $s1 = "Windows\\\\SysWOW64\\\\svchost.exe" ascii wide  // source: Implementation of the process hollowing technique (decompilation)
        $s2 = "Windows\\\\System32\\\\svchost.exe" ascii wide  // source: Implementation of the process hollowing technique (decompilation)
        $s3 = "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\DisableAntiSpyware" wide  // source: Disabling Windows Defender (disassembly)
        $s4 = "NtSetInformationProcess" ascii  // source: Setting its own process as critical (decompilation)
        $s5 = "%4d.%2d.%2d-%2d:%2d:%2d" ascii  // source: Restarting on exceptions (decompilation)
        $s6 = "WinSta0\\\\Default" ascii wide  // source: The DownloadAndExecute function calls DownloadPeFile, then launches the downloaded module (decompilation)
        $s7 = "ApateDNS" ascii wide  // source: Window name checks (decompilation)
        $s8 = "TaskExplorer" ascii wide  // source: Window name checks (decompilation)
        $s9 = "CurrPorts" ascii wide  // source: Window name checks (decompilation)
        $s10 = "Malwarebytes" ascii wide  // source: Window name checks (decompilation)
        $s11 = "Wireshark" ascii wide  // source: Window name checks (decompilation)
        $s12 = "MSIE 6.0" ascii wide  // source: The DownloadPeFile function is responsible for downloading a PE file (decompilation)
        $s13 = "任务管理器" wide  // source: Window name checks (decompilation)
        $s14 = "资源监视器" wide  // source: Window name checks (decompilation)
        $s15 = "网络分析" wide  // source: Window name checks (decompilation)

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        4 of ($s*)
}
