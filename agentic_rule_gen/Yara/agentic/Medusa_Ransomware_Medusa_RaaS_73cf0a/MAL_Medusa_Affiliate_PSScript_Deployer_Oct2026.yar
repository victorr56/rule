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
rule MAL_Medusa_Affiliate_PSScript_Deployer_Oct2026
{
    meta:
        description = "Detects a PowerShell deployer script used by Medusa ransomware affiliates to perform DLL sideloading of a malicious dbghelp.dll. Detection is based on the presence of at least three characteristic strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/under-medusas-gaze-how-darktrace-uncovers-rmm-abuse-in-ransomware-campaigns"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $s1 = "private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);" ascii  // source: figure_literals (Figure 3)
        $s2 = "private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);" ascii  // source: figure_literals (Figure 3)
        $s3 = "private static extern IntPtr GetForegroundWindow();" ascii  // source: figure_literals (Figure 3)
        $s4 = "public class WindowHider" ascii  // source: figure_literals (Figure 3)
        $s5 = "Copy-Item $SourceDll $TempPath -Force" ascii  // source: figure_literals (Figure 3)
        $s6 = "$TargetDir\\\\dbghelp.dll" ascii  // source: figure_literals (Figure 3)
        $s7 = "C:\\\\Windows\\\\Temp\\\\dbghelp.tmp" ascii  // source: figure_literals (Figure 3)
        $s8 = "$BypassScript = @'" ascii  // source: figure_literals (Figure 3)
        $s9 = "Add-Type @\\\"" ascii  // source: figure_literals (Figure 3)

    condition:
        filesize < 20KB and
        3 of ($s*)
}
