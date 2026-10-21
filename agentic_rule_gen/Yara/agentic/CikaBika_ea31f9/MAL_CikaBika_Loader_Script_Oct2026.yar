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
rule MAL_CikaBika_Loader_Script_Oct2026 {
  meta:
    author = "ioc-yara-daily (agentic)"
    date = "2026-10-16"
    description = "Detects the PowerShell deployer script used by the CikaBika loader. The script combines a UAC bypass with DLL sideloading logic."
    reference = "https://www.darktrace.com/blog/when-ai-infrastructure-becomes-part-of-the-attack-surface"
    malware_family = "CikaBika"
    tlp = "WHITE"
    status = "untested"
    test_result = "not tested: the report gives no sample hash for this rule"
    score = 60
  strings:
    $bypass1 = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" ascii  // source: artifact.5
    $bypass2 = "$TargetDir\\dbghelp.dll" ascii  // source: Figure 3: Silent DLL deployer.
    $bypass3 = "C:\\Windows\\Temp\\dbghelp.tmp" ascii  // source: Figure 3: Silent DLL deployer.
    $hider1 = "public class WindowHider" ascii  // source: Figure 3: Silent DLL deployer.
    $hider2 = "private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);" ascii  // source: Figure 3: Silent DLL deployer.
    $hider3 = "private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);" ascii  // source: Figure 3: Silent DLL deployer.
  condition:
    filesize < 100KB and ( ( $bypass1 and 1 of ( $bypass2, $bypass3 ) ) or ( $hider1 and 1 of ( $hider2, $hider3 ) ) )
}
