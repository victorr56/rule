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
rule MAL_CikaBika_Deployer_Script_Oct2026
{
    meta:
        description = "Detects a PowerShell script used in CikaBika attacks. The script contains logic for a UAC bypass, DLL deployment, and embedded C# code to hide windows. The rule requires 3 of 5 supporting strings to match."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/hiding-in-plain-sight-uncovering-a-multi-stage-ransomware-attack-through-behavioral-detection"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1"
    strings:
        // UAC Bypass and DLL placement artifacts
        $s1 = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" ascii wide // source: prose
        $s2 = "C:\\Windows\\Temp\\dbghelp.tmp" ascii wide // source: figure_or_disassembly, Figure 3: Silent DLL deployer.
        $s3 = "Copy-Item $SourceDll $TempPath -Force" ascii wide // source: figure_or_disassembly, Figure 3: Silent DLL deployer.
        $s4 = "$TargetDir\\dbghelp.dll" ascii wide // source: figure_or_disassembly, Figure 3: Silent DLL deployer.
        // C# code embedded in the script to hide windows
        $s5 = "public class WindowHider" ascii wide // source: figure_or_disassembly, Figure 3: Silent DLL deployer.
    condition:
        filesize < 100KB and
        3 of ($s*)
}
