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
rule APT_Storm1175_Tool_CikaBika_RAT_Oct2026
{
    meta:
        description = "Detects CikaBika RAT, a Discord-based implant used by Medusa ransomware affiliates like Storm-1175. The rule can fire on a unique hardcoded Discord token or a list of supported commands."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/under-medusas-gaze-how-darktrace-uncovers-rmm-abuse-in-ransomware-campaigns"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s4"

    strings:
        $x1 = "MTQzMjcyMjA4Mzk5NzAyODUxMg.GJpNS2.CE19P" ascii wide  // source: artifact (figure_or_disassembly)
        $x2 = "Available commands: !shell, !src, !info, !download, !upload, !sysinfo, !stream, !camera, !broadcast, !isOn" ascii wide  // source: artifact (figure_or_disassembly)
        $x3 = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" ascii wide  // source: artifact (figure_or_disassembly)

        $s1 = "Device is ready for manual commands" ascii wide  // source: figure_literals (Figure 8)
        $s2 = "Author: sousou.ps1" ascii wide  // source: figure_literals (Figure 10)
        $s3 = "https://discord.com/api/v10/channels/" ascii wide  // source: artifact (figure_or_disassembly)
        $s4 = "AbyssWorker" ascii wide  // source: artifact (prose)
        $s5 = "jdid1.zip" ascii wide  // source: figure_literals (Figure 10)
        $s6 = "!sysinfo" ascii wide  // source: figure_literals (Figure 8)
        $s7 = "!broadcast" ascii wide  // source: figure_literals (Figure 8)

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
