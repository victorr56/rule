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
rule MAL_CikaBika_RAT_Oct2026
{
    meta:
        description = "Detects the CikaBika Rust RAT. A match is declared if one of several unique strings (e.g., Discord token, specific messages) is found, or on a combination of four less-specific supporting strings (e.g., commands, filenames)."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/unmasking-vo1d-inside-darktraces-botnet-detection"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "MTQzMjcyMjA4Mzk5NzAyODUxMg.GJpNS2.CE19P" ascii  // source: Figure 5: Discord configuration within the RAT.
        $x2 = "Available commands: !shell, !src, !info, !download, !upload, !sysinfo, !stream, !camera, !broadcast, !isOn" ascii  // source: Figure 8: Commands available in Discord.
        $x3 = "1440633973104705547" ascii  // source: Figure 5: Discord configuration within the RAT.
        $x4 = { F0 9F 96 A5 EF B8 8F 44 65 76 69 63 65 20 52 65 67 69 73 74 65 72 65 64 }  // source: artifact "🖥️Device Registered", figure_or_disassembly
        $x5 = { E2 9C 85 20 D8 AC D9 87 D8 A7 D8 B2 20 D8 AC D8 AF D9 8A D8 AF 20 D8 AA D9 85 20 D8 AA D8 B3 D8 AC D9 8A D9 84 D9 87 20 D8 A8 D9 86 D8 AC D8 A7 D8 AD }  // source: artifact "✅ جهاز جديد تم تسجيله بنجاح", figure_or_disassembly

        $s1 = "Device is ready for manual commands" ascii wide  // source: Figure 8: Commands available in Discord.
        $s2 = "Device Management System" ascii wide  // source: figure_or_disassembly
        $s3 = "https://discord.com/api/v10/channels/" ascii  // source: Figure 5: Discord configuration within the RAT.
        $s4 = "!sysinfo" ascii wide  // source: Figure 8: Commands available in Discord.
        $s5 = "!broadcast" ascii wide  // source: Figure 8: Commands available in Discord.
        $s6 = "!download" ascii wide  // source: Figure 8: Commands available in Discord.
        $s7 = "tasklist_startup.txt" ascii wide  // source: artifact, explicit_literal
        $s8 = "network_info.txt" ascii wide  // source: artifact, explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
