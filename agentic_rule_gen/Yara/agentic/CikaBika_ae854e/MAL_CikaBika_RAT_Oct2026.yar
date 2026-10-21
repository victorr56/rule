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
rule MAL_CikaBika_RAT_Oct2024
{
    meta:
        description = "Detects the CikaBika Rust RAT. Matches on one of several strong anchor strings, or a combination of two medium-strength anchors and a supporting string, or four supporting strings. These strings are related to its Discord C2 functionality."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/hiding-in-plain-sight-uncovering-a-multi-stage-ransomware-attack-through-behavioral-detection"
        date = "2024-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Strong anchors ($x*) - unique, >=16-byte text, or >=8-byte hex
        $x1 = "Available commands: !shell, !src, !info, !download, !upload, !sysinfo, !stream, !camera, !broadcast, !isOn" ascii // source: figure_or_disassembly, Figure 8: Commands available in Discord.
        $x2 = "MTQzMjcyMjA4Mzk5NzAyODUxMg.GJpNS2.CE19P" ascii // source: figure_or_disassembly, Figure 5: Discord configuration within the RAT.
        $x3 = { d8 ac d9 87 d8 a7 d8 b2 20 d8 ac d8 af d9 8a d8 af 20 d8 aa d9 85 20 d8 aa d8 b3 d8 ac d9 8a d9 84 d9 87 20 d8 a8 d9 86 d8 ac d8 a7 d8 ad } // "جهاز جديد تم تسجيله بنجاح" // source: figure_or_disassembly
        $x4 = "1440633973104705547" ascii // source: figure_or_disassembly, Figure 5: Discord configuration within the RAT.

        // Medium-strength anchors ($a*) - plausible but not unique enough to fire alone
        $a1 = "Device is ready for manual commands" ascii // source: figure_or_disassembly, Figure 8: Commands available in Discord.
        $a2 = "https://discord.com/api/v10/channels/" ascii // source: figure_or_disassembly, Figure 5: Discord configuration within the RAT.
        $a3 = "Device Management System" ascii // source: figure_or_disassembly
        $a4 = "https://cdn.discordapp.com/attachments/148648516" ascii // source: figure_or_disassembly

        // Supporting strings ($s*)
        $s1 = "!download" ascii // source: figure_or_disassembly, Figure 8: Commands available in Discord.
        $s2 = "!sysinfo" ascii // source: figure_or_disassembly, Figure 8: Commands available in Discord.
        $s3 = "!broadcast" ascii // source: figure_or_disassembly, Figure 8: Commands available in Discord.
        $s4 = "network_info.txt" ascii // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and (
            1 of ($x*) or
            (2 of ($a*) and 1 of ($s*)) or
            4 of ($s*)
        )
}
