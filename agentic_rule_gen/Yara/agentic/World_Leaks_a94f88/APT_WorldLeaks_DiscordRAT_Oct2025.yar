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
rule APT_WorldLeaks_DiscordRAT_Oct2025
{
    meta:
        description = "Detects a Discord-based RAT used by World Leaks. This rule matches on a unique Discord token or ID, a specific command list, or a combination of at least three other supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.darktrace.com/blog/when-reality-diverges-from-the-playbook-darktrace-identifies-encryption-in-a-world-leaks-ransomware-attack"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Unique strings, strong enough to fire alone
        $x1 = "MTQzMjcyMjA4Mzk5NzAyODUxMg.GJpNS2.CE19P" ascii  // source: report Fig.5 disassembly
        $x2 = "Available commands: !shell, !src, !info, !download, !upload, !sysinfo, !stream, !camera, !broadcast, !isOn" ascii  // source: report Fig.8 terminal_or_log
        $x3 = "1440633973104705547" ascii  // source: report Fig.5 disassembly

        // Supporting strings
        $s1 = "Device is ready for manual commands" ascii  // source: report Fig.8 terminal_or_log
        $s2 = "https://discord.com/api/v10/channels/" ascii  // source: report Fig.5 disassembly
        $s3 = "!broadcast" ascii wide  // source: report Fig.8 terminal_or_log
        $s4 = "!sysinfo" ascii wide  // source: report Fig.8 terminal_or_log
        $s5 = "!download" ascii wide  // source: report Fig.8 terminal_or_log
        $s6 = "!upload" ascii wide  // source: report Fig.8 terminal_or_log
        $s7 = "!stream" ascii wide  // source: report Fig.8 terminal_or_log
        $s8 = "!camera" ascii wide  // source: report Fig.8 terminal_or_log
        $s9 = "!shell" ascii wide  // source: report Fig.8 terminal_or_log

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
