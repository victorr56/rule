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
rule MAL_DCRAT_SpybotList_Oct2026 {
    meta:
        description = "Detects a DCRAT variant that embeds a hosts file blocklist from Spybot Anti-Beacon by matching on three or more strings from this list."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/fake-gta6-download-malware-analysis"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
    strings:
        // All strings are from a blocklist created by Spybot Anti-Beacon and embedded in a DCRAT variant
        $s1 = "# Start of entries inserted by Spybot Anti-Beacon for Windows 10" ascii // source: figure_or_disassembly
        $s2 = "0.0.0.0 telemetry.battle.net" ascii // source: report Fig.3: Entries added to the hosts file
        $s3 = "0.0.0.0 insights-collector.gog.com" ascii // source: report Fig.3: Entries added to the hosts file
        $s4 = "0.0.0.0 telemetry.malwarebytes.com" ascii // source: report Fig.3: Entries added to the hosts file
        $s5 = "0.0.0.0 carcharodon.trendmicro.com" ascii // source: report Fig.3: Entries added to the hosts file
        $s6 = "0.0.0.0 analytics.ccs.mcafee.com" ascii // source: report Fig.3: Entries added to the hosts file
        $s7 = "0.0.0.0 incoming.telemetry.mozilla.org" ascii // source: report Fig.3: Entries added to the hosts file
    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        3 of ($s*)
}
