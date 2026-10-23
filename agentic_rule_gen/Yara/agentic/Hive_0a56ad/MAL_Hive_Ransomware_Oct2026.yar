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
rule MAL_Hive_Ransomware_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-23"
        description = "Detects Hive ransomware for Windows, Linux and ESXi. Match on unique hex patterns or strings from service/process kill lists, or a combination of other supporting strings."
        reference = "https://www.group-ib.com/blog/hive/"
        hash1 = "1e21c8e27a97de1796ca47a9613477cf7aec335a783469c5ca3a09d4f07db0ff"
        hash2 = "25bfec0c3c81ab55cf85a57367c14cc6803a03e2e9b4afd72e7bbca9420fe7c5"
        hash3 = "6983ef6e484c0c70356d6f868ac03bc90a1055560642706743511f76aa6f28ad"
        hash4 = "0e8e6fc94e6eb17cfd8993b3dcfd9acd11ee32f1b4e956df3097ae3259be4f9c"
        hash5 = "822d89e7917d41a90f5f65bee75cad31fe13995e43f47ea9ea536862884efc25"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s4, s5, s6"

    strings:
        // Strong anchors (>=16 bytes text or >=8 bytes hex)
        $x1 = { B? 03 52 DA 8D [6-12] 69 ?? 00 70 0E 00 [14-20] 8D ?? 00 90 01 00 } // source: strings_listing
        $x2 = { 48 69 ?? B5 B4 1B 01 48 C1 E? 20 69 ?? 00 70 0E 00 29 ?? } // source: strings_listing
        $x3 = "Enterprise Client Service|EPSecurityService|EPUpdateService|EraserSvc11710" ascii // source: figure_or_disassembly
        $x4 = "firefoxconfig|infopath|mbamtray|msaccess|mspub|mydesktop|Ntrtscan" ascii // source: figure_or_disassembly

        // Medium-strength unique string
        $a1 = "Stopping VMs" ascii // source: strings_listing

        // Supporting strings
        $s1 = "HOW_TO_DECRYPT.txt" ascii wide // source: prose
        $s2 = "windows.exe" ascii // source: figure_or_disassembly
        $s3 = "esxi" ascii // source: figure_or_disassembly
        $s4 = "-no-wipe" ascii wide // source: prose
        $s5 = "-no-stop" ascii wide // source: prose
        $s6 = "-low-cpu" ascii wide // source: prose
        $s7 = "YooIT|zhudongfangyu|Zoolz" ascii // source: figure_or_disassembly
        $s8 = "tbirdconfig|thebat|thunderbird|tmlisten|visio|word|xfssvccon|zoolz" ascii // source: figure_or_disassembly

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and filesize < 20MB and
        (
            1 of ($x*) or
            ($a1 and 2 of ($s*)) or
            4 of ($s*)
        )
}
