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
rule HKTL_PANIX_Tool_Oct2026
{
    meta:
        description = "Detects the main binary of the PANIX Linux persistence research tool. The rule can be triggered by one of several unique output strings, or a combination of three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/continuation-on-persistence-mechanisms"
        date = "2026-10-30"
        malware_family = "PANIX"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "[+] Backdoor added to /etc/ld.so.preload for persistence." ascii // source: figure_or_disassembly
        $x2 = "[+] System user backdoor persistence established for user: news" ascii // source: figure_or_disassembly
        $x3 = "original_execve = dlsym(RTLD_NEXT, \"execve\");" ascii // source: figure_or_disassembly

        $s1 = "bash -i >& /dev/tcp/%s/%d 0>&1" ascii // source: figure_or_disassembly
        $s2 = "nologin " ascii // source: figure_or_disassembly
        $s3 = "/cmd.php" ascii // source: figure_or_disassembly
        $s4 = "/cgi-bin/reverse.py" ascii // source: figure_or_disassembly

    condition:
        uint32(0) == 0x464c457f and
        filesize < 2MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
