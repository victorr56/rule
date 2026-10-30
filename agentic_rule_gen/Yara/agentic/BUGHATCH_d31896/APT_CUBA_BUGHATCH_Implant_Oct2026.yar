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
rule APT_CUBA_BUGHATCH_Implant_Oct2026
{
    meta:
        description = "This rule detects the BUGHATCH implant used by the CUBA ransomware group. It looks for a unique code sequence from the XOR key generation logic, or a combination of strings such as internal function names, temporary file name formats, and execution arguments. A match is triggered by the unique code sequence, or four of the supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/bughatch-malware-analysis"
        date = "2026-10-30"
        hash1 = "F1325F8A55164E904A4B183186F44F815693A008A9445D2606215A232658C3CF"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s15, s16"

    strings:
        $x1 = { 69 4D 10 FD 43 03 00 81 C1 C3 9E 26 00 89 4D 10 8B 55 FC 8B 45 F8 0F B7 0C 50 8B 55 10 C1 EA 10 81 E2 FF FF 00 00 33 CA 8B 45 FC 8B 55 F8 66 89 0C 42 }  // source: strings_listing

        $s1 = "ReflectivelyExecutePERemote" ascii wide  // source: figure_or_disassembly
        $s2 = "ReflectivelyLoadDllRemote" ascii wide  // source: figure_or_disassembly
        $s3 = "SelfDeleteExitProcess" ascii wide  // source: figure_or_disassembly
        $s4 = "DropPEDiskExecute" ascii wide  // source: figure_or_disassembly
        $s5 = "RemoteShellcodeExecute" ascii wide  // source: figure_or_disassembly
        $s6 = "SelfShellcodeExecute" ascii wide  // source: figure_or_disassembly
        $s7 = "TEMP%u.PS1" ascii wide  // source: strings_listing
        $s8 = "TEMP%u.CMD" ascii wide  // source: strings_listing
        $s9 = "\\TEMP%d.%s" ascii wide  // source: strings_listing
        $s10 = "ExecutePowershell" ascii wide  // source: figure_or_disassembly
        $s11 = "ExecuteCmd" ascii wide  // source: figure_or_disassembly
        $s12 = "MigrateC2" ascii wide  // source: figure_or_disassembly
        $s13 = "-windowstyle hidden -executionpolicy bypass -file" ascii wide  // source: strings_listing
        $s14 = "\\Sysnative\\" ascii wide  // source: strings_listing
        $s15 = "/Agent32.bin" ascii wide  // source: prose
        $s16 = "/Agent64.bin" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        (
            $x1 or
            4 of ($s*)
        )
}
