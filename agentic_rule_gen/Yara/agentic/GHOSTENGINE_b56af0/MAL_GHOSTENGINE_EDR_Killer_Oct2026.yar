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
rule MAL_GHOSTENGINE_EDR_Killer_Oct2026
{
    meta:
        description = "Detects GHOSTENGINE's EDR termination component, which uses specific IOCTLs to exploit vulnerable drivers and clears specific event logs. A match requires one of two IOCTLs and both of two event log names."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/invisible-miners-unveiling-ghostengine"
        date = "2026-10-18"
        hash1 = "2fe78941d74d35f721556697491a438bf3573094d7ac091b42e4f59ecbd25753"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "c1, c2, s1, s2"

    strings:
        $c1 = { 04 C0 99 72 }  // source: report explicit_literal, IOCTL 0x7299C004 for aswArPots.sys
        $c2 = { 24 21 22 00 }  // source: report explicit_literal, IOCTL 0x222124 for iobitunlockers.sys

        $s1 = "Microsoft-Windows-AppModel-Runtime/Operational" ascii wide  // source: report explicit_literal, Event log channel to clear
        $s2 = "Microsoft-Windows-Winlogon/Operational" ascii wide  // source: report explicit_literal, Event log channel to clear

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        1 of ($c*) and 2 of ($s*)
}
