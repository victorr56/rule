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
rule APT_Webworm_GraphWorm_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.welivesecurity.com/en/eset-research/webworm-new-burrowing-techniques/"
        date = "2026-10-16"
        description = "Detects GraphWorm backdoor (Webworm toolset), which uses Microsoft Graph API for C&C. A match requires 4 unique strings related to filenames and commands. Most strings are from prose and are unverified."
        malware_family = "GraphWorm"
        threat_actor = "Webworm"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "$s1, $s2, $s3, $s4, $s5, $s6"

    strings:
        $s1 = "beacon_shell_output.txt" ascii wide  // source: prose
        $s2 = "config.dat" ascii wide  // source: prose
        $s3 = "alive.txt" ascii wide  // source: prose
        $s4 = "keyExchange" ascii wide  // source: prose
        $s5 = "/createUploadSession" ascii wide  // source: prose
        $s6 = "heartbeat" ascii wide  // source: prose
        $s7 = "vpnbridge_x64.exe" ascii wide  // source: figure_or_disassembly
        $s8 = "setting.conf" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and 4 of them
}
