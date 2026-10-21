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
rule APT_Webworm_EchoCreep_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.welivesecurity.com/en/eset-research/webworm-new-burrowing-techniques/"
        date = "2026-10-16"
        description = "Detects EchoCreep backdoor (Webworm toolset), which uses Discord for C&C, based on command strings and other unique artifacts. A match requires one strong anchor or a combination of several weaker strings."
        malware_family = "EchoCreep"
        threat_actor = "Webworm"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Strong anchors (can fire alone)
        $x1 = "download https://github.com/fatedier/frp/releases/download/v0.56.0/frp_0.56.0_darwin_amd64.tar.gz C:\\windows\\temp\\123.tar.gz" ascii wide  // source: report Fig.9 frp download
        $x2 = "run C:\\\\tools\\\\se\\\\win64\\\\test.vbs" ascii wide  // source: report Fig.10 Test VBScript
        $x3 = "1220298277849796651" ascii wide  // source: report Fig.8 Junk commands
        $x4 = "1220292840803012639" ascii wide  // source: report Fig.8 Junk commands
        $x5 = "1219910976007045171" ascii wide  // source: report Fig.8 Junk commands

        // Medium-strength anchors
        $a1 = "jonson889912" ascii wide  // source: report Fig.8 Junk commands

        // Supporting strings
        $s1 = "Download Success!" ascii wide  // source: report Fig.9 frp download
        $s2 = "Run Success!" ascii wide  // source: report Fig.10 Test VBScript
        $s3 = "Up Success" ascii wide  // source: report Fig.5 EchoCreep Discord Up Success message
        $s4 = "channel_id" ascii wide  // source: report Fig.8 Junk commands
        $s5 = "author_id" ascii wide  // source: report Fig.8 Junk commands
        $s6 = "auhtor" ascii wide  // source: report Fig.5 EchoCreep Discord Up Success message

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and (
            1 of ($x*)
            or ($a1 and 2 of ($s*))
            or 4 of ($s*)
        )
}
