import "pe"

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

rule MAL_CNB_Bot_Oct2026
{
    meta:
        description = "Detects CNB Bot, a RAT used by REF1695. The rule targets a unique C2 panel URL path or a combination of supporting strings, including the C2 domain, a unique POST request parameter, and associated filenames."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/fake-installers-to-monero"
        date = "2026-10-17"
        hash1 = "460203070b5a928390b126fcd52c15ed3a668b77536faa6f0a0282cf1c157162"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, s1, s2, s3, s4"
        malware_family = "CNB Bot"

    strings:
        $x1 = "CNB/l0g1n234.php" ascii wide  // source: prose

        $s1 = "win64autoupdates.top" ascii wide  // source: prose
        $s2 = "payload: \\\"fetch\\\"" ascii wide  // source: prose
        $s3 = "MLPCInstallHelper.exe" ascii wide  // source: prose
        $s4 = "sysdata.vbs" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            $x1 or
            3 of ($s*)
        )
}
