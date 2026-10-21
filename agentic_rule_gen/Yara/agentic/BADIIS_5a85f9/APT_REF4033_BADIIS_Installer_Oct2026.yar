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
rule APT_REF4033_BADIIS_Installer_Oct2026 {
    meta:
        description = "Detects the BADIIS service installer (CbsMsgApi.exe) based on a unique PDB path."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/badiis-to-the-bone-new-insights-to-global-seo-poisoning-campaign"
        date = "2026-10-17"
        hash1 = "055bdcaa0b69a1e205c931547ef863531e9fdfdaac93aaea29fb701c7b468294"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1"
    strings:
        $x1 = "C:\\Users\\Administrator\\Desktop\\\xe6\x9b\xbf\xe6\x8d\xa2\xe9\x85\x8d\xe7\xbd\xae\xe6\x96\x87\xe4\xbb\xb6\\w3wpservice-svchost\\x64\\Release\\CbsMsgApi.pdb" ascii // source: explicit_literal
    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and $x1
}
