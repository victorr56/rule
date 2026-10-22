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
rule APT_Cuba_Ransomware_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects Cuba ransomware based on unique ransom note strings. The rule requires one of two unique ransom note strings to match."
        reference = "https://www.elastic.co/security-labs/threat-command/cuba-ransomware-campaign-analysis"
        threat_actor = "Cuba Ransomware"
        malware_family = "Cuba"
        hash1 = "33352a38454cfc247bc7465bf177f5f97d7fd0bd220103d4422c8ec45b4d3d0e"
        hash2 = "0f385cc69a93abeaf84994e7887cb173e889d309a515b55b2205805bdfe468a3"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
    strings:
        $x1 = "We also inform that your databases, ftp server and file server were downloaded by us to our servers." ascii wide  // source: strings_listing
        $x2 = "Good day. All your files are encrypted. For decryption contact us." ascii wide  // source: strings_listing


    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        (
            1 of ($x*)
        )
}
