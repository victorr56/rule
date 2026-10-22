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
rule MAL_Bughatch_Downloader_Cuba_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects the BUGHATCH downloader, used by the Cuba ransomware group, based on a unique PDB path."
        reference = "https://www.elastic.co/security-labs/threat-command/cuba-ransomware-campaign-analysis"
        threat_actor = "Cuba Ransomware"
        malware_family = "Bughatch"
        hash1 = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"
        hash2 = "17edf458f7b8baae5ddef725e255d3a7bb6c960830503556f157655308895128"
        hash3 = "2e6fffad384cd6ce93cc1cde97911063e640c1953dac0507cd5f5b4b3d21bb69"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1"
    strings:
        $x1 = "F:\\\\Source\\\\Mosquito\\\\Agent\\\\x64\\\\Release\\\\Agent.pdb" ascii  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        1 of ($x*)
}
