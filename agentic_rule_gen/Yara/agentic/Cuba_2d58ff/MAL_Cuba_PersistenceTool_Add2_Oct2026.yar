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
rule MAL_Cuba_PersistenceTool_Add2_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects a persistence tool used by the Cuba ransomware group, which creates a hidden user account. The rule can match on a unique hardcoded password or a combination of the username and a registry key used to hide the account."
        reference = "https://www.elastic.co/security-labs/threat-command/cuba-ransomware-campaign-analysis"
        threat_actor = "Cuba Ransomware"
        malware_family = "Cuba"
        hash1 = "728994be6b928de3d1c7b49ca1c79db8656c1cf4b95a1e508a6be48c6ab407da"
        hash2 = "c24d7a93d6a5c33e673e6b0fd171701c4646e67cf2328f41739ef9b50302a02e"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
    strings:
        $x1 = "KJaoifhLOaiwdhadx1@!" ascii wide  // source: figure_or_disassembly

        $s1 = "Mysql" ascii wide  // source: figure_or_disassembly
        $s2 = "SpecialAccounts\\\\UserList" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        (
            $x1 or ($s1 and $s2)
        )
}
