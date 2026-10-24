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
rule SUSP_Jenkins_Exfil_Tool_Oct2026
{
    meta:
        description = "Detects potential attacker tools targeting Jenkins for unauthorized access and execution. It triggers on highly specific URI paths related to creating administrative users or accessing specific credentials."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/gitlab-jenkins-forensics/"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "/securityRealm/createAccountByAdmin" ascii  // source: figure_or_disassembly
        $x2 = "/credentials/store/system/domain/_/credential/jenkins-repo-check-user" ascii  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            1 of ($x*)
        )
}
