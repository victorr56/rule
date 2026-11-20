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
rule APT_AuditTeam_OpsAgent_Core_Nov2026
{
    meta:
        description = "This rule detects the core C++/Rust component of OpsAgent, used by AuditTeam. It can match on a single strong anchor (unique keys, salts, named pipe) or a combination of several supporting strings (commands, config markers)."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/auditteam-opsagent-forced-audit/122031/"
        date = "2026-11-20"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "$x1, $x2, $x3, $x4, $s1, $s7, $s8"

    strings:
        // Strong anchors, can fire alone
        $x1 = "c2-framework-psk-salt-v1" ascii  // source: explicit_literal
        $x2 = "f4bb8c7e15d8b98d535eb20b09176b3d" ascii  // source: explicit_literal
        $x3 = "604902af7b70b271" ascii  // source: explicit_literal
        $x4 = "\\\\KvCorePortX0" ascii wide  // source: explicit_literal

        // Supporting strings
        $s1 = "c2-encryption-key\\x01" ascii  // source: explicit_literal
        $s2 = "mimikatz_spawn" ascii  // source: figure_or_disassembly
        $s3 = "execute_assembly" ascii  // source: figure_or_disassembly
        $s4 = "pth_spawn" ascii  // source: figure_or_disassembly
        $s5 = "worker_restart" ascii  // source: figure_or_disassembly
        $s6 = "pivot_auto" ascii  // source: figure_or_disassembly
        $s7 = "GetConfig" ascii  // source: explicit_literal
        $s8 = "EndConfig" ascii  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
