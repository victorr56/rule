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
rule MAL_SCKit_Scripts_Nov2026
{
    meta:
        description = "Detects SCKit scripts used for persistence, deployment, and targeting IT support technicians. The rule requires a combination of at least three supporting strings to trigger."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        date = "2026-11-20"
        hash1 = "d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a"
        hash2 = "4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b"
        hash3 = "cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956"
        hash4 = "81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781"
        hash5 = "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1, s7, s8"

    strings:
        // Supporting strings. None are strong enough to fire alone.
        // A generic string "network.mojom.NetworkService" was removed.
        $s1 = "RelayTrapLiteAlert" ascii wide  // source: prose
        $s2 = "c=Exploited" ascii wide  // source: explicit_literal
        $s3 = "/EadF.php" ascii wide  // source: explicit_literal
        $s4 = "TrapWatch" ascii wide  // source: explicit_literal
        $s5 = ".ASPXAUTH" ascii wide  // source: figure_or_disassembly
        $s6 = "-NoReArm" ascii wide  // source: figure_or_disassembly
        $s7 = "-Mode full" ascii wide  // source: prose
        $s8 = "lab-context.json" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 500KB and
        3 of ($s*)
}
