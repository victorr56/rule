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
rule APT_STAC3725_LPE_Tool_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/citrixbleed-2-dragonforce-ransomware"
        date = "2026-10-28"
        description = "Detects a Local Privilege Escalation (LPE) tool used by threat actor STAC3725. The rule may be triggered by a unique cleanup message string or a hardcoded GUID, or by a combination of three supporting strings."
        hash1 = "c84739655ce1af0a0269138263d47567418f69e0f75e249f8e23bc21802209e2"
        hash2 = "eb083365dc70d0294e8c4f55a2e78be0edb0f3497f2a06a70c9f474dafab48d8"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x2, s1, s3"

    strings:
        $x1 = "Restoring registry..." wide ascii  // source: figure_or_disassembly
        $x2 = "{28d78fad-5a12-11d1-ae5b-0000f803a8c2}" wide ascii  // source: prose

        $s1 = "loko123" wide ascii  // source: explicit_literal
        $s2 = "useeeer" wide ascii  // source: figure_or_disassembly
        $s3 = "\\Group Policy State\\Machine\\GPO-List\\test" wide ascii  // source: prose

    condition:
        uint16(0) == 0x5a4d
        and filesize < 2MB
        and (
            1 of ($x*) or
            3 of ($s*)
        )
}
