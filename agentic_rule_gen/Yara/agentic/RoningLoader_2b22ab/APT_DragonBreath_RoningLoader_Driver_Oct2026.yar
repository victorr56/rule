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
rule APT_DragonBreath_RoningLoader_Driver_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/roningloader"
        date = "2026-10-17"
        description = "Detects the RoningLoader driver component (ollama.sys), which is used to terminate EDR processes. The rule matches on a unique PDB path or a combination of the driver's device name and signer certificate subject."
        hash1 = "2515b546125d20013237aeadec5873e6438ada611347035358059a77a32c54f5"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, a1, a2"

    strings:
        // Strong anchor
        $x1 = "D:\\VS_Project\\加解密\\MyDriver1\\x64\\Release\\MyDriver1.pdb" ascii  // source: prose, artifact.kind: pdb_path

        // Medium-strength unique strings
        $a1 = "\\\\.\\Ollama" wide  // source: explicit_literal, artifact.kind: unique_string
        $a2 = "Kunming Wuqi E-commerce Co., Ltd." wide  // source: prose, artifact.kind: certificate_subject

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        (
            $x1 or
            ($a1 and $a2)
        )
}
