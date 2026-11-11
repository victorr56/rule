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
rule MAL_Sn00py_Ransomware_Nov2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-11-11"
        description = "Detects Sn00py ransomware used by the Citrus group. The rule matches on unique console output messages, embedded public key fragments, or a combination of supporting strings. A match can be triggered by one of the unique strings or three of the supporting strings."
        reference = "https://securelist.com/citrus-ransomware/121879/"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        malware_family = "Sn00py"
        threat_actor = "Citrus"
        unverified_strings = "s3"

    strings:
        // Unique strings, long enough to be strong anchors
        $x1 = "We`re going to do something special today :). Made with RaaS platform Sn00py." ascii wide  // source: figure_or_disassembly
        $x2 = "A7+eV3M+EDIh5kId+vf46QkKpAOKxUxv97PDFj66ox+uE0GV9UQhrSmBAoGAcyNI" ascii  // source: figure_or_disassembly
        $x3 = "JLkZX7pxLLSd9iQdxMxDrLYZGRtiht8ToD5OGZri36oPvnW56ijJZ/NMzlFtVr7V" ascii  // source: figure_or_disassembly
        $x4 = "iSZJr5Qkz2cxShcSuhDLLXmzleclBd7HQtWTuZUCgYEAqN8WFAZxkV2e1p4v3U98" ascii  // source: figure_or_disassembly

        // Supporting strings
        $s1 = "bcedit" ascii wide  // source: figure_or_disassembly
        $s2 = "host_blacklist" ascii wide  // source: figure_or_disassembly
        $s3 = "CITRUS_README.txt" wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
