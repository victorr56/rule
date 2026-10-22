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
rule MAL_IncRansomware_Gen_Oct2026
{
    meta:
        description = "Detects INC Ransomware for Windows and Linux. The rule can be triggered by a highly unique string or a combination of three supporting indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://socradar.io/blog/inc-gentlemen-ransomware-ai-infrastructure/"
        date = "2026-10-22"
        hash1 = "ffca6aa96572743200f9f0040a3e435766f6d7c15d6a4c72045a0cbb4db72eb4"
        hash2 = "0ae4447d755593ee1931170d4187a07a29bf0690179acc39b7400a4c65cd07c5"
        hash3 = "70f28e18e7f4083cd542e6bff6b2682f3876c5ef4bcf4323aa22a6d03d4a8a82"
        hash4 = "7ad718a530a2913f775e62c656060af79ffde5c1f2c04138bcc068142f162a20"
        hash5 = "ec4ba1d570601eaa1474ab7cfffafcff218a717e44e8d2d22ed0573676b0463e"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x2, s1, s2, c1"

    strings:
        // $x* strings are strong anchors (>= 16 bytes)
        $x1 = "tomorrow at 6 Moscow time, right?" ascii wide // source: figure_or_disassembly
        $x2 = "README_PARTNER.md" ascii wide // source: explicit_literal

        // $s* strings from prose, require combination
        $s1 = "INC-README.txt" ascii wide // source: prose
        $s2 = ".INC" ascii wide // source: prose

        // $c* constant from prose, requires combination
        $c1 = { 28 C0 53 00 } // source: prose, IOCTL 0x0053C028

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and filesize < 20MB and
        (
            1 of ($x*) or
            ($c1 and 2 of ($s*))
        )
}
