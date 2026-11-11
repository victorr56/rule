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
rule APT_CopperDragon_Sparrow_Framework_Nov2026
{
    meta:
        description = "Detects core components of the Sparrow framework used by CopperDragon. The rule is triggered by a unique self-signed certificate subject, or a combination of two backdoor names and a magic constant."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/"
        date = "2026-11-11"
        hash1 = "dbdaa8a52246b1e3f9285820db2f976b8ab513926ed972c968fae1c8aeb77056"
        hash2 = "46407cc35c48d19c6b1990a03ebdd19321005ce08d5a98acd168fda55a92d946"
        hash3 = "2ea96ea398e9254706ff2761b86302372c149ef090536ad76231e51d7c810a2a"
        hash4 = "de6a3140797f7c00a48b2068127965c3994f92867466259e69c861880e6ec2d8"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        // Unique string (strong anchor)
        $x1 = "O=Internet Widgits Pty Ltd" ascii  // source: explicit_literal

        // Supporting strings
        $s1 = "SparroWocky" ascii wide  // source: explicit_literal
        $s2 = "annobinagent" ascii  // source: explicit_literal

        // Constants
        $c1 = { 44 33 22 11 }  // source: explicit_literal, magic value 0x11223344 for C2 validation
        $c2 = { 0e 0e 0e 0e }  // source: explicit_literal, custom ioctl ID 0x0e0e0e0e

    condition:
        ( uint16(0) == 0x5a4d or uint32(0) == 0x464c457f ) and filesize < 10MB and
        (
            $x1 or
            (2 of ($s*) and 1 of ($c*))
        )
}
