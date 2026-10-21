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
rule APT_FINALDRAFT_Core_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/finaldraft"
        date = "2026-10-17"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        description = "Detects core components and modules of the FINALDRAFT toolkit. The rule will fire on the unique named pipe, or a combination of three other distinctive strings."
        hash1 = "39e85de1b1121dc38a33eca97c41dbd9210124162c6d669d28480c833e059530"
        hash2 = "83406905710e52f6af35b4b3c27549a12c28a628c492429d3a411fdb2d28cc8c"
        unverified_strings = "x1, s1, s2, s3, s4, s5"

    strings:
        // $x1 is a strong anchor and can fire the rule alone
        $x1 = "\\\\.\\Pipe\\E340C955-15B6-4ec9-9522-1F526E6FBBF1" ascii wide  // source: explicit_literal

        // Supporting strings, require 3 to trigger a match
        $s1 = "GoogleProxy" ascii  // source: explicit_literal
        $s2 = "Aslire597" ascii wide  // source: explicit_literal
        $s3 = "Session.x64.dll" ascii wide  // source: explicit_literal
        $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UUID\\" ascii wide  // source: explicit_literal
        $s5 = "UpdateTask" ascii  // source: explicit_literal

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        filesize < 5MB and
        (
            $x1 or
            3 of ($s*)
        )
}
