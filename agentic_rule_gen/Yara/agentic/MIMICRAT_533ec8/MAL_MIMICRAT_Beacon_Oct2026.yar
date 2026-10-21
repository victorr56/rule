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
rule MAL_MIMICRAT_Beacon_Oct2026
{
    meta:
        description = "Detects the MIMICRAT RAT beacon based on a unique hardcoded RC4 key or a combination of C2 communication strings, configuration artifacts, and masqueraded user agent fragments."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/mimicrat-custom-rat-mimics-c2-frameworks"
        date = "2026-10-17"
        hash1 = "a508d0bb583dc6e5f97b6094f8f910b5b6f2b9d5528c04e4dee62c343fce6f4b"
        hash2 = "055336daf2ac9d5bbc329fd52bb539085d00e2302fa75a0c7e9d52f540b28beb"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $s1, $s3, $s4, $s5, $s6, $s7"

    strings:
        $x1 = "@z1@@9&Yv6GR6vp#SyeG&ZkY0X74%JXLJEv2Ci8&J80AlVRJk&6Cl$Hb)%a8dgqthEa6!jbn70i27d4bLcE33acSoSaSsq6KpRaA7xDypo(5" ascii wide // source: report explicit_literal, RC4 key

        $s1 = "abcdefghijklmnop" ascii wide // source: report explicit_literal, AES IV
        $s2 = "zbuild.exe" ascii wide // source: report figure_or_disassembly
        $s3 = "/intake/organizations/events?channel=app" ascii wide // source: report explicit_literal, C2 GET path
        $s4 = "/discover/pcversion/metrics?clientver=ds" ascii wide // source: report explicit_literal, C2 POST path
        $s5 = "Cortana 1.14.9.19041" ascii wide // source: report explicit_literal, partial User-Agent
        $s6 = "AFUAK" ascii wide // source: report explicit_literal, cookie name
        $s7 = "ARCHUID" ascii wide // source: report explicit_literal, cookie name

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        (
            $x1 or
            3 of ($s*)
        )
}
