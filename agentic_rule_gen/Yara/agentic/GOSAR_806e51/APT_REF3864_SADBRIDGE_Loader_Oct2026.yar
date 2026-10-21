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
rule APT_REF3864_SADBRIDGE_Loader_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-17"
        description = "Detects the SADBRIDGE loader, part of the REF3864 infection chain. The rule triggers on a unique COM elevation moniker string, or a combination of a magic seed constant and other strings related to its UAC bypass and persistence mechanisms. This rule is designed to detect the x64bridge.dll component."
        reference = "https://www.elastic.co/security-labs/threat-command/under-the-sadbridge-with-gosar"
        hash1 = "accd651f58dd3f7eaaa06df051e4c09d2edac67bb046a2dcb262aa6db4291de7"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$c1, $s2, $s3, $s4, $s5"
    strings:
        $x1 = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide // source: figure_or_disassembly

        $c1 = { A7 C6 67 4E } // source: explicit_literal, magic seed 0x4E67C6A7, little-endian

        $s1 = "S-1-16-12288" ascii wide // source: figure_or_disassembly
        $s2 = "DevQuery Background Discovery Broker Service" ascii wide // source: prose
        $s3 = "DevQueryBroker.exe" ascii wide // source: prose
        $s4 = "HealthServiceRuntime.dll" ascii wide // source: prose
        $s5 = "BridgeInit" ascii wide // source: prose

    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and (
            $x1 or
            ($c1 and 2 of ($s*))
        )
}
