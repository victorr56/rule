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
rule MAL_OfferLoader_Nov2026
{
    meta:
        description = "Detects OfferLoader malware components. The rule triggers on unique C2 parameters or filenames, or a combination of multiple supporting domains, filenames, and C2 parameters."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/"
        date = "2026-11-04"
        hash1 = "006510ce1da2b7410376f0788c19e55616eb4bcc30072d25b7d0871dc32aa11c"
        hash2 = "ab2c2dd37fdcfe1e7620a57f98c80bd063258bea145adc0cc6a0f8b1e24c6a8f"
        hash3 = "452a210bba4c8d08f7cb7733a816d7220a7fa570a469aea0a997cfc8b594b6a0"
        hash4 = "55cd3d36fdcc58016a64398357b2c9724a060da9f0d09266e537a61ec9552e4f"
        hash5 = "21306fc5716f95e252388f920314b42f1c8bcc7df67cb4d39da30217b96f4044"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $x2, $s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10"

    strings:
        // Unique C2 parameters and filenames that are strong anchors
        // prose -> eligible for $x if actor-specific
        $x1 = "r=offer_execution_fail" ascii wide // source: prose
        // prose -> eligible for $x if actor-specific
        $x2 = "Windows Manager – Postback Johan.msi" ascii wide // source: prose

        // Supporting C2 parameters, domains and filenames
        // prose -> short (<8 bytes) -> $s/$c only
        $s1 = "d=inno" ascii wide // source: prose
        // prose -> eligible for $x if actor-specific
        $s2 = "orbittrack.cfd" ascii wide // source: prose
        // prose -> eligible for $x if actor-specific
        $s3 = "prairielink.cfd" ascii wide // source: prose
        // prose -> eligible for $x if actor-specific
        $s4 = "willowbox.xyz" ascii wide // source: prose
        // prose -> eligible for $x if actor-specific
        $s5 = "sdk-agent.updater.exe" ascii wide // source: prose
        // prose -> eligible for $x if actor-specific
        $s6 = "watchdog.ps1" ascii wide // source: prose
        // prose -> eligible for $x if actor-specific
        $s7 = "AdvancedWindowsManager.exe" ascii wide // source: prose
        // prose -> short (<8 bytes) -> $s/$c only
        $s8 = "o=1727" ascii wide // source: prose
        // prose -> short (<8 bytes) -> $s/$c only
        $s9 = "dn=564" ascii wide // source: prose
        // prose -> short (<8 bytes) -> $s/$c only
        $s10 = "o=1720" ascii wide // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
