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
rule MAL_ModularRAT_Exodus_Modules_Oct2026
{
    meta:
        description = "Detects modules of a modular RAT associated with a trojanized Exodus wallet installer. The rule matches on a unique PDB path or a combination of module names."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat"
        date = "2026-10-17"
        hash1 = "8c3b41ea5a85778145a6e5772bfee2eb0f8b027d0af199fb71a76dfb8bb29e5a"
        hash2 = "fdd376562aac4be64fb635546a61e1912ff2c353360db73d2c553dcbb5a44f54"
        hash3 = "2f47cfbb13f7a8a2d30d287f4ddd974fabea6762ad9781d438eb53da41b4582d"
        hash4 = "84437d4239d2a3d90c4faad0a3c0630b2f61a40f7bbd12109bef74d7613b8756"
        hash5 = "5274e93e35586a341d14b50cdf8413d59c51fd94f32bdc70bfdfb77198367603"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $s1, $s2, $s3, $s4, $s5, $s6"

    strings:
        $x1 = "C:\\\\Users\\\\root\\\\node_modules\\\\@intelcorp\\\\wmi-native-module\\\\build\\\\Release\\\\wmi_native_module.pdb" ascii  // source: explicit_literal

        $s1 = "dll4_cmd.dll" ascii  // source: explicit_literal
        $s2 = "dll4_fileman.dll" ascii  // source: explicit_literal
        $s3 = "dll4_browser.dll" ascii  // source: explicit_literal
        $s4 = "dll4_socks.dll" ascii  // source: explicit_literal
        $s5 = "dll4_vnc.dll" ascii  // source: explicit_literal
        $s6 = "dll4_script.dll" ascii  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        (
            $x1 or
            3 of ($s*)
        )
}
