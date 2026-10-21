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
rule APT_GamblingGoblin_Linux_Toolkit_Oct2026
{
    meta:
        description = "Detects components of the Gambling Goblin Linux toolkit, specifically PasswordHarvester and DownPro. The rule relies on distinct strings from each tool: a unique error message and a Chinese-language format string. A match on either of these strong indicators will trigger the rule."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/gaming-the-system-how-a-chinese-speaking-actor-turned-brazilian-government-sites-into-an-seo-weapon/"
        date = "2026-10-16"
        hash1 = "5af1bec4635e52da4909bf744ea4b7e4483ec944241218855212f4a9e3d48611"
        hash2 = "e8bb763bd10e727228ca9a8e3e6cf10bf4de4639b6be680a3abfb181a0adc052"
        hash3 = "fa7fc029ac13af2f3880151e9c408e9afadeba7b2cff01659806fb7c3c83288d"
        hash4 = "c3c09fe219e10808f053e580628aeb87b1f00fc683c810aa828905fe03cda98f"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "kthread-mgr: invalid version string" ascii  // source: figure_literals (Fig.14)
        $x2 = { E5 91 BD E4 BB A4 E8 BE 93 E5 87 BA 3A 0A 25 73 0A } // source: figure_or_disassembly, "命令输出:\n%s\n"

    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and
        1 of ($x*)
}
