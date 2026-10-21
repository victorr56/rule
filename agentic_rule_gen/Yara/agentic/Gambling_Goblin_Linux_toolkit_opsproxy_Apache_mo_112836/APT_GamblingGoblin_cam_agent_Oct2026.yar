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
rule APT_GamblingGoblin_cam_agent_Oct2026
{
    meta:
        description = "Detects the cam-agent Go-based scanner from the Gambling Goblin toolkit. The rule matches on multiple unique, long strings including a JSON configuration policy, a usage message, an internal project name, and a log message fragment. Any one of these is sufficient for detection."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/gaming-the-system-how-a-chinese-speaking-actor-turned-brazilian-government-sites-into-an-seo-weapon/"
        date = "2026-10-16"
        hash1 = "12af9d95c44e20a375148c25f8a2978a62ee95489134654c3537ccfb2d42120d"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x3"

    strings:
        $x1 = "{\"network_scan\":true,\"common_web_ports\":[80,443,8080,8443]}" ascii  // source: figure_or_disassembly
        $x2 = "cam-agent [-f] [-flog] [-h] [-v]" ascii  // source: figure_or_disassembly, figure_literals
        $x3 = "cluster-asset-mapping" ascii  // source: explicit_literal
        $x4 = "default long-lived worker session fo" ascii  // source: figure_literals

    condition:
        uint32(0) == 0x464c457f and filesize < 20MB and
        1 of ($x*)
}
