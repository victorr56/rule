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
rule MAL_ClickFix_RAT_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat"
        date = "2026-10-16"
        description = "Detects the ClickFix RAT component based on unique strings. The rule can be triggered by one strong unique string or three supporting strings."
        hash1 = "eff5d63ddf1813962f0d8ad1250cea5486c8bb5dd27c3f432b43957a33e43764"
        hash2 = "9c615db040b88c18ce6b96f30d08797045b7d506f940bea452dc7a6992fdbb8d"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "Broadcast start failed: RD worker launch failed" ascii wide // source: report Fig.15 strings listing
        $x2 = "DLL RUNDLL32 payload is missing" ascii wide // source: report Fig.15 strings listing
        $x3 = "-NoProfile -ExecutionPolicy Bypass -Command \\\"Expand-Archive -LiteralPath '" ascii wide // source: report Fig.15 strings listing
        $x4 = "Current Gate Host:" ascii wide // source: strings_listing

        $s1 = "Advanced search engine could not be allocated" ascii wide // source: report Fig.15 strings listing
        $s2 = "msedge.exe;chrome.exe;firefox.exe;brave.exe;opera.exe;vivaldi.exe;iexplore.exe;arc.exe;" ascii wide // source: report Fig.15 strings listing
        $s3 = "/SC ONLOGON /RU SYSTEM /F /RL" ascii wide // source: report Fig.15 strings listing
        $s4 = "SELECT displayName FROM AntiVirusProduct" ascii wide // source: strings_listing
        $s5 = "SELECT AMServiceEnabled FROM MSFT_MpComputerStatus" ascii wide // source: strings_listing
        $s6 = "NetLocalGroupAddMembers" ascii wide // source: report Fig.15 strings listing
        $s7 = "Autorun HKCU added" ascii wide // source: report Fig.15 strings listing
        $s8 = "MSI started successfully:" ascii wide // source: report Fig.15 strings listing

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
