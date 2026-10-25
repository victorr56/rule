import "pe"
import "dotnet"

rule APT_CanvasCyclone_POWERSEAL_Runner_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-25"
        description = "Detects POWERSEAL, a .NET PowerShell runner used by Canvas Cyclone (APT32). The rule looks for several unique strings related to its functionality and error handling. A match requires one strong anchor string or three supporting strings in a .NET PE file."
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-charms-spectralviper"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
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
    strings:
        // Strong anchors (>= 16 bytes)
        $x1 = "[+] Loading PowerSeal" ascii // source: report strings_listing
        $x2 = "[!] Failed to exec PowerSeal" ascii // source: report strings_listing
        $x3 = "AppDomain: unable to get the name!" ascii // source: report strings_listing

        // Supporting strings
        $s1 = "PowerSeal.dll" wide // source: report strings_listing, yara_hint: dotnet_user_string
        $s2 = "InvokePs" ascii // source: report strings_listing
        $s3 = "amsiInitFailed" wide // source: report strings_listing, yara_hint: dotnet_user_string

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        dotnet.is_dotnet and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
