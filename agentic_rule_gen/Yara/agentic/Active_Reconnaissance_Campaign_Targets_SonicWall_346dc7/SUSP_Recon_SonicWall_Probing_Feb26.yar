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
rule SUSP_Recon_SonicWall_Probing_Feb26 {
    meta:
        description = "Detects network reconnaissance activity targeting SonicWall firewalls. This rule matches a combination of URI paths and other indicators associated with a campaign observed in February 2024."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.greynoise.io/blog/active-reconnaissance-campaign-targets-sonicwall-firewalls-through-commercial-proxy-infrastructure"
        date = "2024-02-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1, s2, s3, s4"

    strings:
        // All strings are from a recon campaign analysis, likely found in web server logs or network traffic.
        // As this is a text-based rule without a file header, a match requires at least two indicators.
        $s1 = "/api/sonicos/is-sslvpn-enabled" ascii  // source: prose
        $s2 = "/cgi-bin/userLogin" ascii  // source: prose
        $s3 = "/sonicui/7/login/" ascii  // source: prose
        $s4 = "bytezero.io" ascii  // source: prose

    condition:
        // This rule is intended for network traffic or log files; filesize is a proxy for payload size.
        filesize < 5KB and
        2 of ($s*)
}
