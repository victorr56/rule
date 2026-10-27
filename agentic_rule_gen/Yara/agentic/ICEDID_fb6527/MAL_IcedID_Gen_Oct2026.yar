import "pe"

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
rule MAL_IcedID_Gen_Oct2026
{
    meta:
        description = "This rule detects ICEDID (Bokbot) malware by matching on a specific code pattern, or a combination of the 'PluginInit' export and characteristic strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/icedids-network-infrastructure-is-alive-and-well"
        date = "2026-10-27"
        hash1 = "db91742b64c866df2fc7445a4879ec5fc256319e234b1ac5a25589455b2d9e32"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, s1, s2, s3, export_PluginInit"

    strings:
        // Unique pattern for high-confidence detection
        $x1 = { 74 ?? 8B 50 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 0F BA F0 ?? 48 8B 51 ?? 48 8B 4A ?? 39 01 74 ?? 35 14 24 4A 38 39 01 74 ?? } // source: explicit_literal

        // Supporting strings
        $s1 = "license.dat" ascii wide // source: prose
        $s2 = "hollow.dat" ascii wide // source: prose
        $s3 = "olasius.dll" ascii wide // source: prose
        $s4 = "CN=localhost, C=AU, ST=Some-State, O=Internet Widgits Pty Ltd" ascii wide // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB
        and
        (
            $x1 or
            (pe.exports("PluginInit") and 2 of ($s*))
        )
}
