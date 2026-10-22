import "pe"
import "dotnet"

rule MAL_Deimos_Implant_Oct2026
{
    meta:
        description = "Detects the Deimos .NET implant based on unique XOR keys and assembly artifacts. The rule can fire on a unique, high-entropy XOR key alone, or a combination of at least three other indicators including another key, a JSON fragment, a method call string, and the 'Mars.Deimos' assembly name."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/going-coast-to-coast-climbing-the-pyramid-with-the-deimos-implant"
        date = "2026-10-22"
        hash1 = "d6e1c6a30356009c62bc2aa24f49674a7f492e5a34403344bfdd248656e20a54"
        hash2 = "2c1941847f660a99bbc6de16b00e563f70d900f9dbc40c6734871993961d3d3e"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "Mars.Deimos, s3"

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
        // Strong anchor - can fire alone
        $x1 = "XjBrPGQ7aipqcXYkbTQobjJEX0ZzPGlOfm5YbUEmb1dBazZ0RlpCa2hLQks8eXNxK3tsRHpZVmtmUU9mb31jaVVuMXUxUGk/e0tDa0QmXjA8U0ZAckhgNl5vX1deQGBad2peTyZvVUByaSk2XlBJMTxAdEtnT0B3fnBJPCtfe2tvV0d7P3Y0V2BaeXQ9PmhtI3ZaVHc3I2tGcm5IRmlmUTV8bXpxXlg/cyo8XyFwXyt5QmwjOChQZ09aPXxqaS1hfmxDK3U=" ascii // source: figure_or_disassembly

        // Supporting strings - require combination
        $s1 = "hYaAOxeocQMPVtECUZFJwGHzKnmqITrlyuNiDRkpgdWbSsfjvLBX" ascii // source: figure_or_disassembly
        $s2 = "{\\\"action\\\":\\\"ping\\\",\\\"" ascii // source: strings_listing
        $s3 = "[Mars.Deimos]::interact()" ascii wide // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            $x1 or
            (dotnet.is_dotnet and (
                (dotnet.assembly.name == "Mars.Deimos" and 2 of ($s*)) or
                3 of ($s*)
            ))
        )
}
