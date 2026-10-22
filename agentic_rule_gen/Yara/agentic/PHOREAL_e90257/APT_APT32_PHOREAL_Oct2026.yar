import "pe"

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
rule APT_APT32_PHOREAL_Oct2023
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2023-10-24"
        description = "Detects PHOREAL/RIZZO malware used by APT32. The rule triggers on unique artifacts such as a GUID-based mutex, named pipe, or filename pattern, or a specific code sequence. It can also trigger on a combination of three supporting strings like the masqueraded filename 'tscon32.dll', export 'DllEntry', and specific API imports."
        hash1 = "ec5d5e18804e5d8118c459f5b6f3ca96047d629a50d1a0571dee0ac8d5a4ce33"
        hash2 = "88f073552b30462a00d1d612b1638b0508e4ef02c15cf46203998091f0aef4de"
        reference = "https://www.elastic.co/security-labs/threat-command/phoreal-malware-targets-the-southeast-asian-financial-sector"
        score = 60
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        tlp = "WHITE"

    strings:
        $x1 = "Local\\{5FBC3F53-A76D-4248-969A-31740CBC8AD6}" ascii wide  // source: strings_listing
        $x2 = "\\\\.\\pipe\\{A06F176F-79F1-473E-AF44-9763E3CB34E5}" ascii wide  // source: strings_listing
        $x3 = "{FD5F8447-657A-45C1-894B-D533926C9B66}.dll" ascii wide  // source: strings_listing
        $x4 = { 8B FF 55 8B EC 56 E8 3F 3E 00 00 E8 34 3E 00 00 50 E8 14 3E 00 00 85 C0 75 2A 8B 75 08 56 E8 21 }  // source: figure_or_disassembly

        $s1 = "tscon32.dll" ascii wide  // source: figure_or_disassembly
        $s2 = "DllEntry" ascii  // source: strings_listing
        $s3 = "NetWkstaGetInfo" ascii  // source: strings_listing
        $s4 = "NetApiBufferFree" ascii  // source: strings_listing

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and pe.is_dll() and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
