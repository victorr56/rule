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
rule APT_TontoTeam_Downloader_QuickMute_Oct2026 {
  meta:
    author = "ioc-yara-daily (agentic)"
    date = "2026-10-22"
    description = "Detects Tonto Team's downloader, also known as QuickMute. The detection is based on a unique mutex, a 256-byte RC4 key, a distinctive sscanf format string, or a combination of other specific strings. A match is triggered by one of the unique strings or a combination of four supporting strings."
    reference = "https://www.group-ib.com/blog/tonto-team/"
    hash1 = "c357faf78d6fb1460bfcd2741d1e99a9f19cf6dffd6c09bda84a2f0928015398"
    malware_family = "Bisonal"
    threat_actor = "Tonto Team"
    tlp = "WHITE"
    status = "untested"
    test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
    score = 60
    unverified_strings = "s5, s6"

  strings:
    $x1 = "{A931568B-94AF-449D-B7F6-6585EF9E9839}" ascii wide  // source: figure_or_disassembly
    $x2 = "%[^!]!%[^$]$%[^$]$%[^$]$%[^$]$%[^$]$%[^$]$%[^$]$%[^$]$%[^$]$%[^$]" ascii  // source: strings_listing
    $x3 = { 38 05 87 0F 0C 6B 9F 2A 2B 1F F8 DA D2 6E 1E 42 8D 3D 07 5F 36 F9 91 21 FC 7D EB 8A 06 C7 66 3F 29 2F EF FB 78 B6 1B 7B 04 14 B2 30 98 D0 7F 8B BF EC 47 FE 94 5D A6 CF 15 44 FF AB C9 57 46 81 93 69 82 58 08 03 B5 68 25 83 1D 0A 1A 9E D6 48 2E 09 EA C1 02 0D 51 F2 6C 0B 4D E8 A9 32 5B AE B7 A7 C5 01 3A 8F 72 00 4E 76 DB 65 4A 23 70 BA 97 52 D7 D4 E2 8E 89 3B AC 9B 90 63 28 1C 39 A0 77 27 A5 0E EE D5 4C E7 41 B8 9A 17 B4 37 A4 F1 A3 55 C4 B9 CD CC 88 D1 CB 18 22 4F 2D 8C E5 9D BB F5 35 60 FA 84 E0 73 13 C6 C2 79 B3 5E 71 26 D9 F7 3C 2C F3 45 7A 43 10 4B CE E6 86 16 ED AD 12 BC DE 85 AF 19 A8 C8 E3 E9 31 F0 61 5A 99 75 A2 E1 56 B0 D8 53 7C DD DF BE E4 80 C0 54 C3 74 7E 6D 20 49 64 67 B1 40 A1 95 D3 DC BD 24 9C FD 3E 6F 5C 62 34 F4 6A 50 CA 92 AA 96 33 11 F6 59 }  // source: strings_listing

    $s1 = "QuitMutex%d" ascii wide  // source: strings_listing
    $s2 = "https-note-86" ascii wide  // source: figure_or_disassembly
    $s3 = "`[#o_*#]`" ascii wide  // source: figure_or_disassembly
    $s4 = "Wrap Module" ascii wide  // source: strings_listing
    $s5 = "HttpsVictimMain" ascii  // source: prose
    $s6 = "/update/v32/default" ascii  // source: prose

  condition:
    uint16(0) == 0x5a4d and filesize < 5MB and
    (
      1 of ($x*) or
      4 of ($s*)
    )
}
