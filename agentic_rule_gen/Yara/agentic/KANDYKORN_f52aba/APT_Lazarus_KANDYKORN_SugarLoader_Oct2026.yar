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
rule APT_Lazarus_KANDYKORN_SugarLoader_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-catches-dprk-passing-out-kandykorn"
        date = "2026-10-18"
        description = "Detects the SUGARLOADER component of the KANDYKORN malware family, used by the Lazarus Group. The rule matches on a combination of a characteristic Mach-O section name, reflective loading API names, and a C2 domain."
        malware_family = "KANDYKORN"
        threat_actor = "Lazarus Group"
        hash1 = "3ea2ead8f3cec030906dcbffe3efd5c5d77d5d375d4a54cca03bfe8a6cb59940"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 50
        unverified_strings = "s2, s3, s4"

    strings:
        $s1 = "__mod_init_func" ascii // source: figure_or_disassembly
        $s2 = "NSLinkModule" ascii // source: prose
        $s3 = "pesnam.publicvm.com" ascii // source: prose
        $s4 = "NSCreateObjectFileImageFromMemory-" ascii // source: prose

    condition:
        uint32(0) == 0xfeedfacf and filesize < 10MB and
        3 of ($s*)
}
