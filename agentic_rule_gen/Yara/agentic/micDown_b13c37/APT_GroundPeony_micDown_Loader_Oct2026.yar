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
import "pe"

rule APT_GroundPeony_micDown_Loader_Oct2026
{
    meta:
        description = "Detects the GroundPeony (UNC3347) micDown sideloading DLL which masquerades as version.dll and contains three specific hardcoded filenames."
        author = "ioc-yara-daily (agentic)"
        reference = "http://nao-sec.org/2023/08/groundpeony-crawling-with-malice.html"
        date = "2026-10-16"
        hash1 = "1992b552bdaf93caeb470f94b4bf91e0157ba4a9bb92fb8430be946c0ddabdeb"
        hash2 = "425630cc8be2a7dc2626ccd927bb45e5d40c1cb606bb5b2a7e8928df010af7c9"
        hash3 = "fa6510a84929a0c49d91b3887189fca5a310129912d8e7d14fed062e9446af7e"
        hash4 = "142a027d78c7ab5b425c2b849b347952196b03618e4ad74452dbe2ed4e3f73cd"
        hash5 = "d1989ca12426ed368816ce00f08975dc1ff1e4f474592523c40f9af344a57b49"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $s1 = "mic.doc" ascii wide  // source: artifact, kind: file_name
        $s2 = "mic.ver" ascii wide  // source: artifact, kind: file_name
        $s3 = "mic.exe" ascii wide  // source: artifact, kind: file_name

    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        pe.exports("VerQueryValueW") and
        3 of ($s*)
}
