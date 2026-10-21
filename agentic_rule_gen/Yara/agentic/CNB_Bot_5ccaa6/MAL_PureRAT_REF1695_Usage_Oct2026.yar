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

rule MAL_PureRAT_REF1695_Usage_Oct2026
{
    meta:
        description = "Detects samples of PureRAT associated with the threat actor REF1695. The rule identifies specific GitHub repositories and usernames used by the actor to host and distribute their malware payloads."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/fake-installers-to-monero"
        date = "2026-10-17"
        hash1 = "7bb0e91558244bcc79b6d7a4fe9d9882f11d3a99b70e1527aac979e27165f1d7"
        hash2 = "f84b00fc75f183c571c8f49fcc1d7e0241f538025db0f2daa4e2c5b9a6739049"
        hash3 = "bb48a52bae2ee8b98ee1888b3e7d05539c85b24548dd4c6acc08fbe5f0d7631a"
        hash4 = "6a01cc61f367d3bae34439f94ff3599fcccb66d05a8e000760626abb9886beac"
        hash5 = "e1e87d11079d33ec1a1c25629cbb747e56fe17071bde5fd8c982461b5baa80a4"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, a1, s1"
        malware_family = "PureRAT"
        threat_actor = "REF1695"

    strings:
        $x1 = "lebnabar198/Hgh5gM99fe3dG" ascii wide  // source: prose
        $a1 = "ugurlutaha6116" ascii wide  // source: prose
        $s1 = "MnrsInstllr_240126.exe" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            $x1 or
            ($a1 and $s1)
        )
}
