import "pe"
import "dotnet"

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

rule MAL_REF1695_XMRig_Loader_Oct2026
{
    meta:
        description = "Detects a custom .NET-based XMRig loader used by REF1695. The rule matches on a unique hardcoded AES key and fallback configuration string, or a combination of C2 artifacts. This loader is part of a broader campaign involving cryptomining and RAT deployment."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/fake-installers-to-monero"
        date = "2026-10-17"
        hash1 = "0176ffaf278b9281aa207c59b858c8c0b6e38fdb13141f7ed391c9f8b2dc7630"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, s1, s2, s3"
        malware_family = "XMRig"

    strings:
        $x1 = "AsyncPrivateInputx64" ascii wide  // source: prose
        $x2 = "ztbpVbABSx1jDIKnWGbx1d_0" ascii wide  // source: prose

        $s1 = "autoupdatewinsystem.top" ascii wide  // source: prose
        $s2 = "/MyMNRconfigs/0226.txt" ascii wide  // source: prose
        $s3 = "procsrv.exe" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        pe.is_pe and dotnet.is_dotnet and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
