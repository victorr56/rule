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
rule MAL_KREMLIN_Installer_Oct2026
{
    meta:
        description = "Detects the KREMLIN malware C++ installer component. Detection is based on a unique mutex, campaign identifiers, and other specific strings. A match can be triggered by one of the unique high-entropy strings, or a combination of supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware"
        date = "2026-10-16"
        hash1 = "c8c38634dd44d7c6162c66174a6ee23ee404265125166e8d757681bdd66a4268"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s2"

    strings:
        // Unique strings, strong enough to fire alone
        $x1 = "ClarinhoQueSim-XEDA2O" ascii wide  // source: artifact mutex
        $x2 = "98d8049e-804f-11f1-b79f-ae3a8bb85d01" ascii wide  // source: artifact unique_string
        $x3 = "<<@R9t!Zx#Qv" ascii wide  // source: artifact unique_string
        $x4 = "\\\"!mX7#Lp@^2Kd" ascii wide  // source: artifact unique_string

        // Supporting strings
        $s1 = "kremlin-moscow-russia" ascii wide  // source: artifact unique_string
        $s2 = "OSCrypt.AppBoundProvider.Decrypt.ResultCode" ascii wide  // source: artifact unique_string
        $s3 = "CUSTOMER_ID: %s" ascii wide  // source: report figure "Customer ID and Mutex logging"
        $s4 = "MUTEX: %s" ascii wide  // source: report figure "Customer ID and Mutex logging"
        $s5 = "SIE: 0x%04X" ascii wide  // source: report figure "Customer ID and Mutex logging"
        $s6 = "kr3ml1n" ascii wide  // source: artifact unique_string
        $s7 = "SystemFunction032" ascii  // source: artifact import_name
        $s8 = "http://www.creamp1eonlyfans.net" ascii wide  // source: artifact url

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and (
            1 of ($x*) or
            4 of ($s*)
        )
}
