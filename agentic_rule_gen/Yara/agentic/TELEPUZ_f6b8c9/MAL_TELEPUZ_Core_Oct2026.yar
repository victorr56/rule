/* Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $s, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
import "pe"

rule MAL_TELEPUZ_Core_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/telepuz-maas-malware-clickfix"
        date = "2026-10-16"
        description = "This rule detects the main DLL component of the TELEPUZ MaaS malware. It triggers on one of several unique strings (such as an AES key, service description, file path, or mutex) or the presence of both specific export names."
        malware_family = "TELEPUZ"
        hash1 = "58aec6e3835aaf20f7b4a7e308b36a19e7454673a6f71783871e9bcf6cae8eed"
        hash2 = "bf3b4e645a3c0c23f87c55971069014f7424ad14497371ee7567eff68ffaf343"
        hash3 = "ff791fe1532a2dc3b3c188a71bfd0177f973ef228e4d1dda1db6d3c4b0d62b3e"
        hash4 = "a670b03c1da00ee2c8622fd716085358d7e36ee98c4adafc9bda53eaadd59527"
        hash5 = "7c501632cd3830735040964b69d73a5dc315d0422fe3f1012c4b50db58dc0663"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x4, x8, x10"

    strings:
        // Unique strings, can trigger the rule alone
        $s1 = "cee96a38e2dfe31ccf8c3aa7d0d9323e1e3183b2478ba582285822e943d242e9" ascii  // source: artifact, AES256-CBC key
        $s2 = "Performs periodic configuration checks and reports telemetry anomalies to the central driver aggregator." ascii wide  // source: artifact, Service Description value for CipherAllocator
        $s3 = "C:\\ProgramData\\BrevixCore\\drx_curator.dll" ascii wide  // source: figure_literals, TELEPUZ DownloadRunModule function downloading DLL from zewaplus.club and executing with rundll32.exe
        $s4 = "INJECT:TODO:pid=%u:shellcode_len=%u" ascii wide  // source: artifact, Unimplemented InjectShellcode command return string
        $s5 = "Pivot Controller Service" ascii wide  // source: artifact, Service DisplayName for CipherAllocator
        $s6 = "\\DCFG\\Runtime\\Themes\\Processor\\twhost.dll" ascii wide  // source: figure_literals, TELEPUZ DoPersistence function copying malware to DCFG Runtime Themes Processor folder and executing via rundll32
        $s7 = "policy_alt_96.config" ascii wide  // source: artifact, Embedded policy blob decrypted with CustomRC4 at runtime
        $s8 = "cfgmgr_mtx" ascii wide  // source: artifact, Mutex created at startup if not already present
        $s9 = "cal.joycedoula.com.br" ascii wide  // source: figure_literals, TELEPUZ C2 domain initialization...
        $s10 = "\\files\\telemetriawork\\telepuz.dll" ascii wide  // source: artifact, Dominant payload download path pattern

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        pe.is_dll() and
        (
            1 of ($s*) or
            (pe.exports("GatewayLaunch") and pe.exports("ServiceRoutine"))
        )
}
