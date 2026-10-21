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
rule APT_Lazarus_RemotePE_Loader_Oct2026
{
    meta:
        description = "Detects RemotePELoader and the RemotePE RAT, a cross-platform implant used by a Lazarus subgroup. The rule identifies the malware through combinations of a specific User-Agent string, unique C2 parameter names, and internal class names. A match requires at least three of these indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.fox-it.com/2025/09/01/three-lazarus-rats-coming-for-your-cheese/"
        date = "2026-10-16"
        hash1 = "7a05188ab0129b0b4f38e2e7599c5c52149ce0131140db33feb251d926428d68" // RemotePELoader
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $s1 = "User-Agent: Microsoft-Delivery-Optimization/10.0" ascii wide  // source: report Fig.10, RemotePELoader C2 traffic
        $s2 = "MicrosoftApplicationsTelemetryDeviceId" ascii wide  // source: artifact unique_string, RemotePE C2 parameter
        $s3 = "armAuthorization" ascii wide  // source: artifact unique_string, RemotePE C2 parameter
        $s4 = "IMiddleController" ascii  // source: artifact unique_string, RemotePE class name
        $s5 = "IChannelController" ascii  // source: artifact unique_string, RemotePE class name
        $s6 = "IConfigProfile" ascii  // source: artifact unique_string, RemotePE class name
        $s7 = "IKernelModule" ascii  // source: artifact unique_string, RemotePE class name

    condition:
        (
            uint16(0) == 0x5a4d or // PE
            uint32(0) == 0x464c457f or // ELF
            uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe // Mach-O
        )
        and filesize < 10MB
        and (
            3 of ($s*)
        )
}
