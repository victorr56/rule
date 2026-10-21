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
rule APT_IcePeony_IceCache_IceEvent_Oct2026
{
    meta:
        description = "Detects IcePeony's custom backdoors IceCache and IceEvent. The rule triggers on the presence of a unique PDB path, a Go build ID, or other specific strings, or on a combination of several supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "http://nao-sec.org/2024/10/IcePeony-with-the-996-work-culture.html"
        date = "2026-10-16"
        hash1 = "5b16d1533754c9e625340c4fc2c1f76b11f37eb801166ccfb96d2aa02875a811"
        hash2 = "484e274077ab6f9354bf71164a8edee4dc4672fcfbf05355958785824fe0468f"
        hash3 = "11e90e2458a97957064a3d3f508fa6dadae19f632b45ff9523b7def50ebacb63"
        hash4 = "d1955169cd8195ecedfb85a3234e4e6b191f596e493904ebca5f44e176f3f950"
        hash5 = "a66627cc13f827064b7fcea643ab31b34a7cea444d85acc4e146d9f2b2851cf6"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        // Unique PDB Paths for IceCache and IceEvent (strong anchors)
        $x1 = "C:\\Users\\power\\documents\\visual studio 2017\\Projects\\cachsess\\x64\\Release\\cachsess.pdb" ascii wide  // source: explicit_literal
        $x2 = "C:\\Users\\power\\Documents\\Visual Studio 2017\\Projects\\cachsess\\Release\\cachsess32.pdb" ascii wide  // source: explicit_literal
        $x3 = "C:\\Users\\power\\Documents\\Visual Studio 2017\\Projects\\WinService\\x64\\Release\\WinService.pdb" ascii wide  // source: explicit_literal
        // Unique Go Build ID from an IceCache sample (strong anchor)
        $x4 = "0gqOCbNX2DLfLV4n7GIq/STkDyn" ascii  // source: figure_or_disassembly
        // Unique string from the iisClient wrapper tool (strong anchor)
        $x5 = "Upload a local file 'to' remote server" ascii wide  // source: figure_or_disassembly
        // Unique token from observed C2 traffic (strong anchor)
        $x6 = "X-Token: cbFOvVX1582Mr7nt" ascii  // source: figure_or_disassembly

        // Supporting strings
        $s1 = "CreateProcess failed: %d" ascii wide  // source: figure_or_disassembly
        $s2 = "iisClient" ascii  // source: figure_or_disassembly
        $s3 = "X-Cmd: EXEC" ascii  // source: figure_or_disassembly

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
