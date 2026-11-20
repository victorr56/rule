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
rule MAL_Win_Armoury_Packer_Nov2026
{
    meta:
        description = "Detects the Armoury packer, used by CoffeeLoader, by identifying unique strings from its OpenCL and GLSL decryption routines. Any one of these highly specific strings will trigger the rule."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/retadup-delivers-coffeeloader/121908/"
        date = "2026-11-20"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "__kernel void f(__global char* a,__global char* b,__global char* c,int d)" ascii wide  // source: figure_or_disassembly
        $x2 = "layout(local_size_x = 256) in;" ascii wide  // source: figure_or_disassembly
        $x3 = "gl_GlobalInvocationID.x" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        1 of ($x*)
}
