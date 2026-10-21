// Breaking the Seal: Static Deobfuscation of JSCeal’s Compiled V8 Bytecode
// Source: checkpoint-research | https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode/

import "hash"

rule IOC_Breaking_the_Seal_Static_Deobfuscation_of_JSCeal_s_Compiled_V8_Bytecode_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Breaking the Seal: Static Deobfuscation of JSCeal’s Compiled V8 Bytecode. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "checkpoint-research"
        reference   = "https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "de213ebc44c614d0b2324787e267183dbbbbb19e1ad866435a322ee00e24e7b6" or
        hash.sha256(0, filesize) == "c77b3b7a507162bfc03cfeb8ef18d5ee7017e8fcbd6d7e005f986a3c967b8d45" or
        hash.sha256(0, filesize) == "4757f3d26bc7110e9c7f4da8050afc2ed661cd92aec9cf7d301d9b9b24e0b668" or
        hash.sha256(0, filesize) == "b90e3aaae14e7787e5ea4a6d4beee672049bd5eb05427f2c80b64f605860d2b8" or
        hash.sha256(0, filesize) == "058ae4136e241f116d8c5b1a1cad15b53090797154539faa35706568fbd85d9b" or
        hash.sha256(0, filesize) == "7e1c82cdcff73ac69fee3ba71d67353a062103f1bfae4f263d03b3b84e48d782" or
        hash.sha256(0, filesize) == "c288e79ed9d1fb654a341b92d878a3165a09fb21dfa826f3559b46738fdbbdeb" or
        hash.sha256(0, filesize) == "8b3ed808822479eb62d78d819db35362e4e79138ac82310d30e0c351a17992b6" or
        hash.sha256(0, filesize) == "06dce0f294c62f2a2393c812ff711bde831bf420a4df484bcf5b6241fc0f00d0" or
        hash.md5(0, filesize) == "e27ae65977287bdfb7b0e15fd3603f85" or
        hash.md5(0, filesize) == "0d1fce0cb2b9dec26a10f0822aeffb19" or
        hash.md5(0, filesize) == "581e2e2265d0c1509b3799c5a9039374" or
        hash.md5(0, filesize) == "de10c6b3dc4619f59bc9c80a0aa15e6a" or
        hash.md5(0, filesize) == "0b8015cbb1ffdc6efe6a306ff5b1115f" or
        hash.md5(0, filesize) == "fd4494c555adda2eb54b88f5c9c08801" or
        hash.md5(0, filesize) == "91038aebe528a065c3e995a418db6826" or
        hash.md5(0, filesize) == "13823095b8d31013ba41a5c98ce69b59" or
        hash.md5(0, filesize) == "454fb012cdd0736e4ed41fabf0916f46" or
        hash.md5(0, filesize) == "10c576a57fc040eddd84d631786b8dda"
}

