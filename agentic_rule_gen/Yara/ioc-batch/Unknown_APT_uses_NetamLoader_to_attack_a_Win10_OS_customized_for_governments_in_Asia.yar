// Unknown APT uses NetamLoader to attack a Win10 OS customized for governments in Asia
// Source: securelist | https://securelist.com/netamloader/121676/

import "hash"

rule IOC_Unknown_APT_uses_NetamLoader_to_attack_a_Win10_OS_customized_for_governments_in_Asia_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Unknown APT uses NetamLoader to attack a Win10 OS customized for governments in Asia. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/netamloader/121676/"
        date        = "2026-10-29"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "f2458ed133f8d0ca19e22c10f577e98e" or
        hash.md5(0, filesize) == "e1dc6f1ed193594f2284be22ae08dfa4" or
        hash.md5(0, filesize) == "ab81564bcb8ca7e710c66832de747556" or
        hash.md5(0, filesize) == "cfb8b281bdf5d9390e64b10c312fb2c1" or
        hash.md5(0, filesize) == "67e3617f8709d34f806f8e02badba8a5" or
        hash.md5(0, filesize) == "514ac0d73b8a1b73488ef5e2e55a75c3" or
        hash.md5(0, filesize) == "514117d536e347560d049cfe0c609632" or
        hash.md5(0, filesize) == "9000820d8153c24cd60d53001d3a97b6" or
        hash.md5(0, filesize) == "b3c4a635179680edafb5d006cf0cffc6" or
        hash.md5(0, filesize) == "4f28622c5e60c01319bf48cf742fe1a5" or
        hash.md5(0, filesize) == "c86d53392a87dd3f3e62d62c9b92a9bd" or
        hash.sha1(0, filesize) == "e4537a1762fcafd2fd96bfc825bad34f9db9a24d"
}

