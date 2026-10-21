// New Infostealer Campaign Targets Users via Spoofed Software Installers
// Source: virustotal | https://blog.virustotal.com/2026/01/malicious-infostealer-january-26.html

import "hash"

rule IOC_New_Infostealer_Campaign_Targets_Users_via_Spoofed_Software_Installers_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: New Infostealer Campaign Targets Users via Spoofed Software Installers. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "virustotal"
        reference   = "https://blog.virustotal.com/2026/01/malicious-infostealer-january-26.html"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57" or
        hash.sha256(0, filesize) == "606baa263e87d32a64a9b191fc7e96ca066708b2f003bde35391908d3311a463" or
        hash.sha256(0, filesize) == "6773af31bd7891852c3d8170085dd4bf2d68ea24a165e4b604d777bd083caeaa" or
        hash.sha256(0, filesize) == "4294d6e8f1a63b88c473fce71b665bbc713e3ee88d95f286e058f1a37d4162be" or
        hash.sha256(0, filesize) == "5591156d120934f19f2bb92d9f9b1b32cb022134befef9b63c2191460be36899" or
        hash.sha256(0, filesize) == "f001ae3318ba29a3b663d72b5375d10da5207163c6b2746cfae9e46a37d975cf" or
        hash.sha256(0, filesize) == "c67403d3b6e7750222f20fa97daa3c05a9a8cce39db16455e196cd81d087b54d" or
        hash.sha256(0, filesize) == "5ee9d4636b01fd3a35bd8e3dce86a8c114d8b0aa6b68b1d26ace7ef0f85b438a" or
        hash.sha256(0, filesize) == "e84b0dadb0b6be9b00a063ed82c8ddba06a2bd13f07d510d14e6fd73cd613fba" or
        hash.md5(0, filesize) == "4acaac53c8340a8c236c91e68244e6cb"
}

