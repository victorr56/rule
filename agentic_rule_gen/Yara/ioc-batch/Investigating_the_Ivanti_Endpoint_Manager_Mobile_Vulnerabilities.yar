// Investigating the Ivanti Endpoint Manager Mobile Vulnerabilities
// Source: darktrace | https://www.darktrace.com/blog/ivanti-under-siege-investigating-the-ivanti-endpoint-manager-mobile-vulnerabilities-cve-2025-4427-cve-2025-4428

import "hash"

rule IOC_Investigating_the_Ivanti_Endpoint_Manager_Mobile_Vulnerabilities_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Investigating the Ivanti Endpoint Manager Mobile Vulnerabilities. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "darktrace"
        reference   = "https://www.darktrace.com/blog/ivanti-under-siege-investigating-the-ivanti-endpoint-manager-mobile-vulnerabilities-cve-2025-4427-cve-2025-4428"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "ac91c2c777c9e8638ec1628a199e396907fbb7dcf9c430ca712ec64a6f1fcbc9" or
        hash.sha256(0, filesize) == "f3e0147d359f217e2aa0a3060d166f12e68314da84a4ecb5cb205bd711c71998" or
        hash.md5(0, filesize) == "4abfaeadcd5ab5f2c3acfac6454d1176" or
        hash.md5(0, filesize) == "d8d6fe1a268374088fb6a5dc7e5cbb54" or
        hash.sha1(0, filesize) == "1dec9191606f8fc86e4ae4fdf07f09822f8a94f2" or
        hash.sha1(0, filesize) == "c47abdb1651f9f6d96d34313872e68fb132f39f5"
}

