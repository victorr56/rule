// The global socket: how threat actors are weaponizing GSocket for stealthy C2
// Source: microsoft-security | https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/

import "hash"

rule IOC_The_global_socket_how_threat_actors_are_weaponizing_GSocket_for_stealthy_C2_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The global socket: how threat actors are weaponizing GSocket for stealthy C2. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "microsoft-security"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/"
        date        = "2026-11-12"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa" or
        hash.sha256(0, filesize) == "f95c4d029e6784e3849b4d1e2e2ae1a661187236ef7c5d487c71158a290a03b5" or
        hash.sha256(0, filesize) == "55d141bb2f62c527c3fea3413b8429fed7d52633d0b123b5e611bfa42165229f" or
        hash.sha256(0, filesize) == "12450bafc7a4398040e1ad3a16dbf4dbc79b6a8f83ef306c4f0f73f59886f06c"
}

