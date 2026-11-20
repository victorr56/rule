// SCKit abuses ScreenConnect to deploy remote access and target technician sessions
// Source: microsoft-security | https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/

import "hash"

rule IOC_SCKit_abuses_ScreenConnect_to_deploy_remote_access_and_target_technician_sessions_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: SCKit abuses ScreenConnect to deploy remote access and target technician sessions. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "microsoft-security"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        date        = "2026-11-20"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "61a672a13f03a9e81f573535ee92b1ed6cb7e848a33a06048865312d4e185ae2" or
        hash.sha256(0, filesize) == "8e6912deed82e80bb6bd66f73509d024b1f78b993515366d8317e69a97cff4f4" or
        hash.sha256(0, filesize) == "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af" or
        hash.sha256(0, filesize) == "94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11" or
        hash.sha256(0, filesize) == "7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec" or
        hash.sha256(0, filesize) == "b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d" or
        hash.sha256(0, filesize) == "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4" or
        hash.sha256(0, filesize) == "d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a" or
        hash.sha256(0, filesize) == "4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b" or
        hash.sha256(0, filesize) == "cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956" or
        hash.sha256(0, filesize) == "81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781" or
        hash.sha256(0, filesize) == "43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95" or
        hash.sha256(0, filesize) == "50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61" or
        hash.sha256(0, filesize) == "5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0" or
        hash.sha256(0, filesize) == "454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a" or
        hash.sha1(0, filesize) == "0be01e7bd69cfdd222645d49bb5ad9961372fef2" or
        hash.sha1(0, filesize) == "3f81c9c874a896c46e4bccea2fad2eaa3d9f2054" or
        hash.sha1(0, filesize) == "13ce33b19daee3963f7e15d461b191c38f6bc0d3"
}

