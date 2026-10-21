// REVSTEALER ramps up: analysis of up-and-coming infostealer
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer

import "hash"

rule IOC_REVSTEALER_ramps_up_analysis_of_up_and_coming_infostealer_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: REVSTEALER ramps up: analysis of up-and-coming infostealer. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "8b33e0f32c42a317e3d9cd67d5a6dc68e91a6cf9dd44742162858e7d83cf2073" or
        hash.sha256(0, filesize) == "f07666ac22dfa1a361b8a8576baf69eadaf15431db9f3c34e93334d8d2f8d691" or
        hash.sha256(0, filesize) == "bd97d5cab2d09b001d1b9e08890bce1a2b2cf8542a4b31c86b2def59328cafb2" or
        hash.sha256(0, filesize) == "5c30efd5b9ff75023c3813705f5c47feccc496f439b24b3e572db4c3b08dffe3" or
        hash.sha256(0, filesize) == "1617552169df805405b1bb70f742d6eac5af342f31c6e39ff6b9613bd2392354" or
        hash.sha256(0, filesize) == "83f5b4ca629681abab2b9680472a304572a8c91b4a8ccc1189fbf58c6186db09" or
        hash.sha256(0, filesize) == "4c897108e8e793d6904110928c996815c302d6975c9bc61162149e855a963d50" or
        hash.sha256(0, filesize) == "adc4aa652965396b52e79435ca54987ae9eb21bf5e67de5e9461b09655165ee4" or
        hash.sha256(0, filesize) == "14b2ac356ed75d10ef40bbaaa48e7dd9fff7de9719c2a43ad123fe843dd4e4e2" or
        hash.sha256(0, filesize) == "7c08cf409194056a8517865e5d3433d1499bb8262263b55b49b8b07d9d182fcb" or
        hash.sha256(0, filesize) == "13d7237d7289e67c2d806a65d52580b453ce4987acbe2c4c4d04833f55ebccfa" or
        hash.sha256(0, filesize) == "c66d2b77b9e85c53391891212413ad9a99eb66f4b11c6a431e78884a5b2651e5" or
        hash.sha1(0, filesize) == "7e4126adfe6679b3613f629cd49162fb08fc53bd" or
        hash.sha1(0, filesize) == "0ec6a6d31b36271ebd06450ea98c84eba8a191d5" or
        hash.sha1(0, filesize) == "49ce5712164755ed212209bc71539bbc6fcff541"
}

