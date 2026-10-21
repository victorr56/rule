// The Odyssey and Trojans again: MovieReaper attacks users in multiple countries through compromised torrents
// Source: securelist | https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/

import "hash"

rule IOC_The_Odyssey_and_Trojans_again_MovieReaper_attacks_users_in_multiple_countries_through_comp_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The Odyssey and Trojans again: MovieReaper attacks users in multiple countries through compromised torrents. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "a0b13781edd7cfdab13d79afff3c83c1" or
        hash.md5(0, filesize) == "4843f9fafcae492f11e2d4d33dbb4cdd" or
        hash.md5(0, filesize) == "5310cabae3fbe6db8742849b588093f9" or
        hash.md5(0, filesize) == "70060341caf3338697a7ddfe0fb62875" or
        hash.md5(0, filesize) == "ad4643eea15ac286fa47d1131f9ef756" or
        hash.md5(0, filesize) == "d0b967571ac8a3863c7f324bf5bde99c" or
        hash.md5(0, filesize) == "d88d550d0fb8e60cffff3ea61ff7a067"
}

