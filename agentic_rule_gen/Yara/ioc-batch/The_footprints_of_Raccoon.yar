// The footprints of Raccoon
// Source: group-ib | https://www.group-ib.com/blog/fakesecurity-raccoon/

import "hash"

rule IOC_The_footprints_of_Raccoon_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The footprints of Raccoon. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/fakesecurity-raccoon/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "b1799345152f0f11a0a573b91093a1867d64e119" or
        hash.sha1(0, filesize) == "f3498ba783b9c8c84d754af8a687d2ff189615d9" or
        hash.sha1(0, filesize) == "13b7afe8ee87977ae34734812482ca7efd62b9b6" or
        hash.sha1(0, filesize) == "596a3cb4d82e6ab4d7223be640f614b0f7bd14af" or
        hash.sha1(0, filesize) == "c2f8d217877b1a28e4951286d3375212f8dc2335" or
        hash.sha1(0, filesize) == "430a406f2134b48908363e473dd6da11a172a7e1" or
        hash.sha1(0, filesize) == "f33c1f0930231fe6f5d0f00978188857cbb0e90d" or
        hash.sha1(0, filesize) == "bdfefdff7b755a89d60de22309da72b82df70ecb" or
        hash.sha1(0, filesize) == "b326f9a6d6087f10ef3a9f554a874243f000549d" or
        hash.sha1(0, filesize) == "f2b2f74f4572bf8bd2d948b34147ffe303f92a0f" or
        hash.sha1(0, filesize) == "6685955c5f006c2d83a92952eb5eb3fb9598c783" or
        hash.sha1(0, filesize) == "3657cf5f2142c7e30f72e231e87518b82710dc1c" or
        hash.sha1(0, filesize) == "a10925364347bde843a1d4105dddf4a4eb88c746" or
        hash.sha1(0, filesize) == "618c894c06633e3d7add228531f6e775a180a7f7" or
        hash.sha1(0, filesize) == "6639081791a8909f042e4a4197df7051382b04e5" or
        hash.sha1(0, filesize) == "6c6680659b09d18ccab0f933daf5bf1910168b1a" or
        hash.sha1(0, filesize) == "7b1a5d9bb21d852a6dbf3146fabb1cd1ca276ed9" or
        hash.sha1(0, filesize) == "ed5c20371bae393df0a713be72220b055e5cbdad" or
        hash.sha1(0, filesize) == "bcfb45e5451435530156f1f02ddbb9cadf6338e9"
}

