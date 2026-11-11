// Not All That Glitters Is Gold: Tracking CopperDragon’s Sparrow Framework Around the Globe
// Source: checkpoint-research | https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/

import "hash"

rule IOC_Not_All_That_Glitters_Is_Gold_Tracking_CopperDragon_s_Sparrow_Framework_Around_the_Globe_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Not All That Glitters Is Gold: Tracking CopperDragon’s Sparrow Framework Around the Globe. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "checkpoint-research"
        reference   = "https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/"
        date        = "2026-11-11"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "ee4a8b81fe3864582efc27a77f806990e2602dcc36447ddda4b3a230a473d575" or
        hash.sha256(0, filesize) == "715c206629f59ff5b0134a33362162ce7a40a9b25aa17f0543dc9648d51a67cf" or
        hash.sha256(0, filesize) == "b379d07ba81d4190490d9893b2d6d830ff594e042dce26053ef07794d0403787" or
        hash.sha256(0, filesize) == "e5f7bbfc187264336dea5dfebfb5a7dd1e7fcdcc9692db55fbe6eb4d28f027bc" or
        hash.sha256(0, filesize) == "e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f" or
        hash.sha256(0, filesize) == "f44159bec1d4d3f340652cd3c6e250dcf2bdb266e5400d3e267f0466d290dda0" or
        hash.sha256(0, filesize) == "f51dc5e1848daee4e607d46faa25033e1151060cd3482ad4439754440d6c4c01" or
        hash.sha256(0, filesize) == "8bbc395a7a0faff074c6e31c7da37bf1540a4e7ec3d80870f8d6bd1f5d4cecbb" or
        hash.sha256(0, filesize) == "054c0ffb08eb7830de1ff2356af4d2ed696f01111a8c2e78e3a4ddc940287e48" or
        hash.sha256(0, filesize) == "b60404c1299e69df029d9817dcf69f9fe325ecc990e16bc7758f56ce5714184b" or
        hash.sha256(0, filesize) == "f23e5391656b178bc0ab510b0fca6ffbd963cf94870c82a5920f0f338f561f18" or
        hash.sha256(0, filesize) == "1cd0c608418cca80149ef3077e54969f24cd7ef3f22707cb280fa4b378ffa76b" or
        hash.sha256(0, filesize) == "40880b6fce6f83df4e902cd29d7abb303ffa3f37c429c382f2aaeea34f7be074" or
        hash.sha256(0, filesize) == "9fa421adb5c5dac3b2fc1165b0dddd596e82cfd3b08347a91d63f9e88d8718d0" or
        hash.sha256(0, filesize) == "3637f4f804cffc3b25222d542e7cb544ee48074ed2e46607e31f9410c17bf223" or
        hash.sha256(0, filesize) == "1b365975f9ad8a4748b2bbfb36de3be171aeadeb59d497192a8b4d9560b37173" or
        hash.sha256(0, filesize) == "d1da8e2389f48d1d1c0e127f3417e3d3e0dbf54691e22d6d0c863d28b9e7a812" or
        hash.sha256(0, filesize) == "dbdaa8a52246b1e3f9285820db2f976b8ab513926ed972c968fae1c8aeb77056" or
        hash.sha256(0, filesize) == "46407cc35c48d19c6b1990a03ebdd19321005ce08d5a98acd168fda55a92d946" or
        hash.sha256(0, filesize) == "3e4eef1a641d6060f6144ceba6757df6085d475eedb8b9e61b5feb84e9fb989e" or
        hash.sha256(0, filesize) == "4cafda69af3179ceb4a1f5ed864c501279796254709c86ca236be1cf74a8643f" or
        hash.sha256(0, filesize) == "48dcc07d9f87129e937f5ca2ad5ba56975600efb8a7280a170b2aeeff503f595" or
        hash.sha256(0, filesize) == "a47279e4ee703092263e7030c43c61533146c00689e7cb8f2080f18e57d5cf7f" or
        hash.sha256(0, filesize) == "12b6d5ca7aca7134032721b6feb8e4d5ad75c886fbf8a5889d3d36971a083681" or
        hash.sha256(0, filesize) == "125525a38abc45e855f848d499582a8100f1428938d4bd3d3eba957072e64e7a" or
        hash.sha256(0, filesize) == "4b1fea3265492ad1d272428447fb5919bbe3184131b12a0ae84caf3bc442718e" or
        hash.sha256(0, filesize) == "4e50f53b5294a6dbd601fc20a607ae85725162b596119f4867311ef0b3f75a6a" or
        hash.sha256(0, filesize) == "f42461c386834d61780da13760a130ed2ea620627b5eebf97b56237058ea380d" or
        hash.sha256(0, filesize) == "b7060cf7955a1f1caac2bc3d0918c9b1d9daa315c5d82b329acd3bbddb413948" or
        hash.sha1(0, filesize) == "4872589ca964eac0776b1e9617e9813cb1da49dc" or
        hash.sha1(0, filesize) == "760be920fad07881b8ce9d94e074a35b4f806717" or
        hash.sha1(0, filesize) == "20a61422b0352cfc9ef688dc800bcdf810f1fe7d" or
        hash.sha1(0, filesize) == "de32c58a8087cc4f24b9eb65c8ff4516f0f65f13"
}

