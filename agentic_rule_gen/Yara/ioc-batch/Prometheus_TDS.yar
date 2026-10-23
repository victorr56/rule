// Prometheus TDS
// Source: group-ib | https://www.group-ib.com/blog/prometheus-tds/

import "hash"

rule IOC_Prometheus_TDS_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Prometheus TDS. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/prometheus-tds/"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "2777c710350668010542846968025d642d40984fa87ad21b3b175c0d2f7e0b31" or
        hash.sha256(0, filesize) == "2f58ac50edbc16d8aa708d2f6b928076c3411a2fdeefa3031013148ec59ad6fe" or
        hash.sha256(0, filesize) == "a1b1abdf519253a12450708043cfe4fbcc586f288de16f84a64a419521e7f9ba" or
        hash.sha256(0, filesize) == "b629d7b71d99c562955ed11438f790f240704ad7cf06e848418b5476478a60e8" or
        hash.sha256(0, filesize) == "d600a2c30a57b53a650552ca214453f44c1ddddaea913d2a2c9bd2bbe2b051a0" or
        hash.sha256(0, filesize) == "8932db61f72108f0af9267056e74b0e099470b27fe62f997ecd092db8db20945" or
        hash.sha256(0, filesize) == "a5326a661319bd7a8ab027a22fb8bb0b0b6d027269c95ab24bee2da53b09b463" or
        hash.sha256(0, filesize) == "3041387a18df225d20b6564068f23adcb746f1560e9ae466c81163d96e46c258" or
        hash.sha256(0, filesize) == "16a5398065a79fa0ee83cb40444a0b31e838777a5c2638f1aa1e15b2ec9728c8" or
        hash.sha256(0, filesize) == "2b7686542959ce1e6b355f46b7c0aafd6e19243d2cae4123c1f064e0deebfd58" or
        hash.sha256(0, filesize) == "e44d72b2e48262424c9f0c62a9e9fb532686edc1f8d6e5c94d8c94ef76afc3f4" or
        hash.sha256(0, filesize) == "14a2744c4278bfdc4197793f928a24fd1036f604e5e68a7e5473ce224a7f728f" or
        hash.sha256(0, filesize) == "e54a05f127c3c775ce5a7163d37b98b289b4fe4cd11e58e2edc90aa2adc101e7" or
        hash.sha256(0, filesize) == "1495500d6c8613fda22b0e0c8f2ab0ba5d244d6b166c5d854a47000a91f44ab1" or
        hash.sha256(0, filesize) == "cd4164aee2890fbdf1b61b3b09a37b8857f6b3c87ceef29a573d34782598d976" or
        hash.sha256(0, filesize) == "53f16cc3aa9b674651f2e69e02f1c91849123e8a98cb7a850c56ed23c8e89efd" or
        hash.sha256(0, filesize) == "c6677e676ec1049bb877a7ea6c424d7505e0b5ecfb4c1a2f049e008fb0eb17de" or
        hash.sha256(0, filesize) == "858a42b43d4262aded023a166a01e6e43271b0a619e23b55da01694e3c9fe671" or
        hash.sha256(0, filesize) == "38713d11d588217d0e86ba3ea8a8dd550c368dad3b910a1aa72aa74fa325a7ae" or
        hash.md5(0, filesize) == "2e515f89c1e57a82f439f160bdc91045" or
        hash.md5(0, filesize) == "c5bc239bb990ca808b5645078c6710d1" or
        hash.md5(0, filesize) == "0dcd730d8bb4e11b15a18b1dc76fc495" or
        hash.md5(0, filesize) == "96e55bf478df6538526fb27d93ae0cff" or
        hash.md5(0, filesize) == "1598cbcca37f6d92037ad5569b152ffa" or
        hash.md5(0, filesize) == "5797d7959a374447e004251696460f83" or
        hash.md5(0, filesize) == "0e1134acbb0bc58770345c3874a80189" or
        hash.md5(0, filesize) == "24f7520283e02868e262dc9d595c7540" or
        hash.md5(0, filesize) == "79af726897412573ba50ad5b9ad168f0" or
        hash.md5(0, filesize) == "196ab58d25d3548c90472875a33743c6" or
        hash.md5(0, filesize) == "89ee343062cbb8e2fa70204cb0574b88" or
        hash.md5(0, filesize) == "ea967b761036ea62e17a3e1e8d9e6941" or
        hash.md5(0, filesize) == "c2263a4741865a59adbf94f6e8089b62" or
        hash.md5(0, filesize) == "60eea3a21bf7eda64e4dc09f490658da" or
        hash.md5(0, filesize) == "d32f0c13bd4041bd59fe4a3b6e1f5a24" or
        hash.md5(0, filesize) == "a70ae53c00fb51ef317c045dd8066e17" or
        hash.md5(0, filesize) == "045c33237a9843a2ece09e00203f2368" or
        hash.md5(0, filesize) == "02aed8241295fbdb0a6393393f2eb688" or
        hash.md5(0, filesize) == "3eb5461d2b200cce8e90c4c8db2fba96" or
        hash.md5(0, filesize) == "ffcf6712b62b87f44bcd7b3662308c5a" or
        hash.sha1(0, filesize) == "41138f0331c3edb731c9871709cffd01e4ba2d88" or
        hash.sha1(0, filesize) == "7394632d8cfc00c35570d219e49de63076294b6b" or
        hash.sha1(0, filesize) == "2d74e52ac0e3ebbf2bb4aabb6469cba9badd70eb" or
        hash.sha1(0, filesize) == "db23b35b2c2b8bf413fb57ee9017127f651e0304" or
        hash.sha1(0, filesize) == "fcd8674f8df4390d90dad6c31a3dd6f33d6a74de" or
        hash.sha1(0, filesize) == "e3249b46e76b3d94b46d45a38e175ef80b7d0526" or
        hash.sha1(0, filesize) == "f729b75d68824f200bebe3c3613c478f9d276501" or
        hash.sha1(0, filesize) == "a9964c999a28c850ef3fbb061d8272025ac38aaf" or
        hash.sha1(0, filesize) == "077baa375c2eea771867884cc8eeb632761346c9" or
        hash.sha1(0, filesize) == "143034d966a0a8fa125d3cfa2c59f8f6bc077fd1" or
        hash.sha1(0, filesize) == "efa8af362029314cafdb5cd3b21acba0c3398b37" or
        hash.sha1(0, filesize) == "050990c1fd000aaf8e97eb4d08f349b5b9ccbb32" or
        hash.sha1(0, filesize) == "d396268c483bbb5bf5c23198be569c7ef93a0223" or
        hash.sha1(0, filesize) == "58db5164840e053e7d20a136d4afdc9a3c4d6df2" or
        hash.sha1(0, filesize) == "75f68a7de72c53fd87a6ff161e2b4dfe4273b647" or
        hash.sha1(0, filesize) == "9bc673671d293d0787a77c8240bc8173ae68222c" or
        hash.sha1(0, filesize) == "c2fe78d027669d8fafec394718baa37cac529177" or
        hash.sha1(0, filesize) == "4f5ac7c2f7097bbdcabfccb9a3a6bbbe99f929b7" or
        hash.sha1(0, filesize) == "68b9c9217d81afea86e40d8789f4cbdedcf50697" or
        hash.sha1(0, filesize) == "76b375a2cf40ebbba72b0f622d2426d9ab86d443" or
        hash.sha1(0, filesize) == "74c1635011e4ce39205ee5884e22c96222d56cbb" or
        hash.sha1(0, filesize) == "a7aeb4a887810f978ffa91ca9ed890fe9279a465" or
        hash.sha1(0, filesize) == "df5e7cd307451a6c1ba6c0bc8901d4119a7e387b"
}

