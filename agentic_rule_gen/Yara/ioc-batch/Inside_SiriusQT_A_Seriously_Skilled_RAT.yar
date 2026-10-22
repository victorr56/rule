// Inside SiriusQT: A Seriously Skilled RAT
// Source: group-ib | https://www.group-ib.com/blog/siriusqt-rat-hvnc-stealer/

import "hash"

rule IOC_Inside_SiriusQT_A_Seriously_Skilled_RAT_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Inside SiriusQT: A Seriously Skilled RAT. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/siriusqt-rat-hvnc-stealer/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "c206fa613257110b0522b60b402ca0b35da2cb126113e47b67543ba3ff93c53c" or
        hash.sha256(0, filesize) == "4fbbb632e08fde2aed8401ffcae9e45627d87084335ac88eb4c25088f0708b79" or
        hash.sha256(0, filesize) == "2eced97bf1395c1560fce05971a3400e0718a3bb70aadb5c2323121cdf6d19a2" or
        hash.sha256(0, filesize) == "903fdebedf8976c8f6f937ab02e86dd73e5386120b6ec257bc9b2ff57a653cee" or
        hash.sha256(0, filesize) == "00c6341ecb3dfed3e3b2f1e8ad3464356738c07edc48368cc0a5c501a0a97fa3" or
        hash.sha256(0, filesize) == "044fabf6c74ee4de19cee1e3abe4c2beb6a33a38cbed401c7a822c696fbaa33a" or
        hash.sha256(0, filesize) == "05447eb22f74a607391b3260291491c129ac92a286d044f53f07d45911c13bfd" or
        hash.sha256(0, filesize) == "0ecb89b09a2aeee9285bef8a54aef6410e3a3fedcc4ad4022a5f5d6d6a0c2043" or
        hash.sha256(0, filesize) == "0f4fba21d5b02928d2fabc7d3aa6c1d98dcb3ddebde8e76e31e02f0a6784825f" or
        hash.sha256(0, filesize) == "10899bccfe2d03922935cdd1eab7caef8c309f00f30df9797e972371f33f38a5" or
        hash.sha256(0, filesize) == "11667a43a05871e91891001f7ad34b5044d0ff400608b183a90641e8ef03d1cf" or
        hash.sha256(0, filesize) == "12e2b046127093fcb01d402599239a723278e00238986776071493282c6c95da" or
        hash.sha256(0, filesize) == "13b4441f5d8851a7b5f64f676ed83e1081b579078a7113606733c68ddf422847" or
        hash.sha256(0, filesize) == "163ebd5c74e865827639ba521bb6de49d8d01eade7367e421cb04f5285096709" or
        hash.sha256(0, filesize) == "4aa693d6e973d03175c7a4403ab13d94215f5c778dcf066101b12d35506514dc" or
        hash.sha256(0, filesize) == "4b7c35770f05d45b42fe9c212a807dc156efa44d2f7b12242ca8bf1103f6f675" or
        hash.sha256(0, filesize) == "4c5a229fb67eab9da3eec9cc0ca412d88a0c084b9665a5326166c2300fc9e44f" or
        hash.sha256(0, filesize) == "4cbd5d8f38fae48d231f59a3cb3efc54e50314f655d549d70b898428e089ef17" or
        hash.sha256(0, filesize) == "4dcf241b28d04361ec7eaad8e78204a844ae73c78896971ba1002907f2a7fae8" or
        hash.sha256(0, filesize) == "5004325791883b8dd6daabe199238ce909fa7fbdd81c3cede32e68912c24a8d7" or
        hash.sha256(0, filesize) == "500e217fc829d22b9bfbc29306e97e632720bafc96f6fa8b767f5cc4391c5e58" or
        hash.sha256(0, filesize) == "55afe5ad9092239bc9a64b85a16f4ad33dd9225fb14b9576f6897e904adb4742" or
        hash.sha256(0, filesize) == "58359849d455569a65378c7143cf0722d91cc76bbb82ad4225b6d3677400ebf4" or
        hash.sha256(0, filesize) == "5856e9cb3b6ed9bc8a274bb3e349cb3038f4180096bf16aaaeee6ded297faed6" or
        hash.sha256(0, filesize) == "597aaaf263c6482944ce6aeb39cf20c98e579b22a973483816d4104d8772e4f1" or
        hash.sha256(0, filesize) == "597ca35933a2db1f014ea1eb94a8c6c5f6e92b7f171bc2787445fea5c90b4034" or
        hash.sha256(0, filesize) == "5aaf5aae7babd494066bbe38626922db974571514a31f83e9ddf2a8610a76348" or
        hash.sha256(0, filesize) == "5b4ec46453e1c19fb31d899b6b6707b58a6a02ae323c87e8d3b8d51d10a32f5e" or
        hash.sha256(0, filesize) == "782c945effcea3779d19e1fb8e52bd637d04830cb6ba742883de255e7dbda977" or
        hash.sha256(0, filesize) == "78e25e310b2e2263df80e1d0ef434811be52ab51b36bfac440df017d75144105" or
        hash.sha256(0, filesize) == "7a49ffa93d305f85369c72165adabd25c0f82ac78edd7d0787b8bc55b4a2ae7d" or
        hash.sha256(0, filesize) == "7a4fbd22085ffbc982719af76e89b0ab579b353f51a4c3f8a00d4ef169ca3e21" or
        hash.sha256(0, filesize) == "7c36e0b9268defbea30674a6f8590cb53b92699bafbe7d231fa374bf0b41c35b" or
        hash.sha256(0, filesize) == "7dfab4baca5926ec6561928caf994f45e62fa3f23596a24b4af0a8ef4ebddc4a" or
        hash.sha256(0, filesize) == "8d85472d4aa05cddb26a3d1b8c13b829f3e3813a152e0a2c6165ef6ced54c957" or
        hash.sha256(0, filesize) == "8e50201ad8bd4813be995ec2f8d504e1df57d866b3a8759214ea4c1f9d4a157a" or
        hash.sha256(0, filesize) == "92bfbbd8e6eafdeae7e22704b2a7212a4fd9f8e8f6a675800750d1dd30958f20" or
        hash.sha256(0, filesize) == "92f2c18f2271d404c306f6cf5a9a9b603435e48aa48df13115af6a45a2299f91" or
        hash.sha256(0, filesize) == "931938d2edf11b236119bf724250e5811b14bbb52d5b40dd5a0d3bcd7b553775" or
        hash.sha256(0, filesize) == "937f16e523594646a78a42031a84620ffb6d1abee8884c21bfc8baf4bd9bf31b" or
        hash.sha256(0, filesize) == "938050157236523db559513d26223fd8370a4ab2e92590e2167c274fe06c5d1b" or
        hash.sha256(0, filesize) == "b8d1994ef15ca9ec1b8946356e9d6d5fe5cbfadb3af433b23e8741639c002dcf" or
        hash.sha256(0, filesize) == "bac0fd7f51a4ecf930553b463ad3b9fe400aa19c4074564e6c4d4502239b20d3" or
        hash.sha256(0, filesize) == "bc01568885ff3c08414865922bc9cb0eb6f4d34eab6e7a95e4aa1f752f5c3152" or
        hash.sha256(0, filesize) == "bcda26f67e4577a7ae180bae67100eff0f89102d641eb874aa347f28e19bca07" or
        hash.sha256(0, filesize) == "bead0690e96aafcf5c242d0ca0d30885584f42bcf2034a354b92f7e145ac23eb" or
        hash.sha256(0, filesize) == "c0a1713198d3c3aa5535e8a930acc48ec423444ea019c939f2183f9b957b5b24" or
        hash.sha256(0, filesize) == "c0fcd05db135001c6c14d86b6fc9666007ab98d19e8deda2302df0353cecee1c" or
        hash.sha256(0, filesize) == "dfaaac39723510727e4713439030f491a9bce3141f64bee0d4d1bc59ec195422" or
        hash.sha256(0, filesize) == "e053d408047f2899c5d678ea774c2d4e8f3cb81fc590a729b292c6e10ba18ff1" or
        hash.sha256(0, filesize) == "e1035bf33547756c7fbe3366fa7fe21c30b3914a99a61165ebe32576ccc3dfa5" or
        hash.sha256(0, filesize) == "e1590649901ad23bc6dd6a3d0589deef5adbbe90191db7d8d1503808712d3e48" or
        hash.sha256(0, filesize) == "e1b4d44eeddc66967bf8937ae625a84040161f6238e72bb57f0bc8f812984e11" or
        hash.sha256(0, filesize) == "e56f83c1af5e624f41cd5eca35d14d1c786ed94f91395b20bcee9f07bbbdf57b" or
        hash.sha256(0, filesize) == "e5a598b699bd3d192e3c099b14b12f68126b49b3260ba82004eaee87b4155463" or
        hash.sha256(0, filesize) == "f7a247c9d77002878054310ddb6895798eb2df591126231a4b3fafa2c51dbfd4" or
        hash.sha256(0, filesize) == "f7f28ef35e6becde12c319b90acfc98ec25bfa9acb17b534cd68f8c5f732fde2" or
        hash.sha256(0, filesize) == "f8c92b129da1f4ebec7ff2971fd7e4784e65537b7c25a0209032d16ed8d887d4" or
        hash.sha256(0, filesize) == "fa32aba50f22d6f1c4634b7d3ffd9eee5cd573317b75a7cb6bf8402c59c983dc" or
        hash.sha256(0, filesize) == "fa62de958ee2ace2b41728ff10c0911b81692c8d210c2f4e2d6d7c54b9a09f92" or
        hash.sha256(0, filesize) == "fd83e49f81bdbd9cfb1c132ab79095e8329057a38425d45d8ef297d67219cbfd" or
        hash.sha256(0, filesize) == "fe6a726b412ddbe09dc85b2fa11974bb92ddbad97473f3de581eea068caba213" or
        hash.md5(0, filesize) == "7c0684fd9d32c4f4ce32b549f41061b6" or
        hash.sha1(0, filesize) == "08a69dd233ac6f4b83aff34cfcb2984590e2670a"
}

