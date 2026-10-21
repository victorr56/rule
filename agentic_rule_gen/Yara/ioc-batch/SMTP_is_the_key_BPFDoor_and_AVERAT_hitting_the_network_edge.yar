// SMTP is the key: BPFDoor and AVERAT hitting the network edge
// Source: rapid7 | https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge

import "hash"

rule IOC_SMTP_is_the_key_BPFDoor_and_AVERAT_hitting_the_network_edge_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: SMTP is the key: BPFDoor and AVERAT hitting the network edge. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "rapid7"
        reference   = "https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "a37ea9897221d4495b538de72b74f2aa1d2ff09b7b6dcedd395aee58931adbf3" or
        hash.sha256(0, filesize) == "7e667ba5f9df912e02275d3cfe3809d16f822fe776f4035c84b118ebd925b1b5" or
        hash.sha256(0, filesize) == "a6f3b7f932761fb1fd5e74123f2482e36c65dd13e769af2ce08c65da195bfa7a" or
        hash.sha256(0, filesize) == "4435fcd6862921092614dbeaa880e4192352984686ebcd98f0ba13ee8e226ef9" or
        hash.sha256(0, filesize) == "652508a9cf40bee883dc0e5e219dfeba71fe7dac591d01c89f74c21f73b4963f" or
        hash.sha256(0, filesize) == "2bedc26d4b29b435c21962beed7db21188a0219a0d28334bba8b4fb1656d7b15" or
        hash.sha256(0, filesize) == "bf8135f46ecedfe5bd06fcecbb2e721c2367ff765b18f4aa3f868e6597f49e47" or
        hash.sha256(0, filesize) == "4925bcca085ec504f51191645da278d8e96698d91f3c6df44146336c697b4de8" or
        hash.sha256(0, filesize) == "a4379e115d3c4420f5d4b92561022d6e0897990e7297be65c033d47de68e6a6a" or
        hash.sha256(0, filesize) == "925c041807d4fb9dfe2ad84f963c2a4c60ea1289f6a0bdccbfb944478ffc2cf2" or
        hash.sha256(0, filesize) == "2fe2dd402ee6f9c578fce6dd4b36daaa407e99133e5dd502f2afca80feb60150" or
        hash.sha256(0, filesize) == "a65048eb30661e27f8edc2dd8d8c77ec87faec1f1750f6e04e7ecaf069a32858"
}

