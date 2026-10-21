// From Payment Plan to Ransomware - Inside a Global Group Attack
// Source: cofense | https://cofense.com/blog/from-payment-plan-to-ransomware-inside-a-global-group-attack

import "hash"

rule IOC_From_Payment_Plan_to_Ransomware_Inside_a_Global_Group_Attack_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: From Payment Plan to Ransomware - Inside a Global Group Attack. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "cofense"
        reference   = "https://cofense.com/blog/from-payment-plan-to-ransomware-inside-a-global-group-attack"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "d5004e079cb46db15a7d0b7ecebfa47bb8a1bc19e25749849a017b2a36705260" or
        hash.sha256(0, filesize) == "00f70ae018e71f51060346aaa101209c24e34697bbfafec6b3612db8d8127cb2" or
        hash.sha256(0, filesize) == "997cf28771fde81c6bfc067eed1f19d0ad3554342d63d9469d3adcdc1ca0ff31" or
        hash.sha256(0, filesize) == "64388cdbfe48dcff05eaa455892bcb3bfcaa3d43559eb7c65f6ac772810be61e" or
        hash.sha256(0, filesize) == "9fb468a79f88d9a250180749bfae97d4f310c8510f1f98cae359d95c2a62b4af" or
        hash.md5(0, filesize) == "2abd445d3d60fd207b2c62bb0da3a42b" or
        hash.md5(0, filesize) == "9db4b94589728b68d51bf83a90211cfe" or
        hash.md5(0, filesize) == "5dee17e91f79be742881324bcdf139a5" or
        hash.md5(0, filesize) == "1e2c4cd35987ee217994149675784f9f" or
        hash.md5(0, filesize) == "20417846820741fa84c4571affb40e9c"
}

