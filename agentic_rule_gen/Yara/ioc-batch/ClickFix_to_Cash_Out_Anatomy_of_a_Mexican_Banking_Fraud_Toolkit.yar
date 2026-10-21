// ClickFix to Cash-Out: Anatomy of a Mexican Banking-Fraud Toolkit
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/mexican-banking-fraud-scmbanker-ref6045

import "hash"

rule IOC_ClickFix_to_Cash_Out_Anatomy_of_a_Mexican_Banking_Fraud_Toolkit_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: ClickFix to Cash-Out: Anatomy of a Mexican Banking-Fraud Toolkit. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/mexican-banking-fraud-scmbanker-ref6045"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "b30cb0aa977aacdab94d2ef503186c8f0b2fc10d7cf0d7c7c0ada70c127dc7e8" or
        hash.sha256(0, filesize) == "554f1aefeb698995501751328c2f9fe93f02a680679fba3dd15f1ed93d46bf1b" or
        hash.sha256(0, filesize) == "ff3555154e91e42490cc722b6c7f3c4c91654b7ef53a35d0719ffb89accf1b27" or
        hash.sha256(0, filesize) == "526287a40aad1b218228cdd1f459ad3b93f858585048347644d597c6ab19515a" or
        hash.sha256(0, filesize) == "685d29ce8a550feb3a9e1d1c5926ec5e927615cf34aab62c108a812a1eb6737c" or
        hash.sha256(0, filesize) == "8c87ea94401fa97d3743a87604e088d1a29c7b06cf9673623941a42da68452a6" or
        hash.sha256(0, filesize) == "6dcd7fdd5e088d98d861cbd1cb74a7b83ae5508f4dbb617413bcbe7fbc8a82e2" or
        hash.sha256(0, filesize) == "4d9c160ebb44507b11f0e6421f691900284f25b5530a23d9fd50de0ae01663ca" or
        hash.sha256(0, filesize) == "0315d4a7bc14654ad66d4c2b98920b92ca18cbc231b3ce5fba1fcac70b828e19" or
        hash.sha256(0, filesize) == "5d17645548a44fe39d3cc816ffa3933321c1eb8b08a8f4348e3cd82f25112c81" or
        hash.sha256(0, filesize) == "566f4bfdfea54129b8528d50cae187a9030e2f2787749add4b0db22ac35ea581" or
        hash.sha256(0, filesize) == "882d582e85d5bb7abbdde791a2d52e3b1bb7dd7f79c20318ce64b74249221fdb" or
        hash.sha256(0, filesize) == "eea08fbf3720d638af1d313d3ce369708b77d7891379d5c5871dd7f36667ed0c" or
        hash.sha256(0, filesize) == "70140aa236d630a7d5ed08be3dafcccea9a8b0eec6dadf8c1cf1b96d8f608609" or
        hash.sha256(0, filesize) == "6c8ba7127a83431432e85946976c18bb3f3e9bf9def68aae572cd1d9d73604c7" or
        hash.sha256(0, filesize) == "81a4512db985359ed361755da58a1177b07632b5aee951c68a6ace54f4d0534b" or
        hash.sha256(0, filesize) == "3d9015429d65276869ceb9c91f10d6474b1098042db75949c49b9f1682c1f3ae" or
        hash.sha256(0, filesize) == "5bc85b604eb37ffa1e67c57f4744b55ef876a1ab442e2a2440550ef0922aeec7" or
        hash.sha256(0, filesize) == "30ff24faad80184bb43660a8bd317df99a8d09d31bae3b446aaa876543f2620f" or
        hash.sha256(0, filesize) == "4b7b35b921d7615b7a82a42c379560d1b0c5a74c81311a269874195ba2744f2d" or
        hash.sha256(0, filesize) == "5c7ab9e90b05804d07e9d803f85462bc1a44d0726256bad28219984ee2b5772f" or
        hash.sha256(0, filesize) == "32d981b3e7c36aa7030cfd9ee412bff742e00b36c39c80634b2681f89de4a487" or
        hash.sha256(0, filesize) == "cd7b179dd98848a02b9a1d4ebfeee26cdbb317b4ad53eb50786e18515b0cf804" or
        hash.sha256(0, filesize) == "345e8a90b7b762b065333cd068811d88086d157be713d89bdf200c927645f3d8" or
        hash.sha256(0, filesize) == "0ec9b518f84b6bdc0e843b89fa755522ec67db862414ad16bdcaa8c2be25485c" or
        hash.sha256(0, filesize) == "26f906a2a4276b1968a8ce956a7b342aa9bc26f60d32c14668223877f569fb3f" or
        hash.sha256(0, filesize) == "13bfd0f695cea1d6ae570a7ca056ffe930467be73a26f29f95209618f383bd2d"
}

