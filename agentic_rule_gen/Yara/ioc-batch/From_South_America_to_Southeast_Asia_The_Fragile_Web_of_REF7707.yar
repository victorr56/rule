// From South America to Southeast Asia: The Fragile Web of REF7707
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/fragile-web-ref7707

import "hash"

rule IOC_From_South_America_to_Southeast_Asia_The_Fragile_Web_of_REF7707_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: From South America to Southeast Asia: The Fragile Web of REF7707. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/fragile-web-ref7707"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "08331f33d196ced23bb568689c950b39ff7734b7461d9501c404e2b1dc298cc1" or
        hash.sha256(0, filesize) == "cffca467b6ff4dee8391c68650a53f4f3828a0b5a31a9aa501d2272b683205f9" or
        hash.sha256(0, filesize) == "f45661ea4959a944ca2917454d1314546cc0c88537479e00550eef05bed5b1b9" or
        hash.sha256(0, filesize) == "41a3a518cc8abad677bb2723e05e2f052509a6f33ea75f32bd6603c96b721081" or
        hash.sha256(0, filesize) == "d9fc1cab72d857b1e4852d414862ed8eab1d42960c1fd643985d352c148a6461" or
        hash.sha256(0, filesize) == "f29779049f1fc2d45e43d866a845c45dc9aed6c2d9bbf99a8b1bdacfac2d52f2" or
        hash.sha256(0, filesize) == "17b2c6723c11348ab438891bc52d0b29f38fc435c6ba091d4464f9f2a1b926e0" or
        hash.sha256(0, filesize) == "20508edac0ca872b7977d1d2b04425aaa999ecf0b8d362c0400abb58bd686f92" or
        hash.sha256(0, filesize) == "33f3a8ef2c5fbd45030385b634e40eaa264acbaeb7be851cbf04b62bbe575e75" or
        hash.sha256(0, filesize) == "41141e3bdde2a7aebf329ec546745149144eff584b7fe878da7a2ad8391017b9" or
        hash.sha256(0, filesize) == "49e383ab6d092ba40e12a255e37ba7997f26239f82bebcd28efaa428254d30e1" or
        hash.sha256(0, filesize) == "5e3dbfd543909ff09e343339e4e64f78c874641b4fe9d68367c4d1024fe79249" or
        hash.sha256(0, filesize) == "7cd14d3e564a68434e3b705db41bddeb51dbb7d5425fd901c5ec904dbb7b6af0" or
        hash.sha256(0, filesize) == "842d6ddb7b26fdb1656235293ebf77c683608f8f312ed917074b30fbd5e8b43d" or
        hash.sha256(0, filesize) == "f90420847e1f2378ac8c52463038724533a9183f02ce9ad025a6a10fd4327f12"
}

