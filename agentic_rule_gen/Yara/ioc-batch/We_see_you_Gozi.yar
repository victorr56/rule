// We see you, Gozi
// Source: group-ib | https://www.group-ib.com/blog/gozi-latest-ttps/

import "hash"

rule IOC_We_see_you_Gozi_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: We see you, Gozi. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/gozi-latest-ttps/"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "904ca32cb62dc94b61092f80fa78c5bc97d0a5394fa03438aeec85ed87ab763e" or
        hash.sha256(0, filesize) == "360703b2b2c324dde72dcd0651251c9e882e245c22d6b7e8c3163ed34ddb62b9" or
        hash.sha256(0, filesize) == "90660936cb65e0f929f32615ef400e0d0f80232f7f2003778c27e28b84468666" or
        hash.sha256(0, filesize) == "3ef96cfb78cb553943ce591c985fdc793d2acf342a536b90d0f9ef72bdb15ecd" or
        hash.sha256(0, filesize) == "011f6f038b1398c03ae15d3cb81412d32ad0ad554dfbb5d38fae78577fb2b777" or
        hash.md5(0, filesize) == "a0bb2d133b174436a9d4cce527fb78d7" or
        hash.md5(0, filesize) == "63fdefb66fd14dc92a7d1f773d6f619b" or
        hash.md5(0, filesize) == "2b348e0106f20c14615212d7eff0db88" or
        hash.md5(0, filesize) == "1c847fed91ba95a65ff0160757c5b187" or
        hash.md5(0, filesize) == "d3d4b79106465363155a3f4f6c1a5e05" or
        hash.sha1(0, filesize) == "8e72e0115e01f32a2f72d1f31c3e641c6b66ab45" or
        hash.sha1(0, filesize) == "0a96e7edc7a7e4b805f29691a0d39e21453f9eb0" or
        hash.sha1(0, filesize) == "4dcd93a1cfd7f630c5fe71f5b31b298582b8bd39" or
        hash.sha1(0, filesize) == "17ca3fa3bec22507798b5b21906559134f4cd3aa" or
        hash.sha1(0, filesize) == "9e978ad8c58fbbe59b470e26709687023161a5b8"
}

