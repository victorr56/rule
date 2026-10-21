// Stealthy Attributes of Lazarus APT Group: Evading Detection with Extended Attributes
// Source: group-ib | https://www.group-ib.com/blog/stealthy-attributes-of-apt-lazarus/

import "hash"

rule IOC_Stealthy_Attributes_of_Lazarus_APT_Group_Evading_Detection_with_Extended_Attributes_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Stealthy Attributes of Lazarus APT Group: Evading Detection with Extended Attributes. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/stealthy-attributes-of-apt-lazarus/"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "7464850d7d6891418c503d0e1732812d7703d6c1fd5cf3c821f3c202786f9422" or
        hash.sha256(0, filesize) == "f3e6e8df132155daf1d428dff61f0ca53ecd02015a0a0bbe1ad237519ab3cb58" or
        hash.sha256(0, filesize) == "e87177e07ab9651b48664c3d22334248e012e8a2bab02f65c93fedd79af0a74f" or
        hash.sha256(0, filesize) == "a4cab67569d0b35c249dc536fb25dabdc12839ed4e945c59ec826c0a241b792a"
}

