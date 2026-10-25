# United Islamic Cyber Force

Source: https://www.group-ib.com/blog/uicf/

United Islamic Cyber Force (UICF) is a pro-Islamic hacktivist collective known for DDoS attacks and website defacements against government, media, and business entities. The group uses custom web shells, leaves slogans and contact info on compromised sites, and uses social media to publicize its activities.

- **WEBSHELL_UnitedIslamicCyberForce_Defacement_Oct2026** (yara, medium): This rule detects defacement pages by combining the group's name and various campaign hashtags.
- **UICF_Domain_Query** (sigma, medium): This rule detects DNS lookups for a list of domains specifically registered or used by members of the UICF group.
