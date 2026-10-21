# SocGholish

Source: https://www.darktrace.com/blog/socgholish-from-loader-and-c2-activity-to-ransomhub-deployment

SocGholish loader is used for initial access, followed by credential harvesting using WebDAV and malicious SCF files for forced authentication. This access is passed to RansomHub operators who use a Python backdoor and port-hopping C2 communications before deploying ransomware.

- **MAL_SocGholish_CredHarvest_SCF_Oct2026** (yara, medium): The rule keys on the combination of strings defining a malicious SCF file used for NTLM credential theft.
- **SocGholish_Forced_Authentication_SCF_File_Creation** (sigma, high): This rule detects the creation of 'Thumbs.scf', a specific and high-fidelity indicator of the forced authentication technique (T1187) used in this campaign.
- **SocGholish_Forced_Authentication_WebDAV_Access** (sigma, high): This rule combines a specific attacker IP with a specific URI path ('/s') to detect the NTLM hash theft C2 communication with high precision.
- **SocGholish_RansomHub_C2_Domains** (sigma, high): This rule detects DNS queries for a list of domains exclusively used by SocGholish for C2 and distribution in this campaign.
- **SocGholish_RansomHub_C2_IPs** (sigma, high): This rule detects network connections to specific IPs, combining the RansomHub C2 IPs with their observed non-standard ports for higher precision.
