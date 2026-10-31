# FAMOUS CHOMILLA

Source: https://www.huntress.com/blog/huntress-dprk-remote-worker-investigation

DPRK-aligned operatives (FAMOUS CHOMILLA/CHOLLIMA) fraudulently gain remote employment by posing as legitimate workers using stolen or fake identities. They leverage VPNs, proxies, and hardware KVM devices like PiKVM to obscure their location and maintain access. This activity aims to generate revenue for the North Korean regime, exfiltrate data, or deploy malware.

- **APT_DPRK_FamousChomilla_Activity_Artifacts_Oct2026** (yara, medium): Keys on specific URL parameters for the VDO.Ninja service and a combination of unique typos and names from fraudulent documents associated with FAMOUS CHOMILLA activity.
- **DPRK_FAMOUS_CHOMILLA_Hardware_Device_Installation** (sigma, high): This rule detects the registry artifacts of specific hardware (PiKVM, Guermok) used by the actor for KVM/video capture.
- **DPRK_FAMOUS_CHOMILLA_VDO_Ninja_Screen_Sharing** (sigma, high): This rule detects a highly specific URL structure used by the actor for screen sharing via the VDO.Ninja service.
- **DPRK_FAMOUS_CHOMILLA_File_Drop_In_C_asset** (sigma, medium): This rule precisely detects a browser writing to a specific, unusual folder path (`C:\asset\`) used by the actor.
