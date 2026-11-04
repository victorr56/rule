# OfferLoader

Source: https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/

A financially-motivated campaign distributes trojanized Inno Setup installers disguised as cracked software or games. These installers use a distinct C2 callback pattern with parameters 'd=inno' and 'r=offer_execution' to deliver multiple monetization payloads. Confirmed payloads include WorldProxyPool proxyware, CharityEngine/BOINC for resource hijacking, and adware, with persistence established via scheduled tasks.

- **MAL_OfferLoader_Nov2026** (yara, medium): This rule keys on a highly specific error string or combinations of C2 parameters, domains, and payload filenames associated with OfferLoader.
- **OfferLoaderC2CallbackPattern** (sigma, high): This rule keys on the highly specific URI parameters `d=inno` and `r=offer_execution` used in OfferLoader C2 callbacks.
- **OfferLoaderStagedPayloadExecution** (sigma, high): This rule keys on the combination of the specific temporary path pattern (`is-*.tmp`) and a regex of payload names (`eld*.exe`, etc).
- **OfferLoaderWorldProxyPoolPersistence** (sigma, high): This rule keys on the creation of scheduled tasks via schtasks.exe with the unique name prefix `WorldProxyPool`.
- **OfferLoaderC2Domains** (sigma, high): This rule keys on a list of domains exclusively used by the OfferLoader campaign for C2 communications.
- **OfferLoaderAdvancedWindowsManagerAdwareExecution** (sigma, high): This rule keys on the execution of a specific adware payload from its unique installation directory in AppData.
