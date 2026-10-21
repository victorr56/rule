# Amadey, Stealc

Source: https://www.welivesecurity.com/en/eset-research/eset-takes-part-operation-endgame-disrupt-amadey-stealc/

Amadey is a modular malware loader and Stealc a MaaS infostealer, both sold as services with affiliate-run C&C panels; ESET clustered hundreds of samples using embedded RC4 keys, C&C URL random paths, and build identifiers ('sd' for Amadey, 'build' for Stealc) to support Operation Endgame. Amadey beacons over HTTP with an initial 'st=s' POST, receives RC4-encrypted task lists delimited by <c> and <d>, and can deploy stealer, clipper, hVNC and proxy modules; Stealc speaks RC4-encrypted JSON containing build/hwid, an access_token session key and steal_* configuration flags. Both families check the victim's keyboard layout and abort on CIS-country locales.

- **MAL_Amadey_Loader_Oct2026** (yara, high): The rule keys on unique Amadey C&C URI paths from the report, which are strong indicators. It also uses a combination of C&C domains and protocol artifacts for broader but still specific detection.
- **MAL_Stealc_Infostealer_Oct2026** (yara, high): The rule detects Stealc by requiring a combination of highly characteristic configuration strings like "steal_steam" and "parse_cookies", which are unlikely to co-occur in unrelated software.
- **Amadey_C2_URI_Paths** (sigma, high): This rule keys on a list of highly specific and unique URI paths used by Amadey C2 infrastructure.
- **Amadey_C2_DNS_Queries** (sigma, high): This rule keys on a list of specific domains and hostnames used exclusively by Amadey C2 servers.
- **Amadey_Stealc_C2_IP_Connections** (sigma, high): This rule keys on a list of specific IP addresses used by Amadey and Stealc C2, filtering out shared infrastructure.
