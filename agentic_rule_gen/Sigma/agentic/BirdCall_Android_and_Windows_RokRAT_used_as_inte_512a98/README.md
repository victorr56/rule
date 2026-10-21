# BirdCall (Android and Windows; RokRAT used as intermediate backdoor)

Source: https://www.welivesecurity.com/en/eset-research/rigged-game-scarcruft-compromises-gaming-platform-supply-chain-attack/

ScarCruft compromised the Yanbian gaming platform sqgame, trojanizing Android games and a Windows mono.dll update to deliver the BirdCall backdoor via Android BirdCall and a RokRAT downloader chain. Android BirdCall (internally 'zhuagou') uses cloud storage drives, primarily Zoho WorkDrive over HTTPS, for C2, steals contacts, SMS, call logs, documents, media and private keys, and can take screenshots and record audio. Detection can focus on the trojanized APK/DLL hashes, the AndroidManifest entry activities, the JSON config keys and the command magic DWORD 0x2A7B4C33.

- **ScarCruft_BirdCall_C2_via_Zoho_WorkDrive** (sigma, high): This rule detects highly specific Zoho WorkDrive client IDs embedded in C2 URLs used by ScarCruft's BirdCall malware.
- **ScarCruft_Trojan_Download_from_Compromised_SQGame_Site** (sigma, high): This rule detects the download of specific trojanized files by their unique paths from the compromised game server.
- **ScarCruft_Staging_Domain_Queries_SQGame** (sigma, medium): This rule detects DNS queries for a list of domains compromised by ScarCruft to stage malware components.
- **ScarCruft_Staging_IP_Connections_SQGame** (sigma, medium): This rule detects network connections to a list of IP addresses used by ScarCruft to stage malware components.
