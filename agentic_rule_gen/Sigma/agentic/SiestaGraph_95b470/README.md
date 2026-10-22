# SiestaGraph

Source: https://www.elastic.co/security-labs/threat-command/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry

SiestaGraph is a .NET backdoor that uses the Microsoft Graph API for command and control. Observed in an intrusion against an ASEAN foreign ministry, it was deployed alongside a modified DoorMe IIS backdoor and ShadowPad. The primary goal was diplomatic intelligence gathering, focusing on the exfiltration of Exchange mailboxes.

- **REF2924_Exchange_Web_Shell_Reconnaissance** (sigma, high): This rule detects w3wp.exe spawning cmd.exe to execute commands from a specific web directory, a strong indicator of web shell activity observed with REF2924.
- **SiestaGraph_Execution_In_Non_Standard_Path** (sigma, high): This rule detects SiestaGraph execution based on a list of highly specific file paths used by the actor to blend in with the system.
- **ShadowPad_Sideloading_via_BDReinit.exe** (sigma, high): This rule detects a highly specific DLL sideloading combination (BDReinit.exe loading log.dll) associated with the actor's use of ShadowPad.
- **REF2924_Sideloading_via_AlarmClock.exe** (sigma, high): This rule detects a highly specific DLL sideloading combination (AlarmClock.exe loading APerfectDayBase.dll) associated with REF2924 activity.
- **REF2924_Cobalt_Strike_C2_Connection** (sigma, high): This rule detects network traffic to a C2 IP address explicitly listed as an IOC for the REF2924 campaign.
