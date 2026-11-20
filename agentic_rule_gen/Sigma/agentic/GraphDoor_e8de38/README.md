# GraphDoor

Source: https://securelist.com/operation-shadowcloud-graphdoor/122005/

GraphDoor is a modular backdoor that uses the Microsoft Graph API for command and control, blending its traffic with legitimate enterprise activity. It downloads various plugins for functions like keylogging, taking screenshots, and process listing from SharePoint. The malware also features proxy capabilities, including custom variants based on Erfrp and tunneling over the Ably real-time messaging service.

- **APT_GraphDoor_Nov2026** (yara, medium): The rule uses a combination of highly unique hardcoded strings, API paths, a PDB path, and an RC4 key as strong indicators for GraphDoor.
- **HKTL_Erfrp_GraphDoor_Nov2026** (yara, high): This rule detects a specific build of the Erfrp tool via a unique PDB path found in a GraphDoor-related sample.
- **HKTL_Ably_GraphDoor_Nov2026** (yara, medium): This rule detects a custom proxy plugin based on the Ably real-time messaging service, using a unique log message and other specific strings.
- **GraphDoor_File_Creation_ProgramData** (sigma, high): This rule detects the creation of GraphDoor's base directory `C:\ProgramData\Intel_Log`, a highly specific and unique artifact.
- **GraphDoor_C2_DNS_Queries** (sigma, high): This rule detects DNS queries for a list of domains specifically associated with GraphDoor C2 activities.
- **GraphDoor_C2_Network_Connections** (sigma, high): This rule detects network connections to IP addresses specifically listed as GraphDoor C2 servers.
