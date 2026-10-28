# DragonForce

Source: https://www.huntress.com/blog/citrixbleed-2-dragonforce-ransomware

An Initial Access Broker cluster (STAC3725) exploits CitrixBleed 2 (CVE-2025-5777) for initial access to NetScaler appliances. The actors then use a custom registry symlink-based LPE tool to create rogue admin accounts, establish persistence with legitimate RMMs like ScreenConnect, and ultimately deploy DragonForce ransomware.

- **APT_STAC3725_LPE_Tool_Oct2026** (yara, medium): The rule detects an LPE tool used by STAC3725. It keys on a unique cleanup string, or a combination of supporting strings including a password, a typo, a registry GUID, and a specific registry path. These combinations are unique to this tool.
- **STAC3725_DragonForce_Registry_Symlink_LPE** (sigma, high): This rule detects a highly specific registry modification TTP used by the actor for privilege escalation.
- **DragonForce_ScreenConnect_Execution_by_Instance_ID** (sigma, high): This rule keys on the combination of the ScreenConnect client process and specific instance IDs used by the actor.
- **STAC3725_DragonForce_User_Account_Creation** (sigma, high): This rule detects the creation of local users via net.exe using specific usernames observed in DragonForce attacks.
- **STAC3725_RMM_C2_Domains** (sigma, high): This rule detects DNS queries for a list of specific C2 domains associated with the actor's RMM tool infrastructure.
- **STAC3725_LPE_Trigger_via_AppMgmt_Service** (sigma, medium): This rule detects a specific command line used by the actor to trigger a privilege escalation technique.
