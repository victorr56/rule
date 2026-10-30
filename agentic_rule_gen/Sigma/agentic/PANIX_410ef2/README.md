# PANIX

Source: https://www.elastic.co/security-labs/threat-command/continuation-on-persistence-mechanisms

PANIX is a research tool demonstrating Linux persistence techniques. It can establish persistence via LD_PRELOAD hijacking, loadable kernel modules (LKM), web shells (PHP/Python), and by backdooring system user accounts for SSH access.

- **HKTL_PANIX_LKM_Oct2026** (yara, high): This rule keys on highly unique module metadata and a specific thread name embedded in the PANIX LKM.
- **HKTL_PANIX_Tool_Oct2026** (yara, high): This rule keys on unique output strings and code fragments from the main PANIX tool binary.
- **PANIX_Linux_Backdoor_Shell_Creation** (sigma, high): This rule detects a highly specific command line used by PANIX to create a masquerading shell with a trailing space in its name.
- **PANIX_Linux_Passwd_Modification_For_Backdoor** (sigma, high): This rule detects the unique sed command PANIX uses to modify `/etc/passwd` to point a system user to a backdoored shell.
- **PANIX_Linux_SSH_Key_Persistence_For_System_User** (sigma, high): This rule keys on the creation of an SSH `authorized_keys` file for the `news` system user, an extremely suspicious act of persistence.
- **PANIX_Linux_LKM_Persistence** (sigma, medium): This rule detects the creation of a specific and non-standard kernel module configuration file used by PANIX for persistence.
- **PANIX_Linux_Web_Shell_Access** (sigma, medium): This rule detects HTTP requests for URI paths that are specific to the web shells deployed by the PANIX tool.
