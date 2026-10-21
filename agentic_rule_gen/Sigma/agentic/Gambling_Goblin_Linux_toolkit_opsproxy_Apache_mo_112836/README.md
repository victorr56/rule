# Gambling Goblin Linux toolkit (opsproxy Apache module, DownPro, ChUser, PasswordHarvester, AlphaAgent, oRAT, cam-agent)

Source: https://research.checkpoint.com/2026/gaming-the-system-how-a-chinese-speaking-actor-turned-brazilian-government-sites-into-an-seo-weapon/

Gambling Goblin is a Chinese-speaking cybercrime cluster, tied to Earth Berberoka, that compromises Brazilian .gov.br web servers and installs custom Apache modules (opsproxy.c and a second RC4-configured filter module) which reverse-proxy selected paths to gambling and fake app-store pages while stripping CSP headers to hijack search traffic. The Linux toolkit includes the DownPro downloader, the setuid ChUser backdoor, the 3snake-based PasswordHarvester, the modular AlphaAgent backdoor with gRPC/DNS channels, oRAT, an SSH brute-forcer and Chinese-commented recon scripts, all masqueraded as kernel threads or legitimate system services.

- **APT_GamblingGoblin_AlphaAgent_Oct2026** (yara, high): The rule keys on a unique, high-entropy 14-byte salt hardcoded in the AlphaAgent backdoor.
- **APT_GamblingGoblin_cam_agent_Oct2026** (yara, high): The rule uses several long, highly specific strings from the 'cam-agent' Go binary, any one of which can trigger a match.
- **APT_GamblingGoblin_Linux_Toolkit_Oct2026** (yara, high): The rule covers multiple tools (PasswordHarvester, DownPro, ChUser) using strong, unique strings from each component.
- **GamblingGoblin_PasswordHarvester_Execution** (sigma, high): This rule detects the execution of the PasswordHarvester tool by combining its unique installation path and the highly specific, profane argument string.
- **GamblingGoblin_oRAT_Persistence** (sigma, high): This rule detects a specific `systemctl` command used by the actor to enable a persistence service for oRAT, which masquerades as `xtables-addons`.
- **GamblingGoblin_DownPro_Execution_Chain** (sigma, high): This rule detects the specific process lineage where a masquerading DownPro binary launches another payload using a characteristic command-line flag.
- **GamblingGoblin_AlphaAgent_Execution** (sigma, high): This rule detects process execution from a list of highly specific and non-standard file paths used by the AlphaAgent backdoor for masquerading.
- **GamblingGoblin_C2_Domains** (sigma, medium): This rule identifies DNS lookups for a list of domains specifically associated with the Gambling Goblin threat actor's infrastructure.
- **GamblingGoblin_oRAT_Execution** (sigma, high): This rule detects the oRAT backdoor by combining its true executable path (`xtables-addons`) with the specific command line (`sshd: root@pts/0`) it uses to masquerade.
