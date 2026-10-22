# Dark Pink

Source: https://www.group-ib.com/blog/dark-pink-apt/

Dark Pink is a new APT group targeting government and military entities, primarily in the APAC region, for espionage. They employ a custom toolkit including TelePowerBot, KamiKakaBot, and Cucky/Ctealer stealers, delivered via spear-phishing with ISO images. The malware uniquely uses Telegram for C2, establishes persistence by changing default file associations, and propagates through USB infection.

- **DarkPinkPersistenceViaForfiles** (sigma, high): This rule keys on a highly specific and unusual command line for `forfiles.exe` used for persistence by Dark Pink.
- **DarkPinkUACBypassViaNETLUA** (sigma, high): This rule keys on the unique `[NETLUA.Main]::BypassUAC` method call within a PowerShell script, specific to Dark Pink's toolset.
- **DarkPinkPersistenceViaWinlogonShellAndMSBuild** (sigma, high): This rule keys on the modification of the `Winlogon\Shell` key to execute `MSBuild.exe`, a specific persistence TTP used by Dark Pink.
- **DarkPinkMicrosoftIdleScheduledTask** (sigma, medium): This rule keys on the command line used to create a scheduled task with a specific name ("Microsoft Idle") used by Dark Pink.
