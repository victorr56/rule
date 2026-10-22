# r77

Source: https://www.elastic.co/security-labs/threat-command/elastic-security-labs-steps-through-the-r77-rootkit

r77 is a modular, open-source userland rootkit used to hide the presence of other malware, such as the XMRIG crypto miner. It achieves persistence via scheduled tasks and uses techniques like process hollowing, PPID spoofing, and registry storage for its components and configuration. The rootkit's core module hooks multiple Windows APIs to conceal files, processes, and registry keys from users and security tools.

- **MAL_R77_Rootkit_Oct2026** (yara, medium): The rule keys on a combination of configuration strings and component names associated with the r77 rootkit, requiring three matches to reduce false positives.
- **R77RootkitProcessHollowing** (sigma, high): The combination of `dllhost.exe` and the non-standard `/processid:` argument is a specific indicator of the R77 rootkit's process hollowing technique.
- **R77RootkitRegistryComponentStorage** (sigma, high): The registry keys `$77stager` and `$77config` are highly specific and unique names used by R77 for component and configuration storage.
- **R77RootkitInstallerOrLoaderExecution** (sigma, high): The filenames `$77_Install.exe` and `$77_Loader.exe` are highly specific to the R77 rootkit installer and loader components.
- **R77RootkitNamedPipe** (sigma, high): The named pipe `\\.\pipe\$77childproc64` is a hardcoded and unique artifact used for R77's inter-process communication.
- **R77RootkitC2DomainQuery** (sigma, high): The domain `msupdate.info` is a known C2 indicator specifically associated with the R77 rootkit for payload delivery.
- **R77RootkitC2Communication** (sigma, high): The listed IP addresses are known C2 infrastructure specifically associated with the R77 rootkit.
