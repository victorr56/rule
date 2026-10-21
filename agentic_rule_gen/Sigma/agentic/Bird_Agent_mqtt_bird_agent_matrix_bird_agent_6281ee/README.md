# Bird Agent (mqtt-bird-agent / matrix-bird-agent)

Source: https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/

Toy Ghouls deployed two custom 'bird' backdoors delivered over WinRM: mqtt-bird-agent (using the public HiveMQ MQTT broker as C2, dropped as cplsupport.exe) and matrix-bird-agent (using an attacker-run Element/Matrix server, dropped as wtass.exe). Both install as Windows services, seal their config.toml with ChaCha20-Poly1305 keyed to MachineGuid, and execute received commands via PowerShell or cmd.

- **APT_ToyGhouls_BirdAgent_MQTT_Oct2026** (yara, high): This rule keys on unique banners and version strings for the MQTT variant, with a fallback on TOML config strings.
- **ToyGhoulsBirdAgentServiceInstall** (sigma, high): This rule detects the specific command line used by Bird Agent backdoors to install themselves as a Windows service.
- **ToyGhoulsBirdAgentRegistryActivity** (sigma, high): This rule is based on highly specific registry paths used by the malware for configuration and persistence, which are unlikely to have legitimate use.
- **ToyGhoulsBirdAgentPostExploitation** (sigma, high): This rule detects the specific parent-child process relationship when the Bird Agent backdoor executes commands, which is a strong indicator of compromise.
- **ToyGhoulsBirdAgentConfigFileCreation** (sigma, medium): This rule detects the creation of malware configuration files in specific, non-standard paths, indicating an early stage of the infection.
- **ToyGhoulsBirdAgentServiceCreation** (sigma, high): This rule detects service creation using `sc.exe` with service names that are specific indicators of the Toy Ghouls' Bird Agent malware.
