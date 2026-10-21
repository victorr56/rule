# Komari

Source: https://www.huntress.com/blog/komari-c2-agent-abuse

A threat actor abused Komari, a legitimate Go-based open-source monitoring tool, as a C2 agent. After gaining access via stolen VPN credentials, the actor installed Komari as a persistent SYSTEM-level service named "Windows Update Service" using NSSM. Komari provides arbitrary command execution, an interactive reverse shell, and network probing capabilities out-of-the-box via a persistent WebSocket.

- **HKTL_Komari_Agent_Oct2026** (yara, medium): The rule detects the Komari open-source agent based on a combination of its unique API paths and command-line flags. All artifacts originate from the tool itself, mandating an HKTL rule.
- **Tool_Komari_Install_Via_Powershell** (sigma, high): This rule keys on the specific GitHub URL and execution command used to install the Komari agent, as seen in the threat profile.
- **Tool_Komari_Agent_Service_Configuration** (sigma, high): This rule keys on the unique command-line flags `-e` and `-t` used to configure the Komari agent's C2 endpoint and token via a service's registry parameters.
- **Tool_Impacket_Smbexec_RDP_Enablement** (sigma, high): This rule keys on the characteristic command used by Impacket's smbexec to enable RDP, which notably redirects command output to a hidden localhost admin share.
- **Tool_Komari_Agent_Execution** (sigma, high): This rule keys on the execution of the Komari agent from its default, specific installation path in the System32 directory.
- **Tool_Komari_C2_API_Paths** (sigma, high): This rule keys on the specific and unique API URI paths used by the Komari agent for various C2 functions like reporting and tasking.
- **Komari_Persistence_Via_Masqueraded_Service** (sigma, high): This rule keys on the combination of the specific masqueraded service name "Windows Update Service" and the komari-agent.exe executable path in the service's registry parameters.
