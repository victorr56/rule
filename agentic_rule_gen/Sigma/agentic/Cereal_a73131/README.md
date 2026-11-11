# Cereal

Source: https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/

Turla's Cereal is a modular .NET toolset designed for long-term espionage against Microsoft Exchange servers. It uses the compromised server as its C&C infrastructure, listening on paths that blend with legitimate traffic. The malware employs advanced techniques like native code execution from .NET assemblies and in-memory hooking of Exchange transport agents to evade detection.

- **Turla_CerealLoader_in_NET_Native_Image_Cache** (sigma, high): The rule detects a specific malicious Exchange DLL in the .NET cache, filtering for known legitimate processes that modify this location.
- **Turla_CerealLoader_Masquerading_as_wbemcomn.dll** (sigma, high): The rule detects the modification of a specific system DLL, filtering out legitimate system update and installation processes.
