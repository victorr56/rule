# CoffeeLoader

Source: https://securelist.com/retadup-delivers-coffeeloader/121908/

CoffeeLoader is a downloader delivered by the revived Retadup USB worm. Its new variant uses a custom packer, Armoury, which leverages OpenGL for decryption. It achieves persistence via Run registry keys and injects into various system processes to download and execute further payloads.

- **MAL_Win_CoffeeLoader_Nov2026** (yara, high): This rule keys on a unique public key, cryptographic keys, and a specific URI path found in CoffeeLoader samples, ensuring high precision.
- **MAL_Win_Armoury_Packer_Nov2026** (yara, high): This rule keys on unique OpenCL and GLSL code fragments embedded in the Armoury packer, which are highly unlikely to appear in legitimate software.
- **MAL_Win_Retadup_Nov2026** (yara, medium): This rule keys on a unique C2 URI path containing a long hex identifier and a combination of other network and file-based indicators for the Retadup worm.
- **Win_Susp_CoffeeLoader_Rundll32_Execution** (sigma, high): This rule detects the specific command line pattern of CoffeeLoader execution, which is highly distinctive.
- **Win_Susp_CoffeeLoader_Persistence** (sigma, high): This rule targets the unique command structure used by CoffeeLoader for persistence in the registry.
- **Proxy_Retadup_C2_URI** (sigma, high): This rule keys on the highly specific and unique URI structure used by Retadup for C2 communications.
- **Win_Susp_CoffeeLoader_Autorun_Hide** (sigma, medium): This rule detects a defense evasion technique by matching a patterned registry value name with its corresponding data.
