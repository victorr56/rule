# CastleLoader

Source: https://redcanary.com/blog/threat-intelligence/intelligence-insights-july-2026/

CastleLoader (aka CastleBot) is a Windows malware loader distributed through paste-and-run (fake CAPTCHA/ClickFix) campaigns that use caret-obfuscated cmd.exe and finger.exe command lines to fetch batch and Python code. It uses a Bring-Your-Own-Interpreter chain (portable CPython/IronPython) with Base64/zlib/UTF-32 triple-encoded shellcode that injects the RC4-decrypted loader into python.exe, then beacons to C2 for configuration and payloads such as NetSupport Manager, CastleRAT, and a .NET infostealer.

- **MAL_CastleLoader_Oct2026** (yara, medium): The rule keys on a unique marker string and a full C2 URL, both confirmed to be in the binary.
- **CastleLoader_Finger_Execution** (sigma, high): This rule keys on the highly specific and obfuscated command line using finger.exe to fetch and execute commands.
- **CastleLoader_Obfuscated_cURL_Execution** (sigma, high): This rule detects a complex, obfuscated command line; the combination of `where` with wildcards and a caret-obfuscated URL is highly distinctive.
- **CastleLoader_Python_Shellcode_Loader** (sigma, high): This rule targets a Python one-liner used to decode and execute shellcode; the combination of `subprocess`, `base64`, `zlib`, and `z.decompress(b.b64decode(` is characteristic.
- **CastleLoader_Portable_IronPython_Execution** (sigma, high): This rule detects execution of a randomly named executable from a portable IronPython path using a precise regular expression.
- **CastleLoader_C2_Domains** (sigma, high): This rule detects DNS queries for a list of known high-confidence CastleLoader C2 and lure domains.
