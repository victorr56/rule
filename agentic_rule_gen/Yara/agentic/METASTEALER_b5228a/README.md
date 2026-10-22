# METASTEALER

Source: https://www.elastic.co/security-labs/threat-command/globally-distributed-stealers

METASTEALER is a .NET-based info-stealer derived from RedLine, first seen in 2022. It uses the AGILE.NET obfuscator for control-flow obfuscation via proxy calls and dynamic method resolution. Its configuration strings, including C2 details, are encrypted with a multi-step process involving Base64, XOR, and AES CBC.

- **MAL_METASTEALER_DotNet_Oct2026** (yara, medium): The rule keys on specific obfuscator-generated strings and configuration-related names to identify METASTEALER.
