# ICEDID

Source: https://www.elastic.co/security-labs/blog/unpacking-icedid

ICEDID is a banking trojan that uses a Gzip-masquerading variant for initial payload delivery. The malware unpacks an encrypted core binary and configuration file, which contains C2 domains and a specific beacon URI, to deploy its primary modules like browser hooking payloads.

- **IcedidCoreBinaryDrop** (sigma, high): This rule keys on the highly specific file path `UponBetter\license.dat` used by ICEDID to store its core binary.
