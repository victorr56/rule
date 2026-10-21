# Lumma Stealer

Source: https://www.elastic.co/security-labs/threat-command/nightmare-on-0xelm-street

Lumma Stealer, also known as LUMMAC2, is an information stealer that uses a custom ChaCha20 implementation to decrypt its C2 domains. The malware contains distinct code patterns that can be used to locate the crypto setup routine, the decryption function, and the encrypted list of C2 servers. The ChaCha20 context is initialized once and then reused with an incrementing counter for subsequent decryptions.

- **MAL_Lumma_Stealer_ChaCha20_Routines_Oct2026** (yara, high): The rule keys on three distinct, high-specificity code patterns from Lumma Stealer's custom ChaCha20 implementation, making it a reliable indicator for this malware family.
- **Lumma_Stealer_C2_DNS_Query** (sigma, high): This rule keys on a list of C2 domains specific to Lumma Stealer infrastructure.
- **Lumma_Stealer_C2_URL_Access** (sigma, high): This rule keys on a list of full C2 URLs, including paths, specific to Lumma Stealer.
