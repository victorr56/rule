# GHOSTPULSE

Source: https://www.elastic.co/security-labs/threat-command/tricks-and-treats

GHOSTPULSE, also known as HIJACKLOADER, is a loader that has evolved to embed its encrypted configuration and payload within the pixel structure of a PNG image, moving away from its previous IDAT chunk method. The malware locates its config by iterating through the image's RGB data in 16-byte blocks, validating a CRC32 hash to find the structure containing the payload, size, and a 4-byte XOR key for decryption.

- **MAL_GHOSTPULSE_Loader_Oct2026** (yara, medium): The rule uses three distinct and sufficiently long code patterns that are characteristic of the GHOSTPULSE loader.
