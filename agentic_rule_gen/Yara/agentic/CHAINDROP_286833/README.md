# CHAINDROP

Source: https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain

CHAINDROP is a self-propagating npm supply-chain worm that trojanizes packages via a package.json preinstall hook running a setup.mjs dropper, which fetches the bun runtime to execute the heavily obfuscated Math_Symbol.js/math_init.js credential stealer. It harvests developer, cloud, and AI-tooling credentials, encrypts them with AES-256-GCM plus an RSA-wrapped key, and retrieves rotating C2 endpoints from an Ethereum smart contract or GitHub dead-drop.

- **MAL_CHAINDROP_Package_Json_Oct2026** (yara, high): This rule detects the malicious `package.json` configuration used by CHAINDROP. It keys on the combination of the `scripts` object key, the `preinstall` hook name, and the specific malicious command `node setup.mjs`, all confirmed to be in the file via report figures.
- **CHAINDROP_Payload_Execution_With_Bun** (sigma, high): This rule detects the execution of the main CHAINDROP payload by pairing the `bun` runtime with the specific, unique payload filenames `Math_Symbol.js` and `math_init.js`.
