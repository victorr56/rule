# Miasma

Source: https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages

Miasma is a supply chain attack that targets Red Hat-scoped npm packages. Malicious preinstall scripts execute an obfuscated JavaScript payload, derived from the open-source Mini Shai-Hulud malware, to steal cloud identities, developer credentials, and other secrets from CI/CD environments and developer workstations.

- **MiasmaPayloadExecution** (sigma, high): This rule detects the specific command line `bun run _index.js` used to execute the Miasma payload. The combination of the `bun` runtime and the specific script name `_index.js` is distinctive.
