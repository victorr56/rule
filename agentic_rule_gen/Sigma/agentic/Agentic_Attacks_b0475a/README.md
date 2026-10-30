# Agentic Attacks

Source: https://www.wiz.io/blog/the-rise-of-agentic-attacks

An emerging class of attacks where AI agents or agentic frameworks (e.g., Hermes, ARTEX) automate intrusion activities. These attacks are characterized by machine-paced iteration, adaptive execution, and verbose tooling containing natural-language comments. They often employ a breadth-first methodology, resulting in noisy but rapid compromise of cloud-native environments.

- **MAL_Agentic_Attack_Patterns_Oct2026** (yara, high): The rule keys on highly specific natural-language comments and API paths that document the thought process of automated agentic attacks, making them strong indicators.
- **FlowiseUnauthenticatedRCEViaCustomFunction** (sigma, high): This rule detects a highly specific combination of a URI path and an HTTP header used to achieve unauthenticated RCE in Flowise.
- **AgenticAttackRabbitMQAPIManipulation** (sigma, high): This rule keys on highly unusual and self-incriminating URI paths used to manipulate RabbitMQ, making it a high-confidence indicator.
- **HiddenPythonScriptInShm** (sigma, high): This rule detects a file created at a highly specific and suspicious path combining a temporary file system (`/dev/shm`) and a hidden directory.
- **AWSTokenTheftViaIMDSv2** (sigma, high): This rule detects a specific `curl` command line pattern that is characteristic of AWS IMDSv2 token theft attempts.
- **KubernetesSecretDumpWithCurl** (sigma, high): This rule detects a specific `curl` command line that combines multiple indicators of an attempt to dump Kubernetes secrets using a default token.
