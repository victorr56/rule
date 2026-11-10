# Qubole Trust Abuse

Source: https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild

An unknown threat actor leveraged compromised IAM credentials from Qubole's AWS account to assume roles in customer environments. The actor performed broad discovery, harvested credentials, and exfiltrated S3 data opportunistically. A related bootable Linux ISO, sso_agent.iso, was also discovered, designed to establish C2 on victim machines.

- **qubole_trust_abuse_c2_network_connection** (sigma, high): This rule detects connections to high-confidence C2 IPs and a specific C2 port from the report.
