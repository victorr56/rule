# SNS Sender

Source: https://www.elastic.co/security-labs/threat-command/aws-sns-abuse

Adversaries abuse AWS Simple Notification Service (SNS) for data exfiltration and phishing/smishing campaigns. For exfiltration, they create an SNS topic, subscribe an external email address, and publish stolen data to it. For phishing, tools like 'SNS Sender' are used to send bulk SMS messages from compromised AWS accounts with production messaging permissions.

- **AWS_SNS_Topic_Creation_via_CLI** (sigma, high): This rule detects the `aws sns create-topic` command, a specific preparatory action for AWS SNS-based exfiltration.
- **AWS_SNS_Subscription_to_Email_via_CLI** (sigma, high): This rule detects the `aws sns subscribe ... --protocol email` command, a specific method to configure an exfiltration channel.
- **AWS_SNS_Data_Publication_via_CLI** (sigma, high): This rule detects the `aws sns publish --message` command, the direct execution of data exfiltration via AWS SNS.
- **Credential_Aggregation_via_Cat_Command** (sigma, medium): This rule detects a `cat` command line that combines multiple specific credential file paths into a suspiciously named temporary file.
