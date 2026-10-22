# LLMjacking

Source: https://www.wiz.io/blog/from-phishing-to-llmjacking

Threat actors use phishing via sponsored search ads to compromise Google Cloud Platform accounts. They then disable security policies, link their own projects to the victim's billing account, and abuse it for large-scale, costly LLM (Gemini) API usage, a technique dubbed 'LLMjacking'.

- **GCP_Org_Policy_IAM_Allowed_Domains_Deletion** (sigma, high): This rule detects a key defensive evasion TTP (deleting a restrictive IAM policy) by matching the specific GCP API method and the exact policy name, making it highly precise.
- **GCP_Suspicious_Role_Assignment** (sigma, medium): This rule detects the assignment of several sensitive GCP roles used by the actor by looking for the IAM policy change action and the specific roles being added.
