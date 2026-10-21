# Investigating suspicious AI workflows in Microsoft Entra Agent ID: Assistive agents

Source: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/

This report investigates suspicious activity involving a Microsoft Entra Agent ID assistive agent (on-behalf-of flow), where an agent identity sent a suspicious email on behalf of a human user. It demonstrates log correlation across Exchange, Microsoft Graph, and non-interactive sign-in logs to build a minimum viable story and provides detection guidance based on the Agent.agentType/Agent.agentSubjectType fields, the access_agent scope, and anomalous user-agent strings.

- **EntraAgentIdAccessAgentScopeConsentRequest** (sigma, medium): Keys on the Entra authorize endpoint plus the distinctive access_agent scope string from the consent URI, which is specific to Entra Agent ID on-behalf-of agent flows rather than generic login traffic.
