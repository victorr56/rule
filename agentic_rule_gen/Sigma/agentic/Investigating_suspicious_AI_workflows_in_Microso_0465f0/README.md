# Investigating suspicious AI workflows in Microsoft Entra Agent ID: Agent’s user account

Source: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-teams/

This report walks through investigating a suspicious Microsoft Teams message sent by an Entra Agent ID agent user, correlating Purview MicrosoftTeams MessageCreatedHasLink events with MicrosoftGraphActivityLogs and AADNonInteractiveUserSignInLogs via AppAccessContext.UniqueTokenId. Agent users never produce interactive sign-ins; their activity is identifiable through the Agent.agentSubjectType value agentIDuser and the linked agent identity/blueprint in non-interactive sign-in logs. The agent-user OAuth flow (blueprint client secret, AzureADTokenExchange client assertion, user_fic on-behalf-of exchange) and the Graph API POST to a team channel messages endpoint are the key behaviors to detect.

- **Proxy_Link_Domoarigato_AI_Agent_Teams_Phish** (sigma, medium): Keys on the single high-specificity link domain delivered inside the agent-sent Teams message, expressed as one proxy rule over DestinationHostname; Entra/Graph audit telemetry (AADNonInteractiveUserSignInLogs, MicrosoftGraphActivityLogs, Purview MessageCreatedHasLink) and the Azure-owned source IP 51.3.97.221 have no expressible logsource and were deliberately omitted.
