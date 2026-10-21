# From One Account to Every Mailbox: Breaking Zimbra's Identity Boundaries (Part 1)

Source: https://www.rapid7.com/blog/post/ve-breaking-zimbra-identity-boundaries-part-1

Rapid7's staged disclosure of five Zimbra Collaboration Suite account-boundary flaws: GraphQL batched authenticate aliases hide failed logins from the source-IP counter (CVE-2026-93637), LDAP filter injection (CVE-2026-93635), SaveDraftRequest sender impersonation (CVE-2026-73571), EWS FindItem cross-user mailbox reads via composite folder IDs (CVE-2026-10631), and a Sieve notify forwarding-policy bypass (CVE-2026-50055). Detection anchors are anonymous GraphQL requests carrying many authenticate aliases, EWS FindItem requests whose FolderId embeds another account's owner UUID, and stored filter rules using actionNotify with variable-expanded headers and body. Impersonated mail and notify exfiltration arrive through Zimbra's legitimate MTA path, so detection must key on the request bodies and saved rule state rather than transport artifacts.

- **ZimbraGraphQLBatchAuthentication** (sigma, high): This rule detects exploitation of CVE-2026-93637 by combining the specific GraphQL endpoint path with a regex that identifies the core of the attack: batching multiple authentication attempts in one request.
- **ZimbraEWSCrossUserRead** (sigma, high): This rule detects exploitation of CVE-2026-10631 by matching POSTs to vulnerable EWS endpoints with a request body containing both a `FindItem` operation and the specific composite `FolderId` format used in the attack.
