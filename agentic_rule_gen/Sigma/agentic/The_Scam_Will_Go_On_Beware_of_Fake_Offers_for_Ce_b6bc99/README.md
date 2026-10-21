# The Scam Will Go On: Beware of Fake Offers for Celine Dion Concert Tickets

Source: https://www.group-ib.com/blog/fake-concert-ticket-scam-celine-dion/

A multi-layered ticketing scam targeting Celine Dion fans in France, combining social-engineering on Facebook fan groups with fraudulent Shopify-hosted websites impersonating AXS, Ticketmaster and the artist herself. All fake sites share one phishing kit, evidenced by the identical low-entropy 'hWNA' OAuth state prefix, reused Shopify client IDs and a repurposed en-GB locale parameter. Fraudulent payments are taken via a subdomain 'pay.' page or direct peer-to-peer bank transfer, while the same Ticketmaster digital ticket is resold to multiple victims.

- **CelineDionTicketScam_DNS_Query** (sigma, high): This rule detects DNS queries for a comprehensive list of domains used in the Celine Dion ticketing scam.
- **CelineDionTicketScam_Payment_Subdomain** (sigma, high): This rule detects a pattern where payment pages are hosted on `pay.` subdomains of scam sites containing "celine" and "dion".
- **CelineDionTicketScam_Product_Page_Access** (sigma, high): This rule detects the specific and unique URL path for the fake ticket listing, making it highly precise.
