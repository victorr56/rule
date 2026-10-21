# Fake Calendly “Meta Careers” pages steal Facebook and Google logins

Source: https://www.malwarebytes.com/blog/threat-intel/2026/10/fake-calendly-meta-careers-pages-steal-facebook-and-google-logins

A reusable phishing kit impersonates Calendly booking pages for fake Meta job interviews to steal Facebook and Google credentials, including 2FA codes and phone-prompt approvals relayed in real time. The kit polls an attacker collection server (AWS API Gateway in ap-southeast-1) to drive the victim's screen flow and carries version 0.8.0 plus a Vietnamese production-deployment comment. Victims are lured through 'join'-prefixed recruiting-themed domains on the .cfd, .info and .works TLDs.

- **RecruitingThemedPhishingDomains** (sigma, high): This rule detects a list of specific, high-confidence phishing domains associated with this campaign.
