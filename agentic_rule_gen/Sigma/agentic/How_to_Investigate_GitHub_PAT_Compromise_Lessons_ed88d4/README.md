# How to Investigate GitHub PAT Compromise: Lessons From a Multi-Organization Campaign

Source: https://www.wiz.io/blog/investigating-github-pat-compromise

A multi-organization campaign active from mid-May through early June 2026 in which compromised GitHub Personal Access Tokens were used for repository reconnaissance via the GitHub API, low-volume validation cloning, and highly parallelized mass cloning of private repositories. The actor operated from AWS ca-central-1 infrastructure and a HostPapa IP using the git/2.43.0 and git/2.25.1 user agents, and the source of the leaked PATs was never identified. Detection rests on GitHub audit log events such as git.clone and api.request, anomalous git/Chrome user agents, and the listed source IPs.

- **GitHubMassCloningFromAWSCaCentral1** (sigma, high): This rule is precise because it combines a specific git user agent, a list of attacker-controlled IPs, and traffic to GitHub.
- **GitHubValidationCloningFromHostPapa** (sigma, high): This rule is precise because it combines a specific git user agent, a specific attacker-controlled IP, and traffic to GitHub.
