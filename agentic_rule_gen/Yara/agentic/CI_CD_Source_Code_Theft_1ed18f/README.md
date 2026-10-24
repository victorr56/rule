# CI/CD Source Code Theft

Source: https://www.group-ib.com/blog/gitlab-jenkins-forensics/

Analysis of forensic artifacts from GitLab and Jenkins servers used in source code theft incidents. Attackers abuse misconfigured CI/CD instances to create users, generate tokens, and exfiltrate code repositories by cloning or downloading build artifacts. The report details specific log entries, file paths, and URI patterns indicative of this activity.

- **SUSP_GitLab_Exfil_Tool_Oct2026** (yara, medium): This rule detects attacker tooling by keying on highly specific URI paths and action strings associated with creating tokens, adding users, and exfiltrating git repositories from GitLab.
- **SUSP_Jenkins_Exfil_Tool_Oct2026** (yara, medium): This rule detects attacker tooling by keying on highly specific URI paths and strings associated with creating admin users, accessing specific credentials, and authenticating to Jenkins.
- **JenkinsCredentialAccess** (sigma, high): This rule keys on a highly specific and sensitive Jenkins credential access URI pattern, indicating potential credential theft.
- **JenkinsWorkspaceFileExfiltrationViaZipWrapper** (sigma, high): This rule keys on a specific Jenkins URI pattern (`/ws/*zip*/`) used for on-the-fly artifact zipping, a likely exfiltration vector.
- **GitLabPersonalAccessTokenCreation** (sigma, high): This rule detects a POST request to the specific GitLab URI for Personal Access Token creation, indicating a persistence attempt.
- **JenkinsAdminCreatesUserAccount** (sigma, high): This rule detects a POST request to the specific Jenkins URI for user creation by an admin, indicating a potential persistence attempt.
- **GitLabRepositoryDownloadAsArchive** (sigma, medium): This rule keys on a specific GitLab URI pattern for downloading a repository archive, indicating potential bulk code exfiltration.
- **SuspiciousJenkinsUserFileCreation** (sigma, high): This rule keys on a highly anomalous file creation pattern for a Jenkins user configuration file, indicating non-standard user creation.
