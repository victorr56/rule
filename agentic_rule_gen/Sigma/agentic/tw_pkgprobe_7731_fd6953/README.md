# tw-pkgprobe-7731

Source: https://www.reversinglabs.com/blog/malicious-npm-campaign-twilio

A malicious npm package, tw-pkgprobe-7731, posed as an authorized Twilio HackerOne bug-bounty research probe while targeting Twilio developers. After checking for a Twilio developer environment it collected environment variables, system details, working directory and hostname, and exfiltrated Twilio ACCOUNT_SID and AUTH_TOKEN credentials over a webhook, later probing Twilio-internal hosts and the AWS metadata endpoint. Detection can key on the package name, the npm publisher account, the deamon.js component, the embedded bug-bounty probe comments and references to process.env.ACCOUNT_SID/AUTH_TOKEN.

- **TwPkgprobe7731_Package_Execution** (sigma, high): This rule detects the command line installation or execution of the uniquely named malicious npm package `tw-pkgprobe-7731`.
- **TwPkgprobe7731_Malicious_File_Creation** (sigma, high): This rule detects the creation of the `deamon.js` file within the specific `tw-pkgprobe-7731` node_modules directory path.
- **TwPkgprobe7731_Twilio_Internal_Host_Probe** (sigma, medium): This rule detects DNS queries for a specific list of Twilio-internal domains probed by the malware for reconnaissance.
