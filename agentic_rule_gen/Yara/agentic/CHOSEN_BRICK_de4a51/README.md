# CHOSEN BRICK

Source: https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists

CHOSEN BRICK is a Windows malware family used by Iranian state cyber actors since at least 2025 to target dissidents, activists and journalists in the UK, US, Netherlands and elsewhere. It is delivered through social-engineering on messaging platforms using lures disguised as legitimate applications, persists via the HKCU Run key, and uses per-victim Telegram bots plus cloud object stores for command and control and exfiltration. The malware supports process and system discovery, screen and microphone capture, Telegram/WhatsApp and email theft, additional payload downloads and data wiping.

- **APT_CHOSEN_BRICK_Oct2026** (yara, medium): Rule keys on two high-specificity mutex values explicitly mentioned in the report.
- **ChosenBrickPersistenceViaRunKey** (sigma, high): This rule detects specific registry value names and executable paths used by CHOSEN BRICK for persistence, making it highly precise.
- **ChosenBrickFileDropInMasqueradingPath** (sigma, high): This rule detects file creation in a highly unusual, non-standard path used for masquerading, which is a strong indicator of compromise.
