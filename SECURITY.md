# Security Policy & Responsible Use

## Authorized use only

`router-config-xray` is intended **only** for security testing and defensive auditing of devices, networks, and systems you **own** or have **explicit, written permission** to test.

- Do **not** scan, probe, or analyze targets without authorization.
- Do **not** use this tool to access, collect, or retain data you are not permitted to handle.
- You are responsible for complying with applicable laws, contracts, and acceptable-use policies.

## What this tool does (and does not do)

**Does:** perform **read-only** checks (HTTP GET of common config/backup/export paths, or offline parsing of a local file) to detect unauthenticated exposure and extract observable configuration fields for evidence.

**Does not:** log in, brute-force credentials, modify device state, install persistence/backdoors, flash or alter firmware, or exploit targets beyond reading resources that are already reachable without authentication.

## Handling findings responsibly

Reports may contain **highly sensitive material** (credentials, Wi-Fi keys, remote-management details, identifiers). If you discover exposure:

1. **Limit access** to findings and reports; treat them as secrets.
2. **Avoid unnecessary retention** of raw config dumps.
3. **Notify the appropriate owner/vendor/ISP** through responsible channels when applicable.
4. **Remediate:** restrict/remove unauthenticated access to config/backup endpoints, limit management exposure (especially from WAN), and rotate any exposed secrets.
5. **Validate fixes** only with authorization.

## Reporting issues in this project

If you find a security issue in this repository/tooling (not in a third-party device), please open a private report to the maintainers where possible. If private reporting is unavailable, open an issue with minimal sensitive detail and avoid including real credentials, personal data, or target-identifying information.

## No warranty / no endorsement

This software is provided "as is" without warranty. It does not guarantee detection of all exposures, and absence of findings is **not** proof that a target is secure. Risk and impact depend on context (reachability, configuration, credential validity, and mitigations).
