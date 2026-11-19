# Contributing to router-config-xray

Thanks for your interest in improving `router-config-xray`! Contributions that make detection, parsing, reporting, and documentation clearer and safer are welcome.

## Ground rules

- **Authorized and ethical use only.** Do not add features that enable unauthorized access, brute forcing, exploitation beyond read-only detection/parsing of exposed resources, persistence, or firmware modification.
- **No secrets or personal data.** Never commit real credentials, keys, serials, MACs, IPs tied to real targets, or private dumps. Use fictional/decoy data (like `samples/decoy_config.xml`).
- **Keep it read-only by design.** The tool’s core behavior must remain non-intrusive (HTTP GET / offline analysis) and safe for authorized auditing.

## How to contribute

1. **Open an issue** (bug, false positive/negative, parsing improvement, new compatible profile, docs) with enough detail to reproduce. Avoid sharing sensitive target data — sanitize reports (use `--redact`).
2. **Fork & branch** from `main`.
3. **Make focused changes**:
   - Parsing/extraction: prefer tolerant, schema-aware logic and add/adjust decoy samples if needed.
   - CLI/output: keep `--no-color` and `--quiet` working; maintain report formats.
   - Docs: keep compatibility claims accurate (specific profiles where observed; best-effort elsewhere) and do not add CVSS/definitive severity claims.
4. **Test locally** (stdlib only):
   ```bash
   python3 -m py_compile router_config_xray.py
   python3 router_config_xray.py --file samples/decoy_config.xml
   python3 router_config_xray.py --file samples/decoy_config.xml --redact --no-color
   python3 router_config_xray.py --file samples/decoy_config.xml --json /tmp/r.json --html /tmp/r.html --md /tmp/r.md --quiet
   ```
5. **Open a pull request** describing what changed, why, and how you tested.

## Adding support for another device/profile

- Document the **specific model/firmware/profile, endpoint, and config format** observed (authorized context), and state limitations clearly.
- Add/extend extraction in a way that doesn’t break existing profiles.
- Include **fictional/decoy** sample data where possible.

## Code of conduct

Be respectful and constructive. Report security concerns per [SECURITY.md](SECURITY.md).
