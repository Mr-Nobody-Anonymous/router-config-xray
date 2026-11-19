# Contributing

Thanks for helping improve `router-config-xray`! Contributions that make detection, parsing, reporting and docs clearer and safer are welcome.

## Ground rules

- **Authorized and ethical use only.** Do not add login attempts, brute force, exploitation beyond read-only detection/parsing of exposed resources, persistence, or firmware modification.
- **No real secrets or personal data.** Never commit real credentials, keys, serials, MACs, or IPs tied to real targets. Use fictional/decoy data (`samples/decoy_config.xml`).
- **Keep it read-only by design**, standard-library only, and keep `--no-color` / `--quiet` / `--redact` working.

## Quick development loop

```bash
python3 -m py_compile router_config_xray.py          # syntax
python3 router_config_xray.py --self-test            # internal checks
make test                                             # full unit suite
python3 router_config_xray.py --demo                  # visual smoke test
python3 router_config_xray.py --demo --redact --outdir /tmp/xray-evidence
```

## Changing the code

The scanner is one self-contained file organized in numbered sections (see its module docstring):

1. Presentation (colors, banners, panels, progress, meters)
2. Input & decoding
3. Extraction
4. Analysis & scoring
5. Scanning
6. Reporting
7. CLI

Keep new helpers in the matching section, use type hints, and add a test in `tests/test_router_config_xray.py` for any behavior change.

## Adding support for another device/profile

- Document the **specific model/firmware, endpoint, and config format** observed in an authorized context, and state limitations clearly.
- Extend `regex_extract()` without breaking existing profiles.
- Add fictional/decoy sample data where possible.
- Never add definitive severity/CVSS claims — scoring stays heuristic and informational.

## Pull requests

1. Open an issue first (bug, false positive/negative, parsing improvement, docs) with sanitized detail.
2. Fork and branch from `main`; make focused changes.
3. Run the checks above and paste results in the PR.
4. Describe **what changed, why, and how you tested**.

Be respectful and constructive. Report security concerns per [SECURITY.md](SECURITY.md).
