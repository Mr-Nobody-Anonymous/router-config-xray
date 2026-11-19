<div align="center">

```
██╗  ██╗███████╗██████╗ ██╗   ██╗██╗      ██████╗ ██████╗ ███████╗███████╗██╗  ██╗
╚██╗██╔╝██╔════╝██╔══██╗██║   ██║██║     ██╔═══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝
 ╚███╔╝ ███████╗██████╔╝██║   ██║██║     ██║   ██║██████╔╝█████╗   ███████╗ ╚███╔╝ 
 ██╔██╗ ██╔════╝██╔══██╗██║   ██║██║     ██║   ██║██╔══██╗██╔══╝   ╚════██║ ██╔██╗ 
██╔╝ ██╗███████╗██║  ██║╚██████╔╝███████╗╚██████╔╝██║  ██║███████╗███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

**X-ray vision for exposed router configs - read-only, evidence-ready, and built for authorized testing.**

![read-only](https://img.shields.io/badge/mode-read--only-2ea44f)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![deps](https://img.shields.io/badge/dependencies-none-brightgreen)
![reports](https://img.shields.io/badge/reports-terminal%20%7C%20JSON%20%7C%20HTML%20%7C%20Markdown-6f42c1)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

> [!] AUTHORIZED USE ONLY - devices/networks you own or have explicit written permission to test.
> See [SECURITY.md](SECURITY.md).

</div>

---

## What it does (in one paragraph)

Some routers/CPEs serve their **entire configuration file** over plain HTTP with **no login**. One reachable file can expose admin passwords, Wi-Fi keys, remote-management (TR-069/ACS) credentials, WAN/PPPoE details, and device identifiers. `router-config-xray` checks for those endpoints with **read-only GET requests** (or parses a local dump), shows exactly what leaks in a flashy terminal UI, and writes evidence reports. **No login, no brute force, no state changes, no firmware flashing.**

## 30-second demo

No network, no setup — just the bundled fictional sample:

```bash
python3 router_config_xray.py --demo
```

You'll see a colorized banner, a per-endpoint verdict, parsed sections (device, accounts, Wi-Fi, TR-069, WAN, LAN), an informational **exposure score**, and a session summary. Try `python3 router_config_xray.py --demo --no-color` in a pipe, or `--redact` to mask secrets.

## Install & run (60 seconds)

Python 3.8+, standard library only — nothing to download except the repo.

```bash
# 1. clone
git clone https://github.com/Mr-Nobody-Anonymous/router-config-xray.git
cd router-config-xray

# 2. verify it works (no network, fictional data)
python3 router_config_xray.py --demo

# 3. see all options
python3 router_config_xray.py --help
```

Optional: install a `router-config-xray` command in a local virtualenv (works on Kali/Debian too):

```bash
make install                         # creates .venv/ — no dependencies downloaded
.venv/bin/router-config-xray --demo
```

If `--demo` shows the banner and a verdict, your install is good.

## Usage

```bash
# Safe offline demo (fictional data, zero network)
python3 router_config_xray.py --demo

# Analyze a config file you are authorized to review
python3 router_config_xray.py --file samples/decoy_config.xml

# Scan one authorized target (default: GET /config.xml)
python3 router_config_xray.py --target 192.168.0.1

# Probe the full read-only endpoint wordlist, 8 parallel workers
python3 router_config_xray.py --target 192.168.0.1 --all-paths --concurrency 8

# Scan many targets, compact output, secrets masked
python3 router_config_xray.py --targets-file hosts.txt --quiet --redact

# Custom path list + write every report format at once
python3 router_config_xray.py -t 192.168.0.1 --paths-file my_paths.txt --outdir ./evidence

# Introspection / QA
python3 router_config_xray.py --list-paths
python3 router_config_xray.py --self-test
make test
```

**Exit codes:** `0` = no clear indicators, `2` = indicators detected, `1` = usage/input error, `130` = interrupted.

**Input errors are friendly** — a missing file, empty targets list, or invalid `--timeout` / `--concurrency` prints `error: ...` instead of a Python traceback.

**Redirects:** the scanner reports a 3xx response but never follows it, so every request stays on the host you authorized.

## Features

| Feature | What it gives you |
|---|---|
| **Flashy terminal UI** | Gradient banner, verdict badges, colored sections, progress bar during scans, exposure meter, boxed session summary. Auto-disables in pipes / `NO_COLOR` / `--no-color`. |
| **Parallel read-only probing** | `--concurrency N` checks many endpoints at once with a live progress bar; deterministic result ordering. |
| **Tolerant extraction** | XML parsing with regex fallback — works even when the config is malformed or uses a vendor-specific schema. |
| **Secret recovery hints** | Raw value plus printable view, hex, and base64/XOR-style decode hints where applicable. |
| **Heuristic exposure score** | 0-100 score (`INFO` to `CRITICAL`) with the reasons behind it. Informational only - **not CVSS**. |
| **Four report formats** | Terminal, `--json`, `--html` (dark themed with cards), `--md`; `--outdir` writes all three at once. |
| **Share-safe mode** | `--redact` masks secret values everywhere, including report files. |
| **Flexible input** | `--demo`, `--file`, `--target`, `--targets-file`, `--paths`, `--paths-file`, `--all-paths`. |
| **Self-checks & tests** | `--self-test` runs internal checks; `make test` runs the 17-test unit suite. |
| **Zero dependencies** | Standard library only — easy to audit, easy to run anywhere. |

## What it extracts (when present)

| Area | Examples |
|---|---|
| Device fingerprint | Vendor/model, serial, MAC/OUI, HW/SW versions, access type |
| Admin / web account | Management username and password material |
| User GUI account | Limited/non-admin account details |
| Service accounts | FTP / Telnet / SSH credentials |
| Wi-Fi / WLAN | SSIDs, state, security/auth/cipher, PSKs/keys |
| TR-069 / ACS / CWMP | ACS URL, credentials, periodic inform, connection-request settings |
| WAN / PPPoE / IP | Credentials (with decode hints), external IP, DNS, gateway, MAC, VLAN |
| LAN | DHCP range, interface IP, subnet, lease time |
| Generic sweep | Other password / key / PSK-like fields |

## How it works

1. **Plan** — show target count, endpoint count, workers, timeout.
2. **Probe** — parallel read-only `GET` requests (or read one local file).
3. **Detect** — evaluate HTTP status + config/secret markers (`DslCpeConfig`, TR-069 structures, …).
4. **Parse** — tolerant XML + regex field mapping, with secret decode hints.
5. **Score & report** — verdicts, fingerprint hints, impact notes, exposure meter, evidence files.

## Compatibility (be honest about this)

**This is not a universal router scanner.** Paths, schemas and field names vary by vendor/model/firmware.

- **Primary observed profile (authorized testing):** SCTY **TG2212-class GPON gateway/CPE** devices with a `ty_httpd`-style web interface exposing unauthenticated `GET /config.xml` in **`DslCpeConfig`** (TR-069/CWMP-style XML).
- **Best-effort elsewhere:** `--all-paths` probes common config/backup/export endpoints across router families; generic markers may detect or partially extract on other devices — or find nothing. Results are **not guaranteed** on untested hardware.

## Remediation (if you find exposure)

1. Restrict/remove unauthenticated access to config/backup/export endpoints; require strong auth and limit to trusted management networks.
2. Disable WAN-side management; enforce firewall/ACL controls.
3. Rotate exposed secrets (admin/service passwords, Wi-Fi keys, TR-069 credentials) and check for unauthorized changes.
4. Apply vendor/ISP firmware updates and review TR-069/ACS exposure.
5. Monitor for unexpected config, DNS, forwarding or client changes.

## Project layout

```text
.
├── router_config_xray.py      # self-contained scanner (presentation -> extraction -> reporting -> CLI)
├── tests/
│   └── test_router_config_xray.py   # 17 standard-library unit tests
├── samples/
│   └── decoy_config.xml       # fictional sample config (safe demo)
├── examples/
│   ├── decoy_report.json      # generated report examples (fictional)
│   ├── decoy_report.html
│   └── decoy_report.md
├── .github/workflows/ci.yml   # test matrix (Python 3.8 - 3.12)
├── Makefile                   # test / lint / selftest / demo / clean
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE
└── requirements.txt           # intentionally empty: stdlib only
```

## Contributing & security

- Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
- Found a security issue in **this project**? See [SECURITY.md](SECURITY.md).
- Reports may contain real secrets — use `--redact` before sharing. Bundled samples are **fictional decoy data**.

## Disclaimer

Provided for educational and authorized security-auditing purposes. No warranty; no guarantee all exposures will be detected. You are responsible for lawful, authorized use.
