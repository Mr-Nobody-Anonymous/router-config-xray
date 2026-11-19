# 🔎 router-config-xray

**X-ray vision for exposed router configs — read-only, evidence-ready, and built for authorized testing.**

`router-config-xray` finds and parses **unauthenticated router/CPE configuration & backup endpoints** (like `/config.xml`) and shows exactly what they leak — **without logging in, brute forcing, or changing anything**.

![mode: read-only](https://img.shields.io/badge/mode-read--only-2ea44f)
![python](https://img.shields.io/badge/python-3.8%2B%20(stdlib)-blue)
![reports](https://img.shields.io/badge/reports-terminal%20%7C%20JSON%20%7C%20HTML%20%7C%20Markdown-6f42c1)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

> ⚠️ **Works on specific routers/profiles (not universal):** primarily built and observed on **SCTY TG2212-class GPON gateway/CPE** devices with a `ty_httpd`-style web interface exposing unauthenticated **`/config.xml`** in **`DslCpeConfig`** (TR-069/CWMP-style XML) format. It can also probe/parse similar exposures on other devices (best-effort), but extraction and coverage depend on model/firmware. See [Compatibility](#-compatibility-specific-routers--profiles).
>
> ✅ **Authorized use only.** Use only on devices/networks you own or have explicit written permission to test. See [SECURITY.md](SECURITY.md).

---

## TL;DR

```bash
# Scan an authorized target
python3 router_config_xray.py --target http://192.168.0.1 --all-paths

# Or analyze a local dump safely (no network)
python3 router_config_xray.py --file samples/decoy_config.xml

# Save shareable evidence (redacted secrets)
python3 router_config_xray.py --file samples/decoy_config.xml --redact --md report.md --json report.json
```

**What you get:** verdicts, fingerprint hints, extracted config (device/accounts/Wi-Fi/TR-069/WAN/LAN), decoded/recovered secret views where applicable, and an informational impact summary — in a flashy terminal UI plus report files.

---

## Why this exists

In an **authorized** review of an ISP/customer-premises gateway, a full configuration export (`/config.xml`) was downloadable over HTTP with **no authentication**. One reachable file can expose management creds, Wi-Fi keys, remote-management (TR-069/ACS) settings, WAN/PPPoE details, and identifiers — which may lead to device/network compromise depending on reachability and validity.

`router-config-xray` demonstrates and documents that exposure class **responsibly**: read-only checks, clear parsing, and evidence reports (no login, no state changes, no persistence, no firmware flashing).

## 🎯 Compatibility (specific routers / profiles)

**This tool is not a universal router scanner.** Config paths, schemas, and field names vary by vendor/model/firmware.

### Primary observed/tested profile
Built and tuned against an authorized case with this profile:

| Detail | Observed value/class |
|---|---|
| **Device class** | SCTY **TG2212-class GPON gateway/CPE** (fiber ONT/router class) |
| **Web interface** | `ty_httpd`-style management service |
| **Exposed endpoint** | Unauthenticated `GET /config.xml` (HTTP 200) |
| **Config format** | `DslCpeConfig` (TR-069/CWMP-style XML) |
| **Typical sections** | `InternetGatewayDevice`, `DeviceInfo`, `X_Customer_TeleComAccount`, `ManagementServer`, `WLANConfiguration`, `WANPPPConnection`/`WANIPConnection`, LAN settings |
| **Behavior** | Full config readable without prior authentication when reachable |

> Field extraction is tuned for this schema/profile. Other SCTY models/firmware or similar TR-069 exports may parse partially or fully, but results are **not guaranteed**.

### Best-effort on others
- `--all-paths` probes common config/backup/export endpoints across router families.
- Generic markers/parsing may detect or partially extract on other devices — but may also find nothing.

## ✨ What makes it cool

- **Flashy, readable terminal UI:** banner, verdict badges, colored sections, fingerprint hints, and a clear summary box (`--no-color` supported)
- **Strictly read-only:** HTTP GET or offline file parsing only — no login, no brute force, no config changes, no persistence/backdoors, no firmware flashing
- **Smart extraction:** tolerant XML + regex fallback, schema-aware field mapping for the target profile, and generic credential/key sweeps
- **Secret recovery helpers:** shows recovered/raw forms with hex and common decode hints (e.g. base64 and XOR-style obfuscation seen in some CPE configs) when applicable
- **Evidence-ready reports:** terminal + `--json`, `--html`, `--md`
- **Share-safe mode:** `--redact` masks secret values in output/reports
- **Flexible input:** single `--target`, `--targets-file`, or offline `--file`; `--quiet` for quick triage

## 🔍 What it extracts (when present)

| Area | Examples |
|---|---|
| **Device info** | Vendor/model/product, serials, MAC/OUI, HW/SW versions, access type |
| **Admin/web account** | Management username/password material |
| **User GUI account** | Limited/non-admin account details |
| **Service accounts** | FTP/Telnet/SSH credentials (if present) |
| **Wi-Fi/WLAN** | SSIDs, state, security/auth/cipher, PSKs/keys |
| **TR-069/ACS/CWMP** | ACS URL, creds, periodic inform, connection-request settings, enable/ACL flags |
| **WAN/PPPoE/IP** | Usernames/passwords (decode hints where applicable), external IP/DNS/gateway/MAC/VLAN/service |
| **LAN** | DHCP/interface basics |
| **Generic sweep** | Other credential/key-like fields |

Outputs include **fingerprint hints**, **access conditions**, and an **informational impact assessment** (no definitive severity/CVSS score).

## 🚀 Quick start

**Requirements:** Python 3.8+ (standard library only, no external dependencies).

```bash
python3 router_config_xray.py --help
python3 router_config_xray.py --version
python3 router_config_xray.py --list-paths

# 1) Authorized live scan
python3 router_config_xray.py --target http://192.168.0.1

# 2) Broader read-only path probing
python3 router_config_xray.py --target http://192.168.0.1 --all-paths

# 3) Offline analysis (safe demo)
python3 router_config_xray.py --file samples/decoy_config.xml

# 4) Evidence reports
python3 router_config_xray.py --file samples/decoy_config.xml --json out.json --html out.html --md out.md

# 5) Redacted/shareable output
python3 router_config_xray.py --file samples/decoy_config.xml --redact --no-color
```

**Exit codes:** `0` = no clear indicators found, `2` = indicators detected (verify in authorized context).

## 🧪 Demo (fictional decoy data only)

Safe demo assets included:
- [`samples/decoy_config.xml`](samples/decoy_config.xml) — fictional config
- [`examples/decoy_report.json`](examples/decoy_report.json), [`examples/decoy_report.html`](examples/decoy_report.html), [`examples/decoy_report.md`](examples/decoy_report.md)

```text
  █▀█ █▀█ █░█ ▀█▀ █▀▀ █▀█   █▀▀ █▀█ █▄░█ █▀▀ █ █▀▀   ▀▄▀ █▀█ █▀█ █▄█
  █▀▄ █▄█ █▄█ ░█░ ██▄ █▀▄   █▄▄ █▄█ █░▀█ █▀░ █ █▄█   █░█ █▀▄ █▀█ ░█░
  v1.2.0  ·  read-only exposure scanner for router/CPE config dumps

⚠ TARGET 1/1: file:///.../samples/decoy_config.xml
  ├ verdict : ⚠  LIKELY EXPOSED CONFIG
  ├ signals : bytes=3566  markers=14  sensitive_hits=15
  ├ hints   : DslCpeConfig (TR-069/CWMP-style XML) · device identifiers present
  └
  🖥 DEVICE INFO  |  🔑 ADMIN/WEB  |  👤 USER  |  🛠 SERVICES
  📶 WIFI/WLAN   |  📡 TR-069/ACS |  🌐 WAN   |  🏠 LAN
  ⚡ IMPACT ASSESSMENT (informational, not a definitive score)
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ INDICATORS DETECTED: Offline analysis of provided config file...   ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## How it works

1. **Probe (read-only):** request common config/backup/export paths (or read a local file).
2. **Detect:** evaluate HTTP status + config/secret markers (e.g. `DslCpeConfig`, TR-069 structures).
3. **Parse & recover:** tolerant extraction with schema-aware mapping and decode hints where applicable.
4. **Report:** present verdicts, fingerprint hints, access conditions, and informational impact with evidence outputs.

## Access conditions

- **Network reachability** to the device web interface is required, but **no prior authentication** is required for an exposed endpoint itself.
- **LAN/Wi-Fi:** reachable on the local network → may be readable if exposed.
- **WAN/internet:** remotely exposed management/endpoint → may be reachable off-network.
- Actual risk depends on exposure, configuration, and validity/usability of recovered values.

## Impact & risk (informational — no definitive score)

An unauthenticated, reachable config/backup export disclosing credentials or sensitive settings is a serious security weakness (often broken access control / sensitive information disclosure). Potential impacts (context-dependent): device takeover, network/Wi-Fi compromise, remote-management abuse risk, service/identity exposure, availability/privacy loss.

**This tool does not claim a CVSS or definitive severity score.** Treat outputs as observed indicators and assess risk in your environment.

## Remediation

- Restrict/remove unauthenticated access to config/backup/export endpoints; require strong auth and limit to trusted management networks.
- Disable unnecessary WAN-side management; enforce firewall/ACL controls.
- Rotate exposed secrets (admin/user/service passwords, Wi-Fi keys, remote-management creds) and review for unauthorized changes.
- Apply vendor/ISP firmware updates/hardening; review TR-069/ACS exposure.
- Monitor for unexpected config, DNS, forwarding, or client changes.

## Responsible use, license & security

- **Authorized testing only.** See [SECURITY.md](SECURITY.md).
- Read-only by design — no backdoors, no firmware flashing, no target modification.
- Findings/reports may contain secrets: handle carefully (`--redact` for sharing). Included samples/examples are **fictional decoy data only**.
- Licensed under [MIT](LICENSE). Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Project layout

```text
.
├── router_config_xray.py      # read-only scanner/extractor
├── samples/
│   └── decoy_config.xml       # fictional sample config (safe demo)
├── examples/
│   ├── decoy_report.json      # sample JSON report (decoy)
│   ├── decoy_report.html      # sample HTML report (decoy)
│   └── decoy_report.md        # sample Markdown report (decoy)
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
├── requirements.txt
└── .gitignore
```

## Disclaimer

Provided for educational and authorized security-auditing purposes. No warranty; no guarantee all exposures will be detected. You are responsible for lawful, authorized use.
