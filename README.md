# 🔎 router-config-xray

**See what an exposed router config reveals — safely, read-only, and with evidence.**

`router-config-xray` is a read-only scanner for **unauthenticated router/CPE configuration and backup endpoints** (like `/config.xml`). It checks whether a config export is reachable without login, parses the dump, and presents what’s inside in a clear, audit-friendly way — **without brute force, without logging in, and without changing anything on the target**.

> **Authorized use only.** Run this tool only on devices/networks you own or have explicit written permission to test.

![mode: read-only](https://img.shields.io/badge/mode-read--only-2ea44f)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![reports](https://img.shields.io/badge/reports-terminal%20%7C%20JSON%20%7C%20HTML%20%7C%20Markdown-6f42c1)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Why this exists

During an **authorized** review of an ISP/customer-premises gateway, a full device configuration export (`/config.xml`) was found to be downloadable over HTTP **with no authentication**.

That single file can expose a surprising amount: management credentials, Wi-Fi keys, remote-management (TR-069/ACS) settings, WAN/PPPoE details, and device identifiers. Depending on reachability and whether those values are valid, the impact can range from privacy loss to full device and network compromise.

`router-config-xray` was built to **detect and demonstrate this class of exposure responsibly**:
- read-only HTTP GET checks (or offline file analysis)
- tolerant parsing and clear extraction
- evidence-ready reports (terminal/JSON/HTML/Markdown)
- no login attempts, no state changes, no persistence/backdoors, no firmware flashing

## Compatibility: specific routers / profiles (important)

This tool **does not work the same on every router**. Config endpoints, formats, and field names vary widely by vendor, model, and firmware.

### Primary observed/tested profile (authorized testing)
Best results and deepest field extraction were developed against a specific CPE class where unauthenticated config export was observed:

- **Device class:** SCTY **TG2212-class GPON gateway/CPE** (fiber ONT/router class)
- **Web/management interface:** `ty_httpd`-style management service
- **Exposed endpoint:** unauthenticated `GET /config.xml` (HTTP 200)
- **Config format:** `DslCpeConfig` (TR-069/CWMP-style XML) containing sections such as `InternetGatewayDevice`, `DeviceInfo`, `X_Customer_TeleComAccount`, `ManagementServer`, `WLANConfiguration`, `WANPPPConnection`/`WANIPConnection`, and LAN settings
- **Observed behavior:** full configuration readable without prior authentication when the endpoint is reachable

> Field names and extraction quality are tuned for this schema/profile. Other SCTY models/firmware builds or similar TR-069-style exports may parse partially or fully, but results are **not guaranteed**.

### Generic detection
The scanner can still probe common config/backup/export paths (`--all-paths`) and apply generic parsing/marker detection on **other devices**, but:
- it may find nothing on devices that do not expose such endpoints,
- or it may detect an accessible config without mapping every field perfectly.

**Bottom line:** treat this as a targeted, read-only auditor for this exposure class — strongest on the profile above, best-effort elsewhere.

## What it looks for & extracts

When a readable config is found, the tool attempts to recover and display (where present):

| Area | Examples of fields |
|---|---|
| **Device info** | Vendor/model/product, serials, MAC/OUI, hardware/software versions, access type |
| **Admin/web account** | Management username/password material |
| **User GUI account** | Limited/non-admin account details |
| **Service accounts** | FTP/Telnet/SSH credentials (if present) |
| **Wi-Fi/WLAN** | SSIDs, enable state, security/auth/cipher, PSKs/keys |
| **TR-069/ACS/CWMP** | ACS URL, credentials, periodic inform, connection-request settings, enable/ACL flags (if present) |
| **WAN/PPPoE/IP** | Usernames/passwords (with decode hints where applicable), external IP/DNS/gateway/MAC/VLAN/service details |
| **LAN** | DHCP/interface basics |
| **Generic sweep** | Other credential/key-like fields |

It also reports **fingerprint hints**, **access conditions**, and an **informational impact assessment** (no definitive severity score).

## Cool features

- 🔒 **Strictly read-only:** HTTP GET / offline parsing only — no login, no brute force, no config changes, no persistence, no firmware flashing
- 🧩 **Specific-profile aware:** tuned for `DslCpeConfig`/TR-069-style exports like the SCTY TG2212-class `/config.xml` profile, with generic fallback
- 🧠 **Tolerant parsing:** XML parsing with regex fallback (handles messy/control-char dumps) and schema-tolerant extraction
- 🔐 **Secret recovery helpers:** shows recovered/raw forms with hex and common decode hints (e.g. base64 and XOR-style obfuscation seen in some CPE configs) when applicable
- 🕵️ **Fingerprint hints:** surfaces useful indicators (server header, schema markers, vendor/model hints) to understand what you’re looking at
- 🌐 **Path discovery:** default checks plus `--all-paths` expanded wordlist of common config/backup/export endpoints
- 📁 **Offline mode:** `--file` to analyze a local config dump safely with zero network requests
- 🧾 **Evidence reports:** terminal output plus `--json`, `--html`, and `--md`
- 🙈 **Share-safe redaction:** `--redact` masks secret values in output/reports for safer sharing
- 🎯 **Multi-target:** scan a single target or a list from file; `--quiet` for CI/triage-style summaries

## Quick start

```bash
# Help & version
python3 router_config_xray.py --help
python3 router_config_xray.py --version

# 1) Scan a target (authorized) for common exposed config endpoints
python3 router_config_xray.py --target http://192.168.0.1

# 2) Broader read-only path scan
python3 router_config_xray.py --target http://192.168.0.1 --all-paths

# 3) Analyze a local config dump offline (safe, no network)
python3 router_config_xray.py --file samples/decoy_config.xml

# 4) Generate evidence reports
python3 router_config_xray.py --file samples/decoy_config.xml \
  --json report.json --html report.html --md report.md

# 5) Shareable (redacted) report
python3 router_config_xray.py --file samples/decoy_config.xml --redact --md redacted.md

# 6) Show built-in path wordlist
python3 router_config_xray.py --list-paths
```

**Exit codes:** `0` = no clear indicators found by this check, `2` = indicators detected (verify in authorized context).

## Demo (fictional decoy data)

A safe, fictional sample is included at [`samples/decoy_config.xml`](samples/decoy_config.xml). Generated example reports (decoy only): [`examples/decoy_report.json`](examples/decoy_report.json), [`examples/decoy_report.html`](examples/decoy_report.html), [`examples/decoy_report.md`](examples/decoy_report.md).

```text
╔══════════════════════════════════════════════════════════════╗
║                 router-config-xray  v1.1.0                   ║
║     Read-only scanner for exposed router/CPE config dumps    ║
║           Authorized testing & defensive auditing            ║
╚══════════════════════════════════════════════════════════════╝

Target: file:///.../samples/decoy_config.xml
  [PATH] ... verdict=LIKELY_EXPOSED_CONFIG  bytes=3566  markers=14  sensitive_hits=15

[DEVICE INFO]        EXAMPLEVENDOR / EXAMPLE-ROUTER-X1 / V2.0.0
[ADMIN / WEB ACCOUNT] username: admin   password: <recovered>
[WI-FI / WLAN]        SSID=ExampleWiFi (WPA2/PSK) key: <recovered>
[TR-069 / ACS / CWMP] https://acs.example.invalid:7547/  interval=300
[WAN / PPPoE]         user/endpoint/DNS details (recovered where possible)
[IMPACT ASSESSMENT]   informational, context-dependent (no definitive score)
SUMMARY: Potential unauthenticated sensitive config exposure detected...
```

> All sample values above and in `samples/`/`examples/` are **fictional placeholders**.

## How it works (high level)

1. **Target & probe (read-only):** request common config/backup/export paths (or read a local file).
2. **Detect:** check HTTP status and config/secret markers (e.g. `DslCpeConfig`, TR-069 structures, credential/key fields).
3. **Parse & recover:** extract structured fields with tolerant parsing and decode hints where applicable.
4. **Report:** present findings, fingerprint hints, access conditions, and an informational impact assessment with evidence outputs.

## Access conditions: does this require connecting first?

- **Network reachability is required** to the device’s web interface — but **no prior authentication** is required for the exposed endpoint itself.
  - **LAN/Wi-Fi:** if you can reach the gateway/management interface on the local network, an unauthenticated endpoint may be readable.
  - **WAN/internet:** if the management interface/endpoint is remotely exposed, it may be reachable off-network.
- Actual risk depends on exposure, configuration, and whether recovered values are valid/usable.

## Impact & risk (informational — no definitive score)

An unauthenticated, reachable configuration/backup export that discloses credentials or sensitive settings is a serious security weakness (often treated as broken access control / sensitive information disclosure). Depending on what is exposed and who can reach it, potential impacts include:

- **Device takeover:** leaked management credentials may allow full administrative access and reconfiguration.
- **Network compromise:** changes to DNS/DHCP/routing/firewall/port-forwarding could enable interception, redirection, or exposure of internal services.
- **Wi-Fi compromise:** exposed keys can allow unauthorized network access and traffic visibility.
- **Remote-management risk:** TR-069/ACS details may increase risk of provisioning abuse where reachable/misconfigured.
- **Service/identity exposure:** WAN/PPPoE and account details can aid abuse or targeted attacks.
- **Availability/privacy loss:** misconfiguration/reset can cause outage; identifiers and topology/config details may leak.

**No CVSS or definitive severity score is claimed by this tool.** Treat outputs as observed indicators and assess risk in your own environment/context.

## Remediation guidance

- Remove or strictly protect config/backup/export endpoints; require strong authentication and limit access to trusted management networks.
- Disable WAN-side management unless necessary; enforce firewall/ACL restrictions.
- **Rotate exposed secrets** (admin/user/service passwords, Wi-Fi keys, remote-management credentials) and review for unauthorized changes.
- Apply vendor/ISP firmware updates and hardening guidance; review TR-069/ACS exposure with your provider.
- Monitor for unexpected configuration, DNS, forwarding, or client changes.

## Responsible use, license & security

- **Authorized testing only.** See [SECURITY.md](SECURITY.md) for responsible use, handling of sensitive findings, and reporting guidance.
- This tool is **read-only by design** and does not plant backdoors, flash firmware, or modify targets.
- Reports may contain secrets — handle/store/share carefully (use `--redact` when appropriate). Included samples/examples use **fictional decoy data only**.
- Licensed under the [MIT License](LICENSE).

## Project layout

```text
.
├── router_config_xray.py      # read-only scanner/extractor
├── samples/
│   └── decoy_config.xml       # fictional sample config for safe demos
├── examples/
│   ├── decoy_report.json      # sample JSON report (decoy data)
│   ├── decoy_report.html      # sample HTML report (decoy data)
│   └── decoy_report.md        # sample Markdown report (decoy data)
├── LICENSE
├── SECURITY.md
├── .gitignore
└── README.md
```

## Disclaimer

Provided for educational and authorized security-auditing purposes. No warranty is provided, and no guarantee is made that all exposures will be detected. You are solely responsible for lawful, authorized use.
