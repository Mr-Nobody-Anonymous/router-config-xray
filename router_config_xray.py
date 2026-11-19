#!/usr/bin/env python3
"""
router-config-xray - read-only exposure scanner for router/CPE config dumps.

WHAT IT DOES (authorized security testing only)
  - Performs READ-ONLY HTTP GET requests to common config/backup/export
    endpoints (e.g. /config.xml), or analyzes a local config file (--file).
  - Parses and displays exposed configuration in clear/recovered form where
    possible: accounts, service credentials, Wi-Fi keys, TR-069/ACS settings,
    WAN/PPPoE details, device identifiers and LAN information.
  - Produces terminal, JSON, HTML and Markdown reports for evidence.

WHAT IT DOES NOT DO
  - No login attempts, no brute force, no state changes, no persistence,
    no firmware flashing, no exploitation beyond reading unauthenticated data.

Use only on devices/networks you own or have explicit written permission to test.

LAYOUT (this file is intentionally self-contained / standard-library only)
  1. Presentation layer ....... colors, banners, panels, progress, meters
  2. Input & decoding ......... normalization, byte decoding, secret recovery
  3. Extraction ............... tolerant XML + regex field mapping
  4. Analysis & scoring ....... markers, verdicts, heuristic exposure score
  5. Scanning ................. parallel read-only probing, offline file mode
  6. Reporting ................ terminal, JSON, HTML, Markdown
  7. CLI ...................... argument parsing and orchestration
"""

from __future__ import annotations

import argparse
import base64
import copy
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "2.1.1"
TOOL_NAME = "router-config-xray"

# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

DEFAULT_PATHS = ["/config.xml"]
EXTRA_PATHS = [
    "/backupsettings.conf", "/romfile.cfg", "/cfg.xml", "/config.bin", "/backup.cfg",
    "/config.conf", "/backup_config.xml", "/settings.conf", "/configuration.xml",
    "/userconfig.cfg", "/config.dat", "/backup.tar.gz", "/backup.tar", "/export.cfg",
    "/cgi-bin/export_settings.cgi", "/cgi-bin/ExportSettings.sh", "/cgi-bin/DownloadCfg",
    "/goform/export", "/goform/BackupSettings", "/goform/save_config", "/getpage.gch",
    "/backup", "/config", "/download.cfg", "/userconfig.xml",
]

COMPAT_NOTES = [
    "Best-effort extraction is tuned for DslCpeConfig / TR-069-style XML exports (e.g. configs exposing /config.xml).",
    "Primary observed profile (authorized testing): SCTY TG2212-class GPON CPE/ONT gateways with a ty_httpd-style web interface exposing unauthenticated /config.xml.",
    "Detection and parsing are generic and may work on other routers/firmwares, but coverage and field mapping vary by model and software.",
]

EXIT_CLEAN = 0
EXIT_FINDINGS = 2
EXIT_ERROR = 1

# ---------------------------------------------------------------------------
# 1. Presentation layer
# ---------------------------------------------------------------------------

PALETTE = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "italic": "\033[3m", "underline": "\033[4m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "white": "\033[37m", "bright_red": "\033[91m", "bright_green": "\033[92m",
    "bright_yellow": "\033[93m", "bright_cyan": "\033[96m",
}

BANNER = r"""
  █▀█ █▀█ █░█ ▀█▀ █▀▀ █▀█   █▀▀ █▀█ █▄░█ █▀▀ █ █▀▀   ▀▄▀ █▀█ █▀█ █▄█
  █▀▄ █▄█ █▄█ ░█░ ██▄ █▀▄   █▄▄ █▄█ █░▀█ █▀░ █ █▄█   █░█ █▀▄ █▀█ ░█░
"""

VERDICT_STYLE = {
    "LIKELY_EXPOSED_UNAUTH_CONFIG": ("bright_red", "bold", "EXPOSED - UNAUTH CONFIG", "HIGH-SIGNAL"),
    "POSSIBLE_SENSITIVE_DISCLOSURE": ("yellow", "bold", "POSSIBLE SENSITIVE DISCLOSURE", "REVIEW"),
    "LIKELY_EXPOSED_CONFIG": ("yellow", "bold", "LIKELY EXPOSED CONFIG", "REVIEW"),
    "ACCESSIBLE_BUT_NO_CLEAR_SECRETS_DETECTED": ("cyan", "", "ACCESSIBLE (NO CLEAR SECRETS)", "INFO"),
    "PROTECTED_OR_FORBIDDEN": ("green", "", "PROTECTED / FORBIDDEN", "OK"),
    "NOT_FOUND": ("dim", "", "NOT FOUND", "OK"),
    "INCONCLUSIVE": ("yellow", "", "INCONCLUSIVE", "CHECK"),
    "PARSED": ("bright_cyan", "", "PARSED", "INFO"),
}


def color_enabled(no_color: bool = False) -> bool:
    """Honor --no-color, NO_COLOR, and non-TTY stdout."""
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def c(text: str, color: str = "", enable: bool = True, bold: bool = False,
      dim: bool = False) -> str:
    """Colorize text with a named palette entry."""
    if not enable or not text:
        return text
    codes: List[str] = []
    if bold:
        codes.append(PALETTE["bold"])
    if dim:
        codes.append(PALETTE["dim"])
    code = PALETTE.get(color)
    if code:
        codes.append(code)
    if not codes:
        return text
    return "".join(codes) + str(text) + PALETTE["reset"]


def rule(char: str = "-", width: int = 72, color: str = "dim", enable: bool = True) -> str:
    return c(char * width, color, enable)


def badge(text: str, color: str, enable: bool = True, bold: bool = False) -> str:
    return c(" " + text + " ", color, enable, bold=bold)


def verdict_badge(verdict: str, enable: bool) -> str:
    vcolor, is_bold, label, _ = VERDICT_STYLE.get(verdict, ("white", "", verdict, ""))
    icon = {"red": "!", "bright_red": "!", "yellow": "?", "green": "+",
            "cyan": "i", "bright_cyan": "i", "dim": "-"}.get(vcolor, " ")
    return c(f"[{icon}] ", vcolor, enable, bold=True) + c(label, vcolor, enable, bold=bool(is_bold))


def section(title: str, icon: str, color: str, enable: bool, width: int = 68) -> None:
    """Print a titled section header with a dotted rule."""
    label = f"{icon}  {title}"
    print("\n  " + c(label, color, enable, bold=True))
    print("  " + c("." * min(width, len(label) + 2), "dim", enable))


def kv(key: str, value: Any, enable: bool, indent: int = 4, key_color: str = "cyan") -> None:
    print(" " * indent + c(f"{key:>22}: ", key_color, enable) + str(value))


def meter(score: int, color: str, enable: bool, width: int = 30) -> str:
    """ASCII/Unicode progress meter for the heuristic exposure score."""
    filled = int(width * max(0, min(100, score)) / 100)
    bar = c("#" * filled, color, enable, bold=True) + c("." * (width - filled), "dim", enable)
    return f"{bar}  {c(str(score).rjust(3) + '/100', color, enable, bold=True)}"


def panel(lines: List[str], title: str, color: str, enable: bool, width: int = 72) -> None:
    """Print a bordered panel with a title; long lines wrap to the panel width."""
    import textwrap
    top = "+- " + title + " "
    print("\n  " + c(top + "-" * max(0, width - len(top) - 1) + "+", color, enable, bold=True))
    for line in lines:
        wrapped = textwrap.wrap(line, width=width - 4, subsequent_indent="  ") or [""]
        for piece in wrapped:
            print("  " + c("| ", color, enable) + piece)
    print("  " + c("+" + "-" * (width - 1) + "+", color, enable))


class Progress:
    """Minimal inline progress indicator (only renders on a TTY)."""

    def __init__(self, total: int, enabled: bool, label: str = "probing") -> None:
        self.total = max(1, total)
        self.enabled = enabled
        self.label = label
        self.count = 0
        self.last = ""

    def tick(self, path: str) -> None:
        self.count += 1
        if not self.enabled:
            return
        pct = int(100 * self.count / self.total)
        filled = int(24 * self.count / self.total)
        short = path if len(path) <= 26 else "..." + path[-23:]
        line = (f"\r  {c('>>', 'bright_cyan', True, bold=True)} {self.label} "
                f"[{c('#' * filled, 'bright_cyan', True)}{c('.' * (24 - filled), 'dim', True)}] "
                f"{pct:3d}%  {c(short, 'white', True)}   ")
        if len(line) < len(self.last):
            line += " " * (len(self.last) - len(line))
        sys.stdout.write(line)
        sys.stdout.flush()
        self.last = line

    def finish(self) -> None:
        if self.enabled:
            sys.stdout.write("\r" + " " * len(self.last) + "\r")
            sys.stdout.flush()


def show_banner(enable: bool) -> None:
    print(c(BANNER, "bright_cyan", enable, bold=True))
    print(c(f"  v{VERSION}  |  read-only exposure scanner for router/CPE config dumps",
            "bright_cyan", enable, bold=True))
    print(c("  authorized testing & defensive auditing only", "dim", enable))
    print(rule("=", 72, "dim", enable))


# ---------------------------------------------------------------------------
# 2. Input & decoding helpers
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_target(target: str) -> str:
    target = target.strip()
    if not re.match(r"^https?://", target, re.I):
        target = "http://" + target
    return target.rstrip("/")


def sanitize_xml_bytes(data: bytes) -> bytes:
    return bytes(ch for ch in data if ch in (9, 10, 13) or ch >= 0x20)


def decode_bytes(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("latin-1", errors="replace")


def is_mostly_printable(text: str) -> bool:
    if not text:
        return True
    good = sum(1 for ch in text if 32 <= ord(ch) < 127 or ch in "\t\r\n")
    return good / max(1, len(text)) >= 0.85


def to_hex(data: bytes) -> str:
    return data.hex(" ")


def try_b64_decode(value: str) -> Optional[bytes]:
    stripped = (value or "").strip()
    if len(stripped) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
        return None
    try:
        return base64.b64decode(stripped + ("=" * ((-len(stripped)) % 4)), validate=False)
    except Exception:
        return None


def xor80_decode_bytes(data: bytes) -> str:
    return "".join(chr(byte ^ 0x80) for byte in data)


def represent_secret(raw: Any) -> Dict[str, Any]:
    """Return raw + recovered/hex/base64 views of a secret-like value."""
    if raw is None:
        return {"raw": None}
    text = raw if isinstance(raw, str) else str(raw)
    data = text.encode("latin-1", errors="replace")
    out: Dict[str, Any] = {"raw": text}
    if not is_mostly_printable(text) or any(ord(ch) < 32 and ch not in "\r\n\t" for ch in text):
        out["hex"] = to_hex(data)
        out["printable_view"] = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    decoded = try_b64_decode(text)
    if decoded is not None and 0 < len(decoded) <= 256:
        stripped = decoded.rstrip(b"\x00")
        try:
            as_text = stripped.decode("utf-8")
        except Exception:
            as_text = stripped.decode("latin-1", errors="replace")
        if as_text and as_text != text and is_mostly_printable(as_text) and any(ch.isalnum() for ch in as_text):
            out["decoded_base64"] = as_text
        xored = xor80_decode_bytes(decoded)
        if is_mostly_printable(xored) and xored != text and any(ch.isalnum() for ch in xored):
            out["decoded_base64_xor80"] = xored
    if not is_mostly_printable(text) and data:
        xored = xor80_decode_bytes(data)
        if is_mostly_printable(xored) and xored.strip():
            out["xor80_of_raw"] = xored
    recovered = text
    if "decoded_base64_xor80" in out:
        recovered = out["decoded_base64_xor80"]
    elif "decoded_base64" in out:
        recovered = out["decoded_base64"]
    elif not is_mostly_printable(text) and "xor80_of_raw" in out:
        recovered = out["xor80_of_raw"]
    out["recovered"] = recovered
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects - keep every request on the authorized host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str, timeout: float, user_agent: str) -> Tuple[Optional[int], Dict[str, str], bytes, Optional[str]]:
    """One read-only GET on the given host. Redirects are reported, never followed."""
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "*/*"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(5_000_000)
            headers = {key: value for key, value in response.headers.items()}
            return response.status, headers, body, None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(500_000)
            headers = {key: value for key, value in (exc.headers.items() if exc.headers else [])}
            return exc.code, headers, body, f"HTTPError:{exc.code}"
        finally:
            exc.close()
    except Exception as exc:
        return None, {}, b"", f"{type(exc).__name__}:{exc}"


def merge_extracted(primary: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, Any]:
    if not primary:
        return dict(fallback)
    out = dict(fallback)
    out.update({key: value for key, value in primary.items() if value})
    for key, value in fallback.items():
        if key not in out or not out[key]:
            out[key] = value
    return out


# ---------------------------------------------------------------------------
# 3. Extraction
# ---------------------------------------------------------------------------


def regex_extract(text: str) -> Dict[str, Any]:
    """Schema-tolerant field extraction. Works even when XML is malformed."""
    out: Dict[str, Any] = {}

    def grab_tag(tag: str) -> Optional[str]:
        match = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.I | re.S)
        return match.group(1) if match else None

    device = {}
    for tag in ["ManufacturerOUI", "ProductClass", "ModelName", "SerialNumber", "DeviceSerialNumber",
                "HardwareVersion", "SoftwareVersion", "X_Customer_MACAddress", "TrueVendorID",
                "AccessType", "FirstUseDate", "Manufacturer", "Product_ID"]:
        value = grab_tag(tag)
        if value is not None:
            device[tag] = value
    if device:
        out["device_info"] = device

    match = re.search(r"<X_Customer_TeleComAccount>(.*?)</X_Customer_TeleComAccount>", text, re.I | re.S)
    if match:
        block = match.group(1)
        user = re.search(r"<User(?:Name)?>(.*?)</User(?:Name)?>", block, re.I | re.S)
        pwd = re.search(r"<Password>(.*?)</Password>", block, re.I | re.S)
        out["admin_web_account"] = {
            "username": user.group(1) if user else "admin",
            "password": represent_secret(pwd.group(1)) if pwd else None,
        }

    match = re.search(r"<X_BROADCOM_COM_LoginCfg>(.*?)</X_BROADCOM_COM_LoginCfg>", text, re.I | re.S)
    if match:
        block = match.group(1)
        user = re.search(r"<User(?:User)?Name>(.*?)</User(?:User)?Name>", block, re.I | re.S)
        pwd = (re.search(r"<UserPassword>(.*?)</UserPassword>", block, re.I | re.S)
               or re.search(r"<Password>(.*?)</Password>", block, re.I | re.S))
        out["user_gui_account"] = {
            "username": user.group(1) if user else "user",
            "password": represent_secret(pwd.group(1)) if pwd else None,
        }

    match = re.search(r"<X_Customer_ServiceManage>(.*?)</X_Customer_ServiceManage>", text, re.I | re.S)
    if match:
        block = match.group(1)
        services = {}
        for tag in ["FtpUserName", "FtpPassword", "TelnetUserName", "TelnetPassword", "SshUserName", "SshPassword"]:
            found = re.search(rf"<{tag}>(.*?)</{tag}>", block, re.I | re.S)
            if found:
                services[tag] = represent_secret(found.group(1)) if "Password" in tag else found.group(1)
        if services:
            out["service_accounts"] = services

    tr069_tags = ["URL", "Username", "Password", "PeriodicInformEnable", "PeriodicInformInterval",
                  "ConnectionRequestURL", "ConnectionRequestUsername", "ConnectionRequestPassword",
                  "X_Customer_Tr69Daemon", "X_Customer_EnableCWMP", "X_Customer_ConnectionRequestPort",
                  "X_Customer_EnableCWMPWanAcl", "X_Customer_ACL_IpAndMask", "X_Customer_DataModel", "ParameterKey"]
    acs = re.search(r"<ManagementServer>(.*?)</ManagementServer>", text, re.I | re.S)
    block = acs.group(1) if acs else ""
    tr069 = {}
    for tag in tr069_tags:
        found = re.search(rf"<{tag}>(.*?)</{tag}>", block, re.I | re.S) if block else None
        if not found:
            found = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.I | re.S)
        if found:
            tr069[tag] = represent_secret(found.group(1)) if "Password" in tag else found.group(1)
    if tr069:
        out["tr069_acs"] = tr069

    wifi = []
    for match in re.finditer(r"<WLANConfiguration[^>]*>(.*?)</WLANConfiguration>", text, re.I | re.S):
        block = match.group(1)
        ssid = re.search(r"<SSID>(.*?)</SSID>", block, re.I | re.S)
        if not ssid and "<WlKey" not in block and "PreSharedKey" not in block:
            continue
        record: Dict[str, Any] = {}
        for tag in ["SSID", "Enable", "BeaconType", "WPAAuthenticationMode", "IEEE11iEncryptionModes",
                    "Channel", "Standard", "BSSID"]:
            found = re.search(rf"<{tag}>(.*?)</{tag}>", block, re.I | re.S)
            if found:
                record[tag] = found.group(1)
        key = re.search(r"<WlKey>(.*?)</WlKey>", block, re.I | re.S)
        if key and key.group(1).strip():
            record["WlKey"] = represent_secret(key.group(1))
        keys = [psk for psk in re.findall(r"<PreSharedKey>(.*?)</PreSharedKey>", block, re.I | re.S) if psk.strip()]
        unique = list(dict.fromkeys(keys))
        if unique:
            record["PreSharedKeys"] = [represent_secret(psk) for psk in unique[:4]]
        if record:
            wifi.append(record)
    if wifi:
        out["wifi"] = wifi

    wan = []
    for tag_name in ["WANPPPConnection", "WANIPConnection"]:
        for match in re.finditer(rf"<{tag_name}[^>]*>(.*?)</{tag_name}>", text, re.I | re.S):
            block = match.group(1)
            record: Dict[str, Any] = {"type": tag_name}
            for field in ["Username", "Password", "ExternalIPAddress", "DefaultGateway", "DNSServers", "MACAddress",
                          "X_Customer_VLANID", "X_Customer_ServiceList", "Name", "Enable", "ConnectionType",
                          "X_Customer_ConnectionType", "NATEnabled", "X_Customer_IPMode", "AddressingType", "SubnetMask"]:
                found = re.search(rf"<{field}>(.*?)</{field}>", block, re.I | re.S)
                if found:
                    record[field] = represent_secret(found.group(1)) if "Password" in field else found.group(1)
            if len(record) > 1 and any(k in record for k in ["Username", "Password", "ExternalIPAddress",
                                                              "X_Customer_ServiceList", "DNSServers"]):
                wan.append(record)
    if wan:
        out["wan_connections"] = wan

    lan = []
    for match in re.finditer(r"<LANHostConfigManagement>(.*?)</LANHostConfigManagement>", text, re.I | re.S):
        block = match.group(1)
        record = {}
        for field in ["DHCPServerEnable", "MinAddress", "MaxAddress", "SubnetMask", "DHCPLeaseTime", "DNSServers"]:
            found = re.search(rf"<{field}>(.*?)</{field}>", block, re.I | re.S)
            if found:
                record[field] = found.group(1)
        ip = re.search(r"<IPInterfaceIPAddress>(.*?)</IPInterfaceIPAddress>", block, re.I | re.S)
        if ip:
            record["LAN_IP"] = ip.group(1)
        if record:
            lan.append(record)
    if lan:
        out["lan"] = lan

    credentials = []
    pattern = r"<([A-Za-z0-9_]*(?:Password|Passwd|KeyPassphrase|PreSharedKey|WlKey|PSK)[A-Za-z0-9_]*)>(.*?)</\1>"
    for match in re.finditer(pattern, text, re.I | re.S):
        if match.group(2).strip():
            credentials.append({"tag": match.group(1), "value": represent_secret(match.group(2))})
    if credentials:
        out["all_credential_like_fields_found"] = credentials[:150]
    return out


def extract_structured(body: bytes) -> Dict[str, Any]:
    """Parse XML when possible, always fall back to tolerant regex extraction."""
    raw_text = decode_bytes(body.replace(b"\x00", b""))
    text = decode_bytes(sanitize_xml_bytes(body))
    fallback = merge_extracted(regex_extract(raw_text), regex_extract(text))
    try:
        ET.fromstring(text)
    except Exception as exc:
        notes = dict(fallback)
        notes["parse_note"] = f"XML parse fallback used ({exc})"
        return notes
    return merge_extracted(regex_extract(raw_text), fallback)


def fingerprint_hints(headers: Dict[str, str], body: bytes, extracted: Dict[str, Any]) -> List[str]:
    hints: List[str] = []
    server = headers.get("Server") or headers.get("server") or ""
    text = decode_bytes(sanitize_xml_bytes(body))
    low = text.lower()
    if server:
        hints.append(f"HTTP Server header: {server}")
        if "ty_httpd" in server.lower():
            hints.append("Profile hint: ty_httpd-style management interface (seen on some SCTY GPON CPEs)")
    if "<dslcpeconfig" in low:
        hints.append("Config schema: DslCpeConfig (TR-069/CWMP-style XML)")
    device = extracted.get("device_info") or {}
    vendor = str(device.get("TrueVendorID") or device.get("Manufacturer") or "")
    product = str(device.get("ProductClass") or device.get("Product_ID") or device.get("ModelName") or "")
    if vendor or product:
        hints.append(f"Device identifiers present: vendor={vendor or '?'} model={product or '?'}")
    if "scty" in (vendor + " " + server).lower() or "tg2212" in product.lower():
        hints.append("Compatibility hint: resembles SCTY TG2212-class GPON CPE profile")
    if "InternetGatewayDevice" in text and "ManagementServer" in text:
        hints.append("TR-069/CWMP management structures present")
    return hints


# ---------------------------------------------------------------------------
# 4. Analysis & scoring
# ---------------------------------------------------------------------------

CONFIG_MARKERS = [
    "<DslCpeConfig", "InternetGatewayDevice", "<WLAN", "<Password", "<PreSharedKey",
    "ManagementServer", "WANPPPConnection", "WANIPConnection", "TR-069", "cwmp",
    "X_BROADCOM", "LANDevice", "DeviceInfo", "SSID", "TeleComAccount", "config",
]

SENSITIVE_KEYS = ["admin_web_account", "user_gui_account", "service_accounts", "tr069_acs",
                  "wifi", "wan_connections", "all_credential_like_fields_found"]


def analyze_body(body: bytes, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    headers = headers or {}
    text = decode_bytes(sanitize_xml_bytes(body))
    markers = sum(1 for marker in CONFIG_MARKERS if marker.lower() in text.lower())
    extracted: Dict[str, Any] = {}
    if "<" in text and (markers >= 2 or "xml" in text[:200].lower()):
        extracted = extract_structured(body)
    hits = 0
    for key in SENSITIVE_KEYS:
        if key in extracted:
            value = extracted[key]
            hits += len(value) if isinstance(value, list) else 1
    return {
        "bytes": len(body),
        "config_markers": markers,
        "sensitive_hits": hits,
        "fingerprint_hints": fingerprint_hints(headers, body, extracted) if body else [],
        "extracted": extracted,
        "sample_head": text[:300],
    }


def verdict_for(status: Optional[int], body: bytes, analysis: Dict[str, Any]) -> str:
    if status == 200 and body:
        if analysis.get("config_markers", 0) >= 2 and analysis.get("sensitive_hits", 0) >= 1:
            return "LIKELY_EXPOSED_UNAUTH_CONFIG"
        if analysis.get("sensitive_hits", 0) >= 1:
            return "POSSIBLE_SENSITIVE_DISCLOSURE"
        if analysis.get("config_markers", 0) >= 2:
            return "LIKELY_EXPOSED_CONFIG"
        return "ACCESSIBLE_BUT_NO_CLEAR_SECRETS_DETECTED"
    if status in (401, 403):
        return "PROTECTED_OR_FORBIDDEN"
    if status == 404:
        return "NOT_FOUND"
    if status is None:
        return "INCONCLUSIVE"
    return "INCONCLUSIVE"


def risk_assessment(extracted: Dict[str, Any]) -> Dict[str, Any]:
    has_admin = bool(extracted.get("admin_web_account"))
    has_wifi = bool(extracted.get("wifi"))
    has_tr069 = bool(extracted.get("tr069_acs"))
    has_wan = bool(extracted.get("wan_connections"))
    has_user = bool(extracted.get("user_gui_account") or extracted.get("service_accounts"))
    impacts: List[str] = []
    if has_admin:
        impacts.append("Administrative account material exposed - may enable full device management access if reused/valid.")
    if has_wifi:
        impacts.append("Wireless credentials/keys exposed - may enable unauthorized network access and traffic visibility.")
    if has_tr069:
        impacts.append("Remote management (TR-069/ACS/CWMP) details exposed - may increase remote provisioning abuse risk.")
    if has_wan:
        impacts.append("WAN/PPPoE/service details exposed - may aid service abuse, impersonation, or targeted attacks.")
    if has_user:
        impacts.append("Additional user/service account material exposed.")
    if not impacts:
        impacts.append("Configuration disclosure may reveal sensitive operational details.")
    return {
        "impact_assessment": "high" if (has_admin or has_wifi or has_tr069 or has_wan) else "moderate",
        "potential_impacts": impacts,
        "factors": [
            "Reachability matters: LAN/Wi-Fi exposure differs from internet/WAN exposure.",
            "No authentication required for the exposed endpoint increases risk when reachable.",
            "Router/gateway compromise can have downstream impact on connected devices and traffic.",
            "Actual impact depends on credential validity, service exposure, and mitigations - assess in your environment.",
        ],
        "note": "This tool reports observed exposure and indicators; it does not assign a definitive severity/CVSS score.",
    }


def exposure_score(result: Dict[str, Any]) -> Dict[str, Any]:
    """Heuristic 0-100 exposure score. Informational only - not CVSS."""
    extracted = result.get("consolidated_extracted") or {}
    score = 0
    reasons: List[str] = []
    if result.get("vulnerable_indicators"):
        score += 30
        reasons.append("sensitive unauthenticated config indicators")
    categories = [key for key in ("admin_web_account", "user_gui_account", "service_accounts",
                                  "wifi", "tr069_acs", "wan_connections") if extracted.get(key)]
    score += min(30, len(categories) * 7)
    if categories:
        reasons.append(f"{len(categories)} sensitive config categories extracted")
    credential_fields = extracted.get("all_credential_like_fields_found") or []
    score += min(10, len(credential_fields) * 2)
    max_markers = max((path.get("analysis", {}).get("config_markers", 0)
                       for path in result.get("paths", [])), default=0)
    score += min(15, max_markers * 2)
    if max_markers:
        reasons.append(f"{max_markers} config schema markers")
    if not result.get("vulnerable_indicators"):
        score = min(score, 35)
    score = max(0, min(100, score))
    if score >= 80:
        label, color = "CRITICAL", "bright_red"
    elif score >= 60:
        label, color = "HIGH", "red"
    elif score >= 35:
        label, color = "MEDIUM", "yellow"
    elif score > 0:
        label, color = "LOW", "cyan"
    else:
        label, color = "INFO", "green"
    return {"score": score, "label": label, "color": color, "reasons": reasons}


# ---------------------------------------------------------------------------
# 5. Scanning
# ---------------------------------------------------------------------------


def check_target(base: str, paths: List[str], timeout: float, user_agent: str,
                 concurrency: int = 6, progress: Optional[Progress] = None) -> Dict[str, Any]:
    """Probe endpoints in parallel, then assemble results in path order."""
    result: Dict[str, Any] = {
        "target": base, "checked_at_utc": utc_now(), "paths": [],
        "vulnerable_indicators": False, "mode": "live-read-only",
    }
    normalized = [p if p.startswith("/") else "/" + p for p in paths]

    def probe(path: str) -> Tuple[int, str, Dict[str, Any]]:
        index = normalized.index(path)
        status, headers, body, error = fetch(base + path, timeout, user_agent)
        entry: Dict[str, Any] = {
            "url": base + path,
            "status": status,
            "error": error,
            "server": headers.get("Server") or headers.get("server"),
            "content_type": headers.get("Content-Type") or headers.get("content-type"),
        }
        analysis = analyze_body(body, headers) if (status == 200 and body) else {}
        if analysis:
            entry["analysis"] = analysis
        entry["verdict"] = verdict_for(status, body or b"", analysis)
        return index, path, entry

    collected: Dict[int, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(probe, path): path for path in dict.fromkeys(normalized)}
        for future in as_completed(futures):
            path = futures[future]
            try:
                index, _, entry = future.result()
                collected[index] = entry
            except Exception as exc:
                collected[normalized.index(path)] = {"url": base + path, "status": None,
                                                      "error": f"worker error: {exc}", "verdict": "INCONCLUSIVE"}
            if progress:
                progress.tick(path)
    if progress:
        progress.finish()

    merged: Dict[str, Any] = {}
    any_vuln = False
    for index in sorted(collected):
        entry = collected[index]
        analysis = entry.get("analysis") or {}
        extracted = analysis.get("extracted") or {}
        if extracted:
            merged = merge_extracted(extracted, merged)
        if entry.get("verdict") in ("LIKELY_EXPOSED_UNAUTH_CONFIG",
                                    "POSSIBLE_SENSITIVE_DISCLOSURE", "LIKELY_EXPOSED_CONFIG"):
            any_vuln = True
        result["paths"].append(entry)

    result["vulnerable_indicators"] = any_vuln
    if merged:
        result["consolidated_extracted"] = merged
        if any_vuln:
            result["risk_assessment"] = risk_assessment(merged)
    result["exposure"] = exposure_score(result)
    result["summary"] = (
        "Potential unauthenticated sensitive config exposure detected (verify in authorized context)."
        if any_vuln else
        "No clear unauthenticated config exposure detected by this read-only check."
    )
    result["access_condition"] = (
        "Requires network reachability to the device web interface (LAN/Wi-Fi after connecting, "
        "or WAN if remotely exposed). No prior authentication required for exposed endpoints."
    )
    return result


def check_file(path: str) -> Dict[str, Any]:
    with open(path, "rb") as handle:
        body = handle.read()
    analysis = analyze_body(body, {})
    extracted = analysis.get("extracted") or {}
    verdict = "LIKELY_EXPOSED_UNAUTH_CONFIG" if (analysis.get("config_markers", 0) >= 2
                                                 and analysis.get("sensitive_hits", 0)) else "PARSED"
    result: Dict[str, Any] = {
        "target": "file://" + os.path.abspath(path),
        "checked_at_utc": utc_now(),
        "mode": "offline-file",
        "paths": [{"url": "file://" + os.path.abspath(path), "status": 200,
                   "verdict": verdict, "analysis": analysis}],
        "vulnerable_indicators": analysis.get("sensitive_hits", 0) > 0,
        "consolidated_extracted": extracted,
        "summary": "Offline analysis of provided config file (for authorized review).",
        "access_condition": "Offline file analysis (no network request).",
    }
    if extracted and result["vulnerable_indicators"]:
        result["risk_assessment"] = risk_assessment(extracted)
    result["exposure"] = exposure_score(result)
    return result


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

SECRET_KEYS = {"password", "passwd", "psk", "key", "keypassphrase", "presharedkey",
               "wlkey", "secret", "passphrase"}
REDACTED_FIELDS = ("raw", "recovered", "decoded_base64", "decoded_base64_xor80",
                   "xor80_of_raw", "printable_view", "hex")


def is_secret_field_name(name: str) -> bool:
    return any(token in (name or "").lower() for token in SECRET_KEYS)


def redact_value(value: Any) -> Any:
    if isinstance(value, dict) and "recovered" in value:
        out = dict(value)
        for key in list(out):
            if key in REDACTED_FIELDS and out[key] is not None:
                out[key] = "[REDACTED]"
        return out
    return "[REDACTED]"


def redact_obj(obj: Any, key_hint: str = "") -> Any:
    if isinstance(obj, dict):
        if "recovered" in obj and any(k in obj for k in ("raw", "hex", "decoded_base64", "decoded_base64_xor80")):
            return redact_value(obj)
        out = {}
        for key, value in obj.items():
            if is_secret_field_name(key):
                out[key] = ([redact_obj(item, key) for item in value] if isinstance(value, list)
                            else redact_obj(value, key) if isinstance(value, dict) and "recovered" not in value
                            else redact_value(value))
            else:
                out[key] = redact_obj(value, key)
        return out
    if isinstance(obj, list):
        return [redact_obj(item, key_hint) for item in obj]
    if is_secret_field_name(key_hint) and obj is not None:
        return redact_value(obj) if isinstance(obj, dict) else "[REDACTED]"
    return obj


def apply_redaction(report: Dict[str, Any], redact: bool) -> Dict[str, Any]:
    if not redact:
        return report
    out = copy.deepcopy(report)
    out["redacted"] = True
    for result in out.get("results", []):
        for path in result.get("paths", []):
            analysis = path.get("analysis") or {}
            if "extracted" in analysis:
                analysis["extracted"] = redact_obj(analysis["extracted"])
            if "sample_head" in analysis:
                analysis["sample_head"] = "[REDACTED FOR SHARING]"
        if "consolidated_extracted" in result:
            result["consolidated_extracted"] = redact_obj(result["consolidated_extracted"])
    return out


def fmt_secret(value: Any) -> str:
    if isinstance(value, dict) and "recovered" in value:
        text = str(value.get("recovered"))
        if text == "[REDACTED]":
            return text
        extras: List[str] = []
        for key, label in (("decoded_base64", "b64"), ("hex", "hex"),
                           ("printable_view", "printable"), ("decoded_base64_xor80", "b64-xor80")):
            if value.get(key) and str(value.get(key)) != text:
                extras.append(f"{label}={value.get(key)}")
        return text + ("  [" + "; ".join(extras) + "]" if extras else "")
    return str(value)


# ---------------------------------------------------------------------------
# 6. Reporting
# ---------------------------------------------------------------------------


def pretty_print(report: Dict[str, Any], color: bool = True, quiet: bool = False,
                 duration: float = 0.0) -> None:
    if quiet:
        for result in report.get("results", []):
            score = result.get("exposure", {}).get("score", 0)
            label = result.get("exposure", {}).get("label", "INFO")
            status = "INDICATORS" if result.get("vulnerable_indicators") else "NO_CLEAR_FINDING"
            print(f"{c('[!]', 'bright_red', color)} {result['target']}: {status} "
                  f"({label} {score}/100) - {result['summary']}")
        return

    if not report.get("quiet_banner"):
        show_banner(color)
        print(c(f"  mode    : {report.get('mode', 'read-only')}", "dim", color))
        print(c(f"  generated: {report.get('generated_at_utc')} UTC", "dim", color))
        print(rule("=", 72, "dim", color))

    results = report.get("results", [])
    for index, result in enumerate(results, 1):
        indicators = result.get("vulnerable_indicators")
        target_color = "bright_red" if indicators else "bright_green"
        icon = "!" if indicators else "+"
        print("\n  " + c(f"[{icon}] TARGET {index}/{len(results)}", target_color, color, bold=True)
              + "  " + c(str(result["target"]), "white", color, bold=True))
        print("  " + c("-" * 72, "dim", color))

        for path in result.get("paths", []):
            print(f"    {c('+', 'dim', color)} {c(path.get('url', ''), 'white', color, bold=True)}")
            print(f"      {c('verdict', 'cyan', color)} : {verdict_badge(path.get('verdict', ''), color)}")
            status_color = "green" if path.get("status") in (200, 401, 403, 404) else "yellow"
            print(f"      {c('status', 'cyan', color)}  : {c(str(path.get('status')), status_color, color, bold=True)}"
                  f"   server={path.get('server') or '-'}")
            if path.get("error"):
                print(f"      {c('error', 'cyan', color)}   : {c(str(path.get('error')), 'yellow', color)}")
            analysis = path.get("analysis") or {}
            if analysis:
                hits = analysis.get("sensitive_hits", 0)
                print(f"      {c('signals', 'cyan', color)} : bytes={analysis.get('bytes')}  "
                      f"markers={analysis.get('config_markers')}  "
                      f"sensitive_hits={c(str(hits), 'bright_red' if hits else 'green', color, bold=True)}")
                for hint in (analysis.get("fingerprint_hints") or [])[:8]:
                    print(f"      {c('|', 'dim', color)}   - {hint}")

        extracted = result.get("consolidated_extracted") or {}

        if extracted.get("device_info"):
            section("DEVICE FINGERPRINT", "CRT", "magenta", color)
            for key, value in extracted["device_info"].items():
                kv(key, value, color)

        if extracted.get("admin_web_account"):
            section("ADMIN / WEB ACCOUNT", "KEY", "bright_red", color)
            account = extracted["admin_web_account"]
            kv("username", account.get("username"), color)
            if account.get("password") is not None:
                kv("password", c(fmt_secret(account["password"]), "yellow", color, bold=True), color)

        if extracted.get("user_gui_account"):
            section("USER GUI ACCOUNT", "USR", "yellow", color)
            account = extracted["user_gui_account"]
            kv("username", account.get("username"), color)
            if account.get("password") is not None:
                kv("password", c(fmt_secret(account["password"]), "yellow", color), color)

        if extracted.get("service_accounts"):
            section("SERVICE ACCOUNTS", "SRV", "yellow", color)
            for key, value in extracted["service_accounts"].items():
                kv(key, fmt_secret(value), color)

        if extracted.get("wifi"):
            section("WIFI / WLAN", "WIFI", "bright_cyan", color)
            for i, network in enumerate(extracted["wifi"], 1):
                if not (network.get("SSID") or network.get("WlKey") or network.get("PreSharedKeys")):
                    continue
                ssid = network.get("SSID") or "(hidden/unknown)"
                enabled = str(network.get("Enable")) == "1"
                state = c("ENABLED", "bright_green", color, bold=True) if enabled else c("DISABLED", "dim", color)
                print(f"    {c('>', 'bright_cyan', color)} #{i} SSID={c(str(ssid), 'white', color, bold=True)}  {state}")
                print(f"      Beacon={network.get('BeaconType')}  Auth={network.get('WPAAuthenticationMode')}  "
                      f"Cipher={network.get('IEEE11iEncryptionModes')}")
                if network.get("WlKey"):
                    print(f"      WlKey: {c(fmt_secret(network['WlKey']), 'yellow', color)}")
                for j, psk in enumerate(network.get("PreSharedKeys", []), 1):
                    print(f"      PSK[{j}]: {c(fmt_secret(psk), 'yellow', color)}")

        if extracted.get("tr069_acs"):
            section("TR-069 / ACS / CWMP", "ACS", "yellow", color)
            for key, value in extracted["tr069_acs"].items():
                kv(key, fmt_secret(value), color)

        if extracted.get("wan_connections"):
            section("WAN / PPPoE / IP", "WAN", "bright_cyan", color)
            for i, wan in enumerate(extracted["wan_connections"], 1):
                print(f"    {c('>', 'bright_cyan', color)} #{i} {wan.get('type')}  "
                      f"service={wan.get('X_Customer_ServiceList')}  name={wan.get('Name')}")
                for key in ["Username", "Password", "ExternalIPAddress", "DefaultGateway", "DNSServers",
                            "MACAddress", "X_Customer_VLANID", "NATEnabled", "AddressingType"]:
                    if key in wan:
                        print(f"      {key}: {fmt_secret(wan[key])}")

        if extracted.get("lan"):
            section("LAN", "LAN", "green", color)
            for lan in extracted["lan"]:
                for key, value in lan.items():
                    kv(key, value, color)

        risk = result.get("risk_assessment")
        if risk:
            section("IMPACT ASSESSMENT (informational, not CVSS)", "RISK", "yellow", color)
            kv("impact level", c(risk.get("impact_assessment", "").upper(), "yellow", color, bold=True), color)
            for impact in risk.get("potential_impacts", []):
                print("    - " + impact)

        exposure = result.get("exposure") or {}
        score = exposure.get("score", 0)
        score_color = exposure.get("color", "green")
        section("EXPOSURE SCORE (heuristic, not CVSS)", "SCORE", score_color, color)
        print("    " + meter(score, score_color, color))
        print("    " + c(exposure.get("label", "INFO"), score_color, color, bold=True)
              + "  " + ", ".join(exposure.get("reasons", []) or ["no strong indicators"]))

        section("ACCESS CONDITION", "NET", "cyan", color)
        print("    " + str(result.get("access_condition")))
        section("COMPATIBILITY NOTES", "INFO", "cyan", color)
        for note in COMPAT_NOTES:
            print("    - " + note)

        box_color = "bright_red" if indicators else "bright_green"
        summary_label = "INDICATORS DETECTED" if indicators else "NO CLEAR INDICATORS"
        panel([f"{c(summary_label, box_color, color, bold=True)}  {result['summary']}"],
              "VERDICT", box_color, color)

        if report.get("redacted"):
            print(c("    (secret values redacted for sharing)", "dim", color))

    # session dashboard
    findings = sum(1 for r in results if r.get("vulnerable_indicators"))
    endpoints = sum(len(r.get("paths", [])) for r in results)
    top_score = max((r.get("exposure", {}).get("score", 0) for r in results), default=0)
    top_label = max(results, key=lambda r: r.get("exposure", {}).get("score", 0)).get("exposure", {}).get("label", "INFO") if results else "INFO"
    dash_color = "bright_red" if findings else "bright_green"
    panel([
        f"targets   : {len(results)}     endpoints probed : {endpoints}",
        f"findings  : {findings}     elapsed          : {duration:.1f}s",
        f"top score : {top_label} ({top_score}/100)",
        "",
        c("next: verify in an authorized context, restrict access, rotate exposed secrets", "dim", color),
        c("tip : use --redact before sharing reports", "dim", color),
    ], "SESSION SUMMARY", dash_color, color)
    print()


def write_html(report: Dict[str, Any], path: str) -> None:
    def esc(value: Any) -> str:
        return html.escape(str(value))

    def pre(obj: Any) -> str:
        return "<pre>" + esc(json.dumps(obj, indent=2, ensure_ascii=False)) + "</pre>" if obj else "<em>None</em>"

    cards = []
    for result in report.get("results", []):
        extracted = result.get("consolidated_extracted") or {}
        exposure = result.get("exposure") or {}
        score = exposure.get("score", 0)
        label = exposure.get("label", "INFO")
        verdict = "FINDINGS" if result.get("vulnerable_indicators") else "CLEAR"
        tone = "bad" if result.get("vulnerable_indicators") else "good"
        cards.append(f"""
        <section class="card {tone}">
          <h2>{esc(result.get('target'))} <span class="pill {tone}">{verdict}</span></h2>
          <p class="meta">{esc(result.get('summary'))}</p>
          <div class="score"><span>{esc(label)}</span><div class="bar"><i style="width:{score}%"></i></div><b>{score}/100</b></div>
          <h3>Device</h3>{pre(extracted.get('device_info'))}
          <h3>Admin / web account</h3>{pre(extracted.get('admin_web_account'))}
          <h3>User GUI account</h3>{pre(extracted.get('user_gui_account'))}
          <h3>Service accounts</h3>{pre(extracted.get('service_accounts'))}
          <h3>Wi-Fi</h3>{pre(extracted.get('wifi'))}
          <h3>TR-069 / ACS / CWMP</h3>{pre(extracted.get('tr069_acs'))}
          <h3>WAN</h3>{pre(extracted.get('wan_connections'))}
          <h3>LAN</h3>{pre(extracted.get('lan'))}
          <h3>Impact assessment</h3>{pre(result.get('risk_assessment'))}
        </section>""")

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(TOOL_NAME)} report</title>
<style>
:root{{--bg:#0b1020;--card:#151c31;--ink:#e8edf7;--muted:#9aa7c2;--line:#2a3554;--good:#3ddc97;--bad:#ff5c7a;--accent:#5eead4}}
*{{box-sizing:border-box}}body{{margin:0;padding:2rem;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,Segoe UI,Roboto,sans-serif}}
h1{{margin:0 0 .25rem;font-size:2rem;background:linear-gradient(90deg,#5eead4,#a78bfa);-webkit-background-clip:text;color:transparent}}
.meta{{color:var(--muted)}}.card{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--good);border-radius:14px;padding:1.25rem 1.5rem;margin:1.5rem 0;box-shadow:0 8px 30px #0006}}
.card.bad{{border-left-color:var(--bad)}}h2{{margin-top:.2rem;font-size:1.2rem;word-break:break-all}}h3{{color:var(--accent);font-size:.85rem;text-transform:uppercase;letter-spacing:.08em;margin:1.2rem 0 .4rem}}
.pill{{font-size:.7rem;padding:.2rem .6rem;border-radius:99px;vertical-align:middle}}.pill.good{{background:#3ddc9722;color:var(--good)}}.pill.bad{{background:#ff5c7a22;color:var(--bad)}}
.score{{display:flex;align-items:center;gap:1rem;margin:.8rem 0}}.bar{{flex:1;height:10px;background:#ffffff12;border-radius:99px;overflow:hidden}}.bar i{{display:block;height:100%;background:linear-gradient(90deg,#3ddc97,#ffd166,#ff5c7a)}}
pre{{background:#0d1426;padding:1rem;border:1px solid var(--line);border-radius:8px;overflow:auto;max-height:340px;color:#cfe3ff}}footer{{color:var(--muted);margin-top:2rem;font-size:.85rem}}
</style></head><body>
<h1>{esc(TOOL_NAME)} <span class="pill">v{esc(report.get('version',''))}</span></h1>
<p class="meta">Generated {esc(report.get('generated_at_utc',''))} UTC &middot; mode: {esc(report.get('mode',''))}
{' &middot; REDACTED' if report.get('redacted') else ''}</p>
{''.join(cards)}
<footer>Informational indicators only - not a CVSS score. Authorized testing only.</footer>
</body></html>"""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(document)


def write_markdown(report: Dict[str, Any], path: str) -> None:
    lines = [f"# {TOOL_NAME} report", "",
             f"- Generated: {report.get('generated_at_utc')} UTC",
             f"- Version: {report.get('version')}",
             f"- Mode: {report.get('mode')}"]
    if report.get("redacted"):
        lines.append("- **REDACTED:** secret values masked for sharing")
    lines.append("")
    for result in report.get("results", []):
        extracted = result.get("consolidated_extracted") or {}
        exposure = result.get("exposure") or {}
        lines += [f"## Target: `{result.get('target')}`", "",
                  f"| Field | Value |", f"|---|---|",
                  f"| Verdict | {'FINDINGS' if result.get('vulnerable_indicators') else 'CLEAR'} |",
                  f"| Exposure | {exposure.get('label')} ({exposure.get('score')}/100) |",
                  f"| Summary | {result.get('summary')} |",
                  f"| Access | {result.get('access_condition')} |", ""]

        def block(title: str, obj: Any) -> None:
            if not obj:
                return
            lines.extend([f"### {title}", "```json",
                          json.dumps(obj, indent=2, ensure_ascii=False), "```", ""])

        for title, key in (("Device info", "device_info"), ("Admin/web account", "admin_web_account"),
                           ("User GUI account", "user_gui_account"), ("Service accounts", "service_accounts"),
                           ("Wi-Fi", "wifi"), ("TR-069/ACS/CWMP", "tr069_acs"),
                           ("WAN", "wan_connections"), ("LAN", "lan")):
            block(title, extracted.get(key))
        block("Impact assessment (informational)", result.get("risk_assessment"))
        block("Exposure score", exposure)
    lines += ["---", "", "*Informational indicators only - not a CVSS score. Authorized testing only.*"]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


# ---------------------------------------------------------------------------
# 7. CLI
# ---------------------------------------------------------------------------

EXAMPLES = """examples:
  router-config-xray --demo                          run the bundled safe demo (no network)
  router-config-xray --file dump.xml                 analyze a local config offline
  router-config-xray --target 192.168.0.1            scan one authorized target
  router-config-xray -t 192.168.0.1 --all-paths      probe the full read-only wordlist
  router-config-xray --targets-file hosts.txt --quiet --redact
  router-config-xray --demo --outdir ./evidence     write JSON + HTML + Markdown at once

authorized use only - read-only, no login, no state changes, no firmware flashing"""


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="router-config-xray",
        description="Read-only scanner for unauthenticated router/CPE config exposure.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-t", "--target", help="Target base URL or IP/host (e.g. http://192.168.0.1)")
    source.add_argument("--targets-file", help="File with one target per line")
    source.add_argument("-f", "--file", help="Analyze a local config file offline (no network)")
    source.add_argument("--demo", action="store_true", help="Run the bundled fictional demo (no network/files)")
    parser.add_argument("-p", "--paths", default=",".join(DEFAULT_PATHS), help="Comma-separated paths to check")
    parser.add_argument("--paths-file", help="File with one path per line (combined with --paths)")
    parser.add_argument("--all-paths", action="store_true", help="Include the expanded read-only wordlist")
    parser.add_argument("--list-paths", action="store_true", help="Print the built-in path wordlist and exit")
    parser.add_argument("--timeout", type=float, default=6.0, help="HTTP timeout seconds (default: 6)")
    parser.add_argument("--concurrency", type=int, default=6, help="Parallel endpoint probes (default: 6)")
    parser.add_argument("--user-agent", default=f"{TOOL_NAME}/{VERSION} (authorized-test)", help="User-Agent header")
    parser.add_argument("--json", dest="json_out", help="Write JSON report to file")
    parser.add_argument("--html", dest="html_out", help="Write HTML report to file")
    parser.add_argument("--md", dest="md_out", help="Write Markdown report to file")
    parser.add_argument("--outdir", help="Write report.json, report.html and report.md into this directory")
    parser.add_argument("--redact", action="store_true", help="Mask secret values (useful for sharing)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors and animation")
    parser.add_argument("--quiet", action="store_true", help="Print one summary line per target")
    parser.add_argument("--self-test", action="store_true", help="Run internal checks and exit")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    return parser.parse_args(argv)


def self_test() -> int:
    """Small internal sanity suite; no external dependencies."""
    checks: List[Tuple[str, bool]] = []
    checks.append(("normalize IP", normalize_target("192.0.2.1") == "http://192.0.2.1"))
    checks.append(("normalize URL", normalize_target("https://x.example/") == "https://x.example"))
    checks.append(("verdict 200", verdict_for(200, b"<DslCpeConfig><Password>x</Password></DslCpeConfig>",
                                              analyze_body(b"<DslCpeConfig><Password>x</Password></DslCpeConfig>"))
                   == "LIKELY_EXPOSED_UNAUTH_CONFIG"))
    checks.append(("verdict 403", verdict_for(403, b"", {}) == "PROTECTED_OR_FORBIDDEN"))
    sample = b"<DslCpeConfig><X_Customer_TeleComAccount><Password>abc</Password></X_Customer_TeleComAccount></DslCpeConfig>"
    checks.append(("extract account", bool(analyze_body(sample)["extracted"].get("admin_web_account"))))
    redacted = apply_redaction({"results": [{"paths": [{"analysis": {"sample_head": "secret"}}]}]}, True)
    checks.append(("redaction", redacted["results"][0]["paths"][0]["analysis"]["sample_head"] == "[REDACTED FOR SHARING]"))
    score = exposure_score({"vulnerable_indicators": True, "consolidated_extracted": {"wifi": []}, "paths": []})
    checks.append(("scoring", 0 <= score["score"] <= 100))
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    failed = [name for name, passed in checks if not passed]
    if failed:
        print(f"\n  {len(failed)} check(s) failed")
        return EXIT_ERROR
    print(f"\n  All {len(checks)} internal checks passed.")
    return EXIT_CLEAN


def load_paths(args: argparse.Namespace) -> List[str]:
    paths = [p.strip() for p in args.paths.split(",") if p.strip()]
    if args.paths_file:
        with open(args.paths_file, "r", encoding="utf-8") as handle:
            paths += [line.strip() for line in handle if line.strip() and not line.strip().startswith("#")]
    if args.all_paths:
        paths += [p for p in EXTRA_PATHS if p not in paths]
    return list(dict.fromkeys(paths))


def _run(args: argparse.Namespace) -> int:
    """Execute a parsed command. Callers must handle unexpected I/O errors."""
    started = time.monotonic()

    if args.timeout <= 0:
        print("error: --timeout must be greater than 0", file=sys.stderr)
        return EXIT_ERROR
    if args.concurrency < 1:
        print("error: --concurrency must be at least 1", file=sys.stderr)
        return EXIT_ERROR

    if args.self_test:
        return self_test()

    if args.list_paths:
        print("Default paths:")
        for path in DEFAULT_PATHS:
            print(f"  {path}")
        print("\nAdditional paths (--all-paths):")
        for path in EXTRA_PATHS:
            print(f"  {path}")
        return EXIT_CLEAN

    if not (args.target or args.targets_file or args.file or args.demo):
        print("error: supply --target, --targets-file, --file, or --demo (or --list-paths)", file=sys.stderr)
        return EXIT_ERROR

    use_color = color_enabled(args.no_color)
    animate = use_color and not args.quiet and sys.stdout.isatty()
    paths = load_paths(args)

    if args.demo:
        demo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "samples", "decoy_config.xml")
        if not os.path.exists(demo_file):
            print("error: bundled demo sample is missing", file=sys.stderr)
            return EXIT_ERROR
        results = [check_file(demo_file)]
        targets = 1
        endpoints = 1
    elif args.file:
        results = [check_file(args.file)]
        targets = 1
        endpoints = 1
    else:
        targets_list = [normalize_target(args.target)] if args.target else []
        if args.targets_file:
            with open(args.targets_file, "r", encoding="utf-8") as handle:
                targets_list += [normalize_target(line) for line in handle
                                 if line.strip() and not line.strip().startswith("#")]
        targets_list = list(dict.fromkeys(targets_list))
        targets, endpoints = len(targets_list), len(paths)
        if not args.quiet:
            show_banner(use_color)
            print(c(f"  plan    : {targets} target(s) x {endpoints} endpoint(s) = "
                    f"{targets * endpoints} read-only GET request(s)", "bright_cyan", use_color, bold=True))
            print(c(f"  workers : {args.concurrency}   timeout: {args.timeout}s   "
                    f"animation: {'on' if animate else 'off'}", "dim", use_color))
            print(rule("=", 72, "dim", use_color))
        results = []
        for target in targets_list:
            progress = Progress(endpoints, animate, label=f"scanning {target[:24]}")
            results.append(check_target(target, paths, args.timeout, args.user_agent,
                                        args.concurrency, progress))

    report: Dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "mode": "read-only (no login, no state changes, no persistence/backdoor, no firmware flashing)",
        "generated_at_utc": utc_now(),
        "compatibility_notes": COMPAT_NOTES,
        "scan_plan": {"targets": targets, "endpoints_per_target": endpoints,
                      "concurrency": args.concurrency, "timeout_seconds": args.timeout},
        "results": results,
    }
    out_report = apply_redaction(report, args.redact)

    outputs: List[Tuple[str, str]] = []
    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        outputs += [("JSON", os.path.join(args.outdir, "report.json")),
                    ("HTML", os.path.join(args.outdir, "report.html")),
                    ("Markdown", os.path.join(args.outdir, "report.md"))]
    for label, path in (("JSON", args.json_out), ("HTML", args.html_out), ("Markdown", args.md_out)):
        if path:
            outputs.append((label, path))

    for label, path in outputs:
        if label == "JSON":
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(out_report, handle, indent=2, ensure_ascii=False)
        elif label == "HTML":
            write_html(out_report, path)
        else:
            write_markdown(out_report, path)

    duration = time.monotonic() - started
    pretty_print(out_report, color=use_color, quiet=args.quiet, duration=duration)
    for label, path in outputs:
        print(c(f"  {label} report: {path}", "dim", use_color))

    return EXIT_FINDINGS if any(r.get("vulnerable_indicators") for r in results) else EXIT_CLEAN


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point with friendly, traceback-free error handling."""
    args = parse_args(argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
