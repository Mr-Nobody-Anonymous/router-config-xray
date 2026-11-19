#!/usr/bin/env python3
"""
router-config-xray — read-only exposure scanner for unauthenticated router/CPE config endpoints

WHAT IT DOES (authorized security testing only)
- Performs READ-ONLY HTTP GET requests to common config/backup/export endpoints
  (e.g. /config.xml) OR analyzes a local config file (--file).
- If content is reachable/readable, parses and displays exposed configuration in
  clear/recovered form where possible: admin & user accounts, service creds,
  Wi-Fi SSIDs/keys, TR-069/ACS/CWMP settings, WAN/PPPoE details, device IDs, LAN info.
- Generates terminal, JSON, HTML, and Markdown reports for evidence.

WHAT IT DOES NOT DO
- No login/auth attempts, no brute force, no state changes, no persistence/backdoors,
  no firmware flashing/modification, no exploitation beyond reading unauthenticated resources.

Use only on devices/networks you own or have explicit written permission to test.
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
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.1.0"
TOOL_NAME = "router-config-xray"

# Primary/commonly observed exposed endpoint on compatible CPEs
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
    "Best-effort extraction is tuned for DslCpeConfig/TR-069-style XML exports (e.g. configs exposing /config.xml).",
    "Primary observed profile (authorized testing): SCTY TG2212-class GPON CPE/ONT gateways using a ty_httpd-style web interface with unauthenticated /config.xml.",
    "Detection/parsing is generic and may work on other routers/firmwares, but coverage and field mapping vary by model and software.",
]

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                 router-config-xray  v{ver:<5}                ║
║     Read-only scanner for exposed router/CPE config dumps    ║
║           Authorized testing & defensive auditing            ║
╚══════════════════════════════════════════════════════════════╝
""".format(ver=VERSION)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_target(t: str) -> str:
    t = t.strip()
    if not re.match(r"^https?://", t, re.I):
        t = "http://" + t
    return t.rstrip("/")


def c(text: str, color: str, enable: bool = True) -> str:
    if not enable:
        return text
    codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36", "bold": "1", "dim": "2"}
    code = codes.get(color, "0")
    return f"\033[{code}m{text}\033[0m"


def sanitize_xml_bytes(b: bytes) -> bytes:
    return bytes(ch for ch in b if ch in (9, 10, 13) or ch >= 0x20)


def decode_bytes(b: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("latin-1", errors="replace")


def is_mostly_printable(s: str) -> bool:
    if s == "":
        return True
    printable = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in "\t\r\n")
    return printable / max(1, len(s)) >= 0.85


def to_hex(b: bytes) -> str:
    return b.hex(" ")


def try_b64_decode(s: str) -> Optional[bytes]:
    st = (s or "").strip()
    if len(st) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", st):
        return None
    try:
        return base64.b64decode(st + ("=" * ((-len(st)) % 4)), validate=False)
    except Exception:
        return None


def xor80_decode_bytes(b: bytes) -> str:
    return "".join(chr(x ^ 0x80) for x in b)


def represent_secret(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {"raw": None}
    txt = raw if isinstance(raw, str) else str(raw)
    b = txt.encode("latin-1", errors="replace")
    out: Dict[str, Any] = {"raw": txt}
    if not is_mostly_printable(txt) or any(ord(ch) < 32 and ch not in "\r\n\t" for ch in txt):
        out["hex"] = to_hex(b)
        out["printable_view"] = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in txt)
    b64 = try_b64_decode(txt)
    if b64 is not None and 0 < len(b64) <= 256:
        btxt = b64.rstrip(b"\x00")
        try:
            btxt_s = btxt.decode("utf-8")
        except Exception:
            btxt_s = btxt.decode("latin-1", errors="replace")
        if btxt_s and btxt_s != txt and is_mostly_printable(btxt_s) and any(ch.isalnum() for ch in btxt_s):
            out["decoded_base64"] = btxt_s
        x = xor80_decode_bytes(b64)
        if is_mostly_printable(x) and x != txt and any(ch.isalnum() for ch in x):
            out["decoded_base64_xor80"] = x
    if not is_mostly_printable(txt) and b:
        xr = xor80_decode_bytes(b)
        if is_mostly_printable(xr) and xr.strip():
            out["xor80_of_raw"] = xr
    recovered = txt
    if "decoded_base64_xor80" in out:
        recovered = out["decoded_base64_xor80"]
    elif not is_mostly_printable(txt) and "xor80_of_raw" in out:
        recovered = out["xor80_of_raw"]
    out["recovered"] = recovered
    return out


def fetch(url: str, timeout: float, user_agent: str) -> Tuple[Optional[int], Dict[str, str], bytes, Optional[str]]:
    req = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(5_000_000)
            headers = {k: v for k, v in resp.headers.items()}
            return resp.status, headers, body, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(500_000)
        except Exception:
            body = b""
        headers = {k: v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, headers, body, f"HTTPError:{e.code}"
    except Exception as e:
        return None, {}, b"", f"{type(e).__name__}:{e}"


def merge_extracted(primary: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, Any]:
    if not primary:
        return fallback
    out = dict(fallback)
    out.update({k: v for k, v in primary.items() if v})
    for k, v in fallback.items():
        if k not in out or not out[k]:
            out[k] = v
    return out


def regex_extract(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    def grab_tag(tag: str) -> Optional[str]:
        m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.I | re.S)
        return m.group(1) if m else None

    dev = {}
    for t in ["ManufacturerOUI", "ProductClass", "ModelName", "SerialNumber", "DeviceSerialNumber",
              "HardwareVersion", "SoftwareVersion", "X_Customer_MACAddress", "TrueVendorID",
              "AccessType", "FirstUseDate", "Manufacturer", "Product_ID"]:
        v = grab_tag(t)
        if v is not None:
            dev[t] = v
    if dev:
        out["device_info"] = dev

    m = re.search(r"<X_Customer_TeleComAccount>(.*?)</X_Customer_TeleComAccount>", text, re.I | re.S)
    if m:
        blk = m.group(1)
        u = re.search(r"<User(?:Name)>(.*?)</User(?:Name)>", blk, re.I | re.S)
        p = re.search(r"<Password>(.*?)</Password>", blk, re.I | re.S)
        out["admin_web_account"] = {"username": (u.group(1) if u else "admin"), "password": represent_secret(p.group(1)) if p else None}

    m = re.search(r"<X_BROADCOM_COM_LoginCfg>(.*?)</X_BROADCOM_COM_LoginCfg>", text, re.I | re.S)
    if m:
        blk = m.group(1)
        u = re.search(r"<User(?:User)?Name>(.*?)</User(?:User)?Name>", blk, re.I | re.S)
        p = re.search(r"<UserPassword>(.*?)</UserPassword>", blk, re.I | re.S) or re.search(r"<Password>(.*?)</Password>", blk, re.I | re.S)
        out["user_gui_account"] = {"username": (u.group(1) if u else "user"), "password": represent_secret(p.group(1)) if p else None}

    m = re.search(r"<X_Customer_ServiceManage>(.*?)</X_Customer_ServiceManage>", text, re.I | re.S)
    if m:
        blk = m.group(1)
        svc = {}
        for t in ["FtpUserName", "FtpPassword", "TelnetUserName", "TelnetPassword", "SshUserName", "SshPassword"]:
            mm = re.search(rf"<{t}>(.*?)</{t}>", blk, re.I | re.S)
            if mm:
                svc[t] = represent_secret(mm.group(1)) if "Password" in t else mm.group(1)
        if svc:
            out["service_accounts"] = svc

    tr = {}
    tr_tags = ["URL", "Username", "Password", "PeriodicInformEnable", "PeriodicInformInterval",
               "ConnectionRequestURL", "ConnectionRequestUsername", "ConnectionRequestPassword",
               "X_Customer_Tr69Daemon", "X_Customer_EnableCWMP", "X_Customer_ConnectionRequestPort",
               "X_Customer_EnableCWMPWanAcl", "X_Customer_ACL_IpAndMask", "X_Customer_DataModel", "ParameterKey"]
    ms = re.search(r"<ManagementServer>(.*?)</ManagementServer>", text, re.I | re.S)
    blk = ms.group(1) if ms else ""
    for t in tr_tags:
        mm = re.search(rf"<{t}>(.*?)</{t}>", blk, re.I | re.S) if blk else None
        if not mm:
            mm = re.search(rf"<{t}>(.*?)</{t}>", text, re.I | re.S)
        if mm:
            tr[t] = represent_secret(mm.group(1)) if "Password" in t else mm.group(1)
    if tr:
        out["tr069_acs"] = tr

    wifi = []
    for m in re.finditer(r"<WLANConfiguration[^>]*>(.*?)</WLANConfiguration>", text, re.I | re.S):
        blk = m.group(1)
        ssid_m = re.search(r"<SSID>(.*?)</SSID>", blk, re.I | re.S)
        if not ssid_m and "<WlKey" not in blk and "PreSharedKey" not in blk:
            continue
        rec: Dict[str, Any] = {}
        for t in ["SSID", "Enable", "BeaconType", "WPAAuthenticationMode", "IEEE11iEncryptionModes", "Channel", "Standard", "BSSID"]:
            mm = re.search(rf"<{t}>(.*?)</{t}>", blk, re.I | re.S)
            if mm:
                rec[t] = mm.group(1)
        mm = re.search(r"<WlKey>(.*?)</WlKey>", blk, re.I | re.S)
        if mm and mm.group(1).strip():
            rec["WlKey"] = represent_secret(mm.group(1))
        psks = re.findall(r"<PreSharedKey>(.*?)</PreSharedKey>", blk, re.I | re.S)
        psks = [p for p in psks if p.strip()]
        seen = set()
        up = []
        for p in psks:
            if p in seen:
                continue
            seen.add(p)
            up.append(p)
        if up:
            rec["PreSharedKeys"] = [represent_secret(p) for p in up[:4]]
        if rec:
            wifi.append(rec)
    if wifi:
        out["wifi"] = wifi

    wan = []
    for tag in ["WANPPPConnection", "WANIPConnection"]:
        for m in re.finditer(rf"<{tag}[^>]*>(.*?)</{tag}>", text, re.I | re.S):
            blk = m.group(1)
            rec: Dict[str, Any] = {"type": tag}
            for f in ["Username", "Password", "ExternalIPAddress", "DefaultGateway", "DNSServers", "MACAddress",
                      "X_Customer_VLANID", "X_Customer_ServiceList", "Name", "Enable", "ConnectionType",
                      "X_Customer_ConnectionType", "NATEnabled", "X_Customer_IPMode", "AddressingType", "SubnetMask"]:
                mm = re.search(rf"<{f}>(.*?)</{f}>", blk, re.I | re.S)
                if mm:
                    rec[f] = represent_secret(mm.group(1)) if "Password" in f else mm.group(1)
            if len(rec) > 1 and any(k in rec for k in ["Username", "Password", "ExternalIPAddress", "X_Customer_ServiceList", "DNSServers"]):
                wan.append(rec)
    if wan:
        out["wan_connections"] = wan

    lan = []
    for m in re.finditer(r"<LANHostConfigManagement>(.*?)</LANHostConfigManagement>", text, re.I | re.S):
        blk = m.group(1)
        rec = {}
        for f in ["DHCPServerEnable", "MinAddress", "MaxAddress", "SubnetMask", "DHCPLeaseTime", "DNSServers"]:
            mm = re.search(rf"<{f}>(.*?)</{f}>", blk, re.I | re.S)
            if mm:
                rec[f] = mm.group(1)
        mm = re.search(r"<IPInterfaceIPAddress>(.*?)</IPInterfaceIPAddress>", blk, re.I | re.S)
        if mm:
            rec["LAN_IP"] = mm.group(1)
        if rec:
            lan.append(rec)
    if lan:
        out["lan"] = lan

    creds = []
    for m in re.finditer(r"<([A-Za-z0-9_]*(?:Password|Passwd|KeyPassphrase|PreSharedKey|WlKey|PSK)[A-Za-z0-9_]*)>(.*?)</\1>", text, re.I | re.S):
        val = m.group(2)
        if val.strip():
            creds.append({"tag": m.group(1), "value": represent_secret(val)})
    if creds:
        out["all_credential_like_fields_found"] = creds[:150]
    return out


def extract_structured(body: bytes) -> Dict[str, Any]:
    raw_text = decode_bytes(body.replace(b"\x00", b""))
    sane = sanitize_xml_bytes(body)
    text = decode_bytes(sane)
    fallback = merge_extracted(regex_extract(raw_text), regex_extract(text))
    try:
        root = ET.fromstring(text)
    except Exception as e:
        fb = dict(fallback)
        fb["parse_note"] = f"XML parse fallback used ({e})"
        return fb

    # If XML parses, still rely on regex-augmented extraction for completeness (tolerant across vendor schemas)
    data = regex_extract(raw_text)
    return merge_extracted(data, fallback)


def fingerprint_hints(headers: Dict[str, str], body: bytes, extracted: Dict[str, Any]) -> List[str]:
    hints = []
    server = (headers.get("Server") or headers.get("server") or "")
    text = decode_bytes(sanitize_xml_bytes(body))
    low = text.lower()
    if server:
        hints.append(f"HTTP Server header: {server}")
        if "ty_httpd" in server.lower():
            hints.append("Profile hint: ty_httpd-style management interface (seen on some SCTY GPON CPEs)")
    if "<dslcpeconfig" in low:
        hints.append("Config schema: DslCpeConfig (TR-069/CWMP-style XML)")
    dev = extracted.get("device_info") or {}
    vendor = str(dev.get("TrueVendorID") or dev.get("Manufacturer") or "")
    product = str(dev.get("ProductClass") or dev.get("Product_ID") or dev.get("ModelName") or "")
    if vendor or product:
        hints.append(f"Device identifiers present: vendor={vendor or '?'} model={product or '?'}")
    if "scty" in (vendor + " " + server).lower() or "tg2212" in product.lower():
        hints.append("Compatibility hint: resembles SCTY TG2212-class GPON CPE profile (results vary by firmware/exposure)")
    if "InternetGatewayDevice" in text and "ManagementServer" in text:
        hints.append("TR-069/CWMP management structures present")
    return hints


def analyze_body(body: bytes, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    headers = headers or {}
    text = decode_bytes(sanitize_xml_bytes(body))
    markers = ["<DslCpeConfig", "InternetGatewayDevice", "<WLAN", "<Password", "<PreSharedKey",
               "ManagementServer", "WANPPPConnection", "WANIPConnection", "TR-069", "cwmp",
               "X_BROADCOM", "LANDevice", "DeviceInfo", "SSID", "TeleComAccount", "config"]
    config_markers = sum(1 for s in markers if s.lower() in text.lower())
    extracted: Dict[str, Any] = {}
    if "<" in text and (config_markers >= 2 or "xml" in text[:200].lower()):
        extracted = extract_structured(body)

    sensitive_hits = 0
    for key in ["admin_web_account", "user_gui_account", "service_accounts", "tr069_acs", "wifi", "wan_connections", "all_credential_like_fields_found"]:
        if key in extracted:
            v = extracted[key]
            sensitive_hits += len(v) if isinstance(v, list) else 1

    hints = fingerprint_hints(headers, body, extracted) if body else []
    return {
        "bytes": len(body),
        "config_markers": config_markers,
        "sensitive_hits": sensitive_hits,
        "fingerprint_hints": hints,
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
    return "INCONCLUSIVE"


def risk_assessment(extracted: Dict[str, Any]) -> Dict[str, Any]:
    has_admin = bool(extracted.get("admin_web_account"))
    has_wifi = bool(extracted.get("wifi"))
    has_tr069 = bool(extracted.get("tr069_acs"))
    has_wan = bool(extracted.get("wan_connections"))
    has_user = bool(extracted.get("user_gui_account") or extracted.get("service_accounts"))
    impacts = []
    if has_admin:
        impacts.append("Administrative account material exposed — may enable full device management access if reused/valid.")
    if has_wifi:
        impacts.append("Wireless network credentials/keys exposed — may enable unauthorized network access and traffic visibility.")
    if has_tr069:
        impacts.append("Remote management (TR-069/ACS/CWMP) details exposed — may increase risk of remote provisioning abuse depending on reachability and controls.")
    if has_wan:
        impacts.append("WAN/PPPoE/service details exposed — may aid service abuse, impersonation, or targeted attacks.")
    if has_user:
        impacts.append("Additional user/service account material exposed.")
    if not impacts:
        impacts.append("Configuration disclosure may reveal sensitive operational details.")
    factors = [
        "Reachability matters: LAN/Wi-Fi exposure differs from internet/WAN exposure.",
        "No authentication required for the exposed endpoint increases risk when reachable.",
        "Router/gateway compromise can have downstream impact on connected devices and traffic.",
        "Actual impact depends on credential validity, service exposure, and mitigations — assess in your environment.",
    ]
    return {
        "impact_assessment": "high" if (has_admin or has_wifi or has_tr069 or has_wan) else "moderate",
        "potential_impacts": impacts,
        "factors": factors,
        "note": "This tool reports observed exposure and indicators; it does not assign a definitive severity/CVSS score.",
    }


def check_target(base: str, paths: List[str], timeout: float, ua: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"target": base, "checked_at_utc": utc_now(), "paths": [], "vulnerable_indicators": False}
    any_vuln = False
    merged_extracted: Dict[str, Any] = {}
    for p in paths:
        if not p.startswith("/"):
            p = "/" + p
        url = base + p
        status, headers, body, err = fetch(url, timeout, ua)
        entry: Dict[str, Any] = {
            "url": url, "status": status, "error": err,
            "server": headers.get("Server") or headers.get("server"),
            "content_type": headers.get("Content-Type") or headers.get("content-type"),
        }
        analysis = analyze_body(body, headers) if (status == 200 and body) else {}
        if analysis:
            entry["analysis"] = analysis
            ex = analysis.get("extracted") or {}
            if ex:
                merged_extracted = merge_extracted(ex, merged_extracted)
        entry["verdict"] = verdict_for(status, body, analysis)
        if entry["verdict"] in ("LIKELY_EXPOSED_UNAUTH_CONFIG", "POSSIBLE_SENSITIVE_DISCLOSURE", "LIKELY_EXPOSED_CONFIG"):
            any_vuln = True
        result["paths"].append(entry)
    result["vulnerable_indicators"] = any_vuln
    if merged_extracted:
        result["consolidated_extracted"] = merged_extracted
        if any_vuln:
            result["risk_assessment"] = risk_assessment(merged_extracted)
    result["summary"] = (
        "Potential unauthenticated sensitive config exposure detected (verify in authorized context)."
        if any_vuln else
        "No clear unauthenticated config exposure detected by this read-only check."
    )
    result["access_condition"] = "Typically requires network reachability to the device web interface (LAN/Wi-Fi after connecting; or WAN if remotely exposed). No prior authentication required for exposed endpoints."
    return result


def check_file(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        body = f.read()
    analysis = analyze_body(body, {})
    ex = analysis.get("extracted") or {}
    result = {
        "target": f"file://{os.path.abspath(path)}",
        "checked_at_utc": utc_now(),
        "paths": [{
            "url": f"file://{os.path.abspath(path)}",
            "status": 200,
            "verdict": "LIKELY_EXPOSED_CONFIG" if analysis.get("sensitive_hits", 0) else "PARSED",
            "analysis": analysis,
        }],
        "vulnerable_indicators": analysis.get("sensitive_hits", 0) > 0,
        "consolidated_extracted": ex,
        "summary": "Offline analysis of provided config file (for authorized review).",
        "access_condition": "Offline file analysis (no network request).",
    }
    if ex and analysis.get("sensitive_hits", 0) > 0:
        result["risk_assessment"] = risk_assessment(ex)
    return result


SECRET_KEYS = {"password", "passwd", "psk", "key", "keypassphrase", "presharedkey", "wlkey", "secret", "passphrase"}


def is_secret_field_name(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in SECRET_KEYS)


def redact_value(v: Any) -> Any:
    if isinstance(v, dict) and "recovered" in v:
        out = dict(v)
        for k in list(out.keys()):
            if k in ("raw", "recovered", "decoded_base64", "decoded_base64_xor80", "xor80_of_raw", "printable_view", "hex"):
                if out[k] is not None:
                    out[k] = "[REDACTED]"
        return out
    if isinstance(v, str):
        return "[REDACTED]"
    return "[REDACTED]"


def redact_obj(obj: Any, key_hint: str = "") -> Any:
    if isinstance(obj, dict):
        # secret representation dict
        if "recovered" in obj and ("raw" in obj or "hex" in obj or "decoded_base64" in obj or "decoded_base64_xor80" in obj):
            return redact_value(obj)
        out = {}
        for k, v in obj.items():
            if is_secret_field_name(k):
                if isinstance(v, list):
                    out[k] = [redact_obj(x, k) for x in v]
                elif isinstance(v, dict) and "recovered" not in v:
                    out[k] = redact_obj(v, k)
                else:
                    out[k] = redact_value(v)
            else:
                out[k] = redact_obj(v, k)
        return out
    if isinstance(obj, list):
        return [redact_obj(x, key_hint) for x in obj]
    if is_secret_field_name(key_hint) and obj is not None:
        if isinstance(obj, dict) and "recovered" in obj:
            return redact_value(obj)
        return "[REDACTED]" if not isinstance(obj, (dict, list)) else redact_obj(obj, key_hint)
    return obj


def apply_redaction(report: Dict[str, Any], redact: bool) -> Dict[str, Any]:
    if not redact:
        return report
    rep = copy.deepcopy(report)
    rep["redacted"] = True
    for r in rep.get("results", []):
        for p in r.get("paths", []):
            a = p.get("analysis") or {}
            if "extracted" in a:
                a["extracted"] = redact_obj(a["extracted"])
            if "sample_head" in a:
                a["sample_head"] = "[REDACTED FOR SHARING]"
        if "consolidated_extracted" in r:
            r["consolidated_extracted"] = redact_obj(r["consolidated_extracted"])
    return rep


def fmt_secret(v: Any) -> str:
    if isinstance(v, dict) and "recovered" in v:
        s = str(v.get("recovered"))
        if s == "[REDACTED]":
            return "[REDACTED]"
        extras = []
        if v.get("decoded_base64") and v.get("decoded_base64") != s:
            extras.append(f"decoded_base64={v.get('decoded_base64')}")
        if v.get("hex"):
            extras.append(f"hex={v.get('hex')}")
        if v.get("printable_view") and v.get("hex"):
            extras.append(f"printable={v.get('printable_view')}")
        if v.get("decoded_base64_xor80") and v.get("decoded_base64_xor80") != s:
            extras.append(f"b64-xor80={v.get('decoded_base64_xor80')}")
        if extras:
            s += "  [" + "; ".join(extras) + "]"
        return s
    return str(v)


def pretty_print(report: Dict[str, Any], color: bool = True) -> None:
    if not report.get("quiet_banner"):
        print(c(BANNER, "cyan", color))
    for r in report.get("results", []):
        vind = r.get("vulnerable_indicators")
        head = f"Target: {r['target']}  (checked {r['checked_at_utc']} UTC)"
        print(c(head, "bold", color))
        print(c("-" * 72, "dim", color))
        for p in r.get("paths", []):
            verdict = p.get("verdict", "")
            vcolor = "red" if "EXPOSED" in verdict or "DISCLOSURE" in verdict else ("yellow" if verdict == "INCONCLUSIVE" else "green")
            print(f"  [PATH] {p['url']}")
            print(f"    status={p.get('status')}  verdict={c(verdict, vcolor, color)}  server={p.get('server')}")
            if p.get("error"):
                print(f"    error={p.get('error')}")
            a = p.get("analysis") or {}
            if a:
                print(f"    bytes={a.get('bytes')}  markers={a.get('config_markers')}  sensitive_hits={a.get('sensitive_hits')}")

        ex = r.get("consolidated_extracted") or {}
        def sec(title):
            print("\n" + c(f"[{title}]", "magenta", color))
        if ex.get("device_info"):
            sec("DEVICE INFO")
            for k, v in ex["device_info"].items(): print(f"  {k}: {v}")
        if ex.get("admin_web_account"):
            sec("ADMIN / WEB ACCOUNT")
            adm = ex["admin_web_account"]
            print(f"  username: {adm.get('username')}")
            if adm.get("password") is not None: print(f"  password: {fmt_secret(adm['password'])}")
        if ex.get("user_gui_account"):
            sec("USER GUI ACCOUNT")
            ua = ex["user_gui_account"]
            print(f"  username: {ua.get('username')}")
            if ua.get("password") is not None: print(f"  password: {fmt_secret(ua['password'])}")
        if ex.get("service_accounts"):
            sec("SERVICE ACCOUNTS")
            for k, v in ex["service_accounts"].items(): print(f"  {k}: {fmt_secret(v)}")
        if ex.get("wifi"):
            sec("WIFI / WLAN")
            for i, w in enumerate(ex["wifi"], 1):
                if not (w.get("SSID") or w.get("WlKey") or w.get("PreSharedKeys")): continue
                print(f"  - #{i} SSID={w.get('SSID')} Enable={w.get('Enable')} BeaconType={w.get('BeaconType')} Auth={w.get('WPAAuthenticationMode')} Cipher={w.get('IEEE11iEncryptionModes')}")
                if w.get("WlKey"): print(f"      WlKey: {fmt_secret(w['WlKey'])}")
                for idx, psk in enumerate(w.get("PreSharedKeys", []), 1): print(f"      PreSharedKey[{idx}]: {fmt_secret(psk)}")
        if ex.get("tr069_acs"):
            sec("TR-069 / ACS / CWMP")
            for k, v in ex["tr069_acs"].items(): print(f"  {k}: {fmt_secret(v)}")
        if ex.get("wan_connections"):
            sec("WAN / PPPoE / IP CONNECTIONS")
            for i, w in enumerate(ex["wan_connections"], 1):
                print(f"  - #{i} {w.get('type')} Service={w.get('X_Customer_ServiceList')} Name={w.get('Name')} Enable={w.get('Enable')}")
                for k in ["Username","Password","ExternalIPAddress","DefaultGateway","DNSServers","MACAddress","X_Customer_VLANID","NATEnabled","AddressingType","X_Customer_ConnectionType"]:
                    if k in w: print(f"      {k}: {fmt_secret(w[k])}")
        if ex.get("lan"):
            sec("LAN")
            for l in ex["lan"]: print(f"  - {l}")

        if r.get("risk_assessment"):
            ra = r["risk_assessment"]
            sec("IMPACT ASSESSMENT (informational, not a definitive score)")
            print(f"  Impact level (heuristic): {ra.get('impact_assessment')}")
            for imp in ra.get("potential_impacts", []): print(f"  - {imp}")
            print("  Factors:")
            for f in ra.get("factors", []): print(f"    * {f}")
            print(f"  Note: {ra.get('note')}")

        print("\n" + c("[ACCESS CONDITION]", "magenta", color))
        print(f"  {r.get('access_condition')}")
        print("\n" + c("[COMPATIBILITY NOTES]", "magenta", color))
        for note in COMPAT_NOTES:
            print(f"  - {note}")
        summ_color = "red" if vind else "green"
        print("\n" + c("SUMMARY: " + r["summary"], summ_color, color))
        if report.get("redacted"):
            print(c("  (report values redacted for sharing)", "dim", color))
        print()


def write_html(report: Dict[str, Any], path: str) -> None:
    rows = []
    for r in report.get("results", []):
        ex = r.get("consolidated_extracted") or {}
        ra = r.get("risk_assessment") or {}
        def esc(x): return html.escape(str(x))
        def pre(obj): return "<pre>" + esc(json.dumps(obj, indent=2, ensure_ascii=False)) + "</pre>" if obj else "<em>None</em>"
        rows.append(f"<h2>Target: {esc(r.get('target'))}</h2><p><b>Summary:</b> {esc(r.get('summary'))}</p><p><b>Access:</b> {esc(r.get('access_condition'))}</p>"
                    f"<h3>Device</h3>{pre(ex.get('device_info'))}"
                    f"<h3>Admin/Web Account</h3>{pre(ex.get('admin_web_account'))}"
                    f"<h3>User GUI Account</h3>{pre(ex.get('user_gui_account'))}"
                    f"<h3>Service Accounts</h3>{pre(ex.get('service_accounts'))}"
                    f"<h3>Wi-Fi</h3>{pre(ex.get('wifi'))}"
                    f"<h3>TR-069/ACS/CWMP</h3>{pre(ex.get('tr069_acs'))}"
                    f"<h3>WAN</h3>{pre(ex.get('wan_connections'))}"
                    f"<h3>LAN</h3>{pre(ex.get('lan'))}"
                    f"<h3>Impact Assessment</h3>{pre(ra)}")
    doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(TOOL_NAME)} report</title>
<style>body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem;max-width:1100px}} pre{{background:#f6f8fa;padding:1rem;overflow:auto;border-radius:6px}} h1{{margin-bottom:.2rem}} .meta{{color:#555}}</style></head>
<body><h1>{html.escape(TOOL_NAME)} report</h1><p class='meta'>Generated {html.escape(report.get('generated_at_utc',''))} UTC · mode: {html.escape(report.get('mode',''))}{' · REDACTED' if report.get('redacted') else ''}</p>{''.join(rows)}</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


def write_markdown(report: Dict[str, Any], path: str) -> None:
    lines = [f"# {TOOL_NAME} report", "", f"- Generated: {report.get('generated_at_utc')} UTC", f"- Mode: {report.get('mode')}"]
    if report.get("redacted"):
        lines.append("- **REDACTED:** secret values masked for sharing")
    lines.append("")
    for r in report.get("results", []):
        ex = r.get("consolidated_extracted") or {}
        ra = r.get("risk_assessment") or {}
        lines += [f"## Target: {r.get('target')}", "", f"**Summary:** {r.get('summary')}", "", f"**Access condition:** {r.get('access_condition')}", ""]
        def block(title, obj):
            if not obj:
                return
            lines.append(f"### {title}")
            lines.append("```json")
            lines.append(json.dumps(obj, indent=2, ensure_ascii=False))
            lines.append("```")
            lines.append("")
        block("Device info", ex.get("device_info"))
        block("Admin/web account", ex.get("admin_web_account"))
        block("User GUI account", ex.get("user_gui_account"))
        block("Service accounts", ex.get("service_accounts"))
        block("Wi-Fi", ex.get("wifi"))
        block("TR-069/ACS/CWMP", ex.get("tr069_acs"))
        block("WAN", ex.get("wan_connections"))
        block("LAN", ex.get("lan"))
        block("Impact assessment (informational)", ra)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Read-only scanner for unauthenticated router/CPE config exposure (authorized testing)",
        epilog="Use only on systems you own or are explicitly authorized to test."
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--target", help="Target base URL or IP/host (e.g. http://192.168.0.1)")
    src.add_argument("--targets-file", help="File with one target per line")
    src.add_argument("--file", help="Analyze a local config file offline (no network requests)")
    ap.add_argument("--paths", default=",".join(DEFAULT_PATHS), help="Comma-separated paths to check")
    ap.add_argument("--all-paths", action="store_true", help="Include expanded read-only wordlist of common config/backup paths")
    ap.add_argument("--list-paths", action="store_true", help="Print the built-in path wordlist and exit")
    ap.add_argument("--timeout", type=float, default=6.0, help="HTTP timeout seconds (default: 6)")
    ap.add_argument("--user-agent", default=f"{TOOL_NAME}/{VERSION} (authorized-test)", help="User-Agent")
    ap.add_argument("--json", dest="json_out", help="Write JSON report to file")
    ap.add_argument("--html", dest="html_out", help="Write HTML report to file")
    ap.add_argument("--md", dest="md_out", help="Write Markdown report to file")
    ap.add_argument("--redact", action="store_true", help="Mask secret values in terminal/report output (useful for sharing)")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--quiet", action="store_true", help="Print only summary/verdict per target")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    if args.list_paths:
        print("Default paths:")
        for p in DEFAULT_PATHS:
            print(f"  {p}")
        print("\nAdditional paths (--all-paths):")
        for p in EXTRA_PATHS:
            print(f"  {p}")
        return 0

    if not (args.target or args.targets_file or args.file):
        print("error: one of --target, --targets-file, or --file is required (or use --list-paths)", file=sys.stderr)
        return 1

    if args.file:
        results = [check_file(args.file)]
    else:
        paths = [p.strip() for p in args.paths.split(",") if p.strip()]
        if args.all_paths:
            for p in EXTRA_PATHS:
                if p not in paths:
                    paths.append(p)
        targets = [normalize_target(args.target)] if args.target else []
        if args.targets_file:
            with open(args.targets_file, "r", encoding="utf-8") as f:
                targets = [normalize_target(line) for line in f if line.strip() and not line.strip().startswith("#")]
        results = [check_target(t, paths, args.timeout, args.user_agent) for t in targets]

    report = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "mode": "read-only (no login, no state changes, no persistence/backdoor, no firmware flashing)",
        "generated_at_utc": utc_now(),
        "compatibility_notes": COMPAT_NOTES,
        "results": results,
    }

    out_report = apply_redaction(report, args.redact)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out_report, f, indent=2, ensure_ascii=False)
    if args.html_out:
        write_html(out_report, args.html_out)
    if args.md_out:
        write_markdown(out_report, args.md_out)

    if args.quiet:
        for r in out_report.get("results", []):
            print(f"{r['target']}: {'INDICATORS' if r['vulnerable_indicators'] else 'NO_CLEAR_FINDING'} - {r['summary']}")
    else:
        pretty_print(out_report, color=not args.no_color)
        for label, path in (("JSON", args.json_out), ("HTML", args.html_out), ("Markdown", args.md_out)):
            if path:
                print(c(f"{label} report: {path}", "dim", not args.no_color))

    return 0 if all(not r.get("vulnerable_indicators") for r in results) else 2


if __name__ == "__main__":
    sys.exit(main())
