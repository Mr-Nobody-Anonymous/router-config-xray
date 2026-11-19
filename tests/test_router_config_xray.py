#!/usr/bin/env python3
"""Standard-library unit tests for router_config_xray (no pytest required).

Run:  python3 -m unittest discover -s tests -v
  or: python3 tests/test_router_config_xray.py
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import router_config_xray as xray  # noqa: E402


SAMPLE_CONFIG = b"""<DslCpeConfig>
  <DeviceInfo>
    <ManufacturerOUI>001122</ManufacturerOUI>
    <ModelName>TEST-MODEL</ModelName>
    <TrueVendorID>TESTVENDOR</TrueVendorID>
    <SoftwareVersion>1.2.3</SoftwareVersion>
  </DeviceInfo>
  <X_Customer_TeleComAccount>
    <Username>admin</Username>
    <Password>AdminSecret123</Password>
  </X_Customer_TeleComAccount>
  <ManagementServer>
    <URL>https://acs.example.invalid:7547/</URL>
    <Password>AcsSecret</Password>
  </ManagementServer>
  <WLANConfiguration>
    <SSID>TestWiFi</SSID>
    <Enable>1</Enable>
    <PreSharedKey>WifiKey123</PreSharedKey>
  </WLANConfiguration>
  <WANPPPConnection>
    <Username>pppoe@example.invalid</Username>
    <Password>PppoeSecret</Password>
    <ExternalIPAddress>203.0.113.1</ExternalIPAddress>
  </WANPPPConnection>
</DslCpeConfig>
"""


class HelpersTest(unittest.TestCase):
    def test_normalize_target(self):
        self.assertEqual(xray.normalize_target("192.0.2.1"), "http://192.0.2.1")
        self.assertEqual(xray.normalize_target(" https://x.example/ "), "https://x.example")

    def test_decode_bytes(self):
        self.assertEqual(xray.decode_bytes(b"<xml>caf\xc3\xa9</xml>"), "<xml>caf\u00e9</xml>")

    def test_secret_recovery_base64(self):
        import base64
        value = base64.b64encode(b"decoded-secret").decode()
        result = xray.represent_secret(value)
        self.assertEqual(result.get("decoded_base64"), "decoded-secret")
        self.assertEqual(result.get("recovered"), "decoded-secret")

    def test_color_can_be_disabled(self):
        self.assertEqual(xray.c("hello", "red", enable=False), "hello")


class AnalysisTest(unittest.TestCase):
    def test_markers_and_hits(self):
        analysis = xray.analyze_body(SAMPLE_CONFIG)
        self.assertGreaterEqual(analysis["config_markers"], 2)
        self.assertGreaterEqual(analysis["sensitive_hits"], 4)

    def test_extracts_accounts_wifi_tr069_wan(self):
        extracted = xray.analyze_body(SAMPLE_CONFIG)["extracted"]
        self.assertEqual(extracted["admin_web_account"]["username"], "admin")
        self.assertEqual(extracted["admin_web_account"]["password"]["recovered"], "AdminSecret123")
        self.assertIn("acs.example.invalid", extracted["tr069_acs"]["URL"])
        self.assertEqual(extracted["wifi"][0]["SSID"], "TestWiFi")
        self.assertEqual(extracted["wan_connections"][0]["ExternalIPAddress"], "203.0.113.1")

    def test_device_info(self):
        device = xray.analyze_body(SAMPLE_CONFIG)["extracted"]["device_info"]
        self.assertEqual(device["TrueVendorID"], "TESTVENDOR")
        self.assertEqual(device["SoftwareVersion"], "1.2.3")

    def test_fingerprint_hints(self):
        hints = xray.fingerprint_hints({"Server": "ty_httpd/1.0"}, SAMPLE_CONFIG, {})
        self.assertTrue(any("ty_httpd" in h for h in hints))
        self.assertTrue(any("DslCpeConfig" in h for h in hints))


class VerdictTest(unittest.TestCase):
    def test_exposed(self):
        analysis = xray.analyze_body(SAMPLE_CONFIG)
        verdict = xray.verdict_for(200, SAMPLE_CONFIG, analysis)
        self.assertEqual(verdict, "LIKELY_EXPOSED_UNAUTH_CONFIG")

    def test_protected(self):
        self.assertEqual(xray.verdict_for(403, b"", {}), "PROTECTED_OR_FORBIDDEN")

    def test_not_found(self):
        self.assertEqual(xray.verdict_for(404, b"", {}), "NOT_FOUND")

    def test_clean_body(self):
        self.assertEqual(xray.verdict_for(200, b"<html>ok</html>", xray.analyze_body(b"<html>ok</html>")),
                         "ACCESSIBLE_BUT_NO_CLEAR_SECRETS_DETECTED")


class ReportingTest(unittest.TestCase):
    def test_redaction_masks_secrets(self):
        report = {"results": [{"paths": [{"analysis": {"sample_head": "raw", "extracted": {
            "admin_web_account": {"password": {"raw": "hunter2", "recovered": "hunter2"}}}}}],
            "consolidated_extracted": {"admin_web_account": {"password": {"raw": "hunter2", "recovered": "hunter2"}}}}]}
        redacted = xray.apply_redaction(report, True)
        node = redacted["results"][0]["consolidated_extracted"]["admin_web_account"]["password"]
        self.assertEqual(node["raw"], "[REDACTED]")
        self.assertEqual(node["recovered"], "[REDACTED]")
        self.assertEqual(redacted["results"][0]["paths"][0]["analysis"]["sample_head"], "[REDACTED FOR SHARING]")

    def test_exposure_score_bounds(self):
        score = xray.exposure_score({"vulnerable_indicators": True, "consolidated_extracted": {
            "admin_web_account": {}, "wifi": []}, "paths": []})
        self.assertBetween(score["score"])

    def assertBetween(self, value):
        self.assertGreaterEqual(value, 0)
        self.assertLessEqual(value, 100)

    def test_markdown_and_html_outputs(self):
        import tempfile
        report = {"tool": "router-config-xray", "version": xray.VERSION, "generated_at_utc": "now",
                  "mode": "test", "results": [{"target": "file:///tmp/x", "summary": "ok",
                  "access_condition": "offline", "exposure": {"score": 10, "label": "LOW"},
                  "consolidated_extracted": {}, "vulnerable_indicators": False}]}
        with tempfile.TemporaryDirectory() as directory:
            md = os.path.join(directory, "r.md")
            html_file = os.path.join(directory, "r.html")
            xray.write_markdown(report, md)
            xray.write_html(report, html_file)
            with open(md, encoding="utf-8") as handle:
                self.assertIn("router-config-xray", handle.read())
            with open(html_file, encoding="utf-8") as handle:
                self.assertIn("<!doctype html>", handle.read())


class CliTest(unittest.TestCase):
    def run_quiet(self, argv):
        """Run the CLI capturing stdout/stderr so the suite stays readable."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = xray.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_self_test_entry_point(self):
        code, out, _ = self.run_quiet(["--self-test"])
        self.assertEqual(code, xray.EXIT_CLEAN)
        self.assertIn("internal checks passed", out)

    def test_list_paths(self):
        code, out, _ = self.run_quiet(["--list-paths"])
        self.assertEqual(code, xray.EXIT_CLEAN)
        self.assertIn("/config.xml", out)

    def test_missing_file_is_a_clean_error(self):
        code, _out, err = self.run_quiet(["--file", "/no/such/config.xml"])
        self.assertEqual(code, xray.EXIT_ERROR)
        self.assertIn("error:", err)
        self.assertNotIn("Traceback", err)

    def test_invalid_concurrency_is_a_clean_error(self):
        code, _out, err = self.run_quiet(["--demo", "--concurrency", "0"])
        self.assertEqual(code, xray.EXIT_ERROR)
        self.assertIn("--concurrency", err)

    def test_invalid_timeout_is_a_clean_error(self):
        code, _out, err = self.run_quiet(["--demo", "--timeout", "-1"])
        self.assertEqual(code, xray.EXIT_ERROR)
        self.assertIn("--timeout", err)

    def test_no_arguments_is_a_clean_error(self):
        code, _out, err = self.run_quiet([])
        self.assertEqual(code, xray.EXIT_ERROR)
        self.assertIn("error:", err)

    def test_findings_exit_code_is_two(self):
        code, _out, _err = self.run_quiet(["--demo", "--quiet", "--no-color"])
        self.assertEqual(code, xray.EXIT_FINDINGS)

    def test_clean_file_exit_code_is_zero(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as handle:
            handle.write(b"<html><body>nothing sensitive here</body></html>")
            path = handle.name
        try:
            code, _out, _err = self.run_quiet(["--file", path, "--quiet", "--no-color"])
            self.assertEqual(code, xray.EXIT_CLEAN)
        finally:
            os.unlink(path)

    def test_redirect_is_not_followed(self):
        import http.server
        import threading

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "/config.xml")
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            status, _headers, _body, error = xray.fetch(
                f"http://127.0.0.1:{port}/start", 2.0, "test-agent")
            # 3xx is reported, never followed to another host
            self.assertEqual(status, 302)
            self.assertTrue(error is None or error.startswith("HTTPError:"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
