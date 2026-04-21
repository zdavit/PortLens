import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import ai_client
import network_map
import scan_history
import scanner


class ScannerValidationTests(unittest.TestCase):
    def test_validate_target_accepts_ipv6_host_and_subnet(self):
        self.assertEqual(scanner.validate_target("2001:db8::10"), "2001:db8::10")
        self.assertEqual(scanner.validate_target("2001:db8::/64"), "2001:db8::/64")

    def test_validate_target_rejects_overly_broad_ipv6_subnet(self):
        with self.assertRaises(scanner.ScannerError):
            scanner.validate_target("2001:db8::/48")

    def test_validate_ports_spec_normalizes_and_rejects_bad_input(self):
        self.assertEqual(scanner.validate_ports_spec("10-8, 443"), "8-10,443")
        self.assertEqual(scanner.validate_ports_spec("22,22,20-25,23-24"), "20-25")
        with self.assertRaises(scanner.ScannerError):
            scanner.validate_ports_spec("0")

    def test_chunk_port_spec_preserves_non_contiguous_ports(self):
        self.assertEqual(scanner.chunk_port_spec("21-22,80", chunk_size=10), ["21-22,80"])

    def test_finalize_results_sorts_hosts_and_dedupes_records(self):
        results = [
            {
                "host": "2001:db8::2",
                "hostname": "v6",
                "state": "up",
                "services": [
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.24", "risk": "Low"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.24", "risk": "Low"},
                ],
                "ports": [
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.24", "risk": "Low"},
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.24", "risk": "Low"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.24", "risk": "Low"},
                ],
            },
            {
                "host": "10.0.0.5",
                "hostname": "v4",
                "state": "up",
                "services": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6", "risk": "Medium"},
                ],
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6", "risk": "Medium"},
                ],
            },
        ]

        finalized = scanner._finalize_results(results)

        self.assertEqual([host["host"] for host in finalized], ["10.0.0.5", "2001:db8::2"])
        self.assertEqual([port["port"] for port in finalized[1]["ports"]], [80, 443])
        self.assertEqual(len(finalized[1]["services"]), 1)

    def test_get_default_target_uses_ipv6_prefix_when_local_ip_is_v6(self):
        with mock.patch("scanner.get_local_ip", return_value="2001:db8::1234"):
            self.assertEqual(scanner.get_default_target(), "2001:db8::/64")


class ScannerRiskAndAiTests(unittest.TestCase):
    def test_version_override_applies_to_https_nginx(self):
        self.assertEqual(scanner.classify_risk("https", "nginx", "1.16.1"), "Medium")

    def test_port_hint_raises_unknown_redis_port_to_critical(self):
        self.assertEqual(
            scanner.classify_risk("unknown", port=6379, protocol="tcp"),
            "Critical",
        )

    def test_tcpwrapped_ssh_port_uses_port_context(self):
        self.assertEqual(
            scanner.classify_risk("tcpwrapped", port=22, protocol="tcp"),
            "Medium",
        )

    def test_product_hint_applies_version_override_for_mariadb(self):
        self.assertEqual(
            scanner.classify_risk("unknown", "MariaDB", "5.5.68", port=3306, protocol="tcp"),
            "Critical",
        )

    def test_host_score_includes_exposure_penalties(self):
        host_info = {
            "services": [
                {"service": "ssh", "risk": "Medium"},
                {"service": "mysql", "risk": "High"},
            ]
        }
        self.assertEqual(scanner.host_exposure_summary(host_info), "Databases, Remote access")
        self.assertEqual(scanner.compute_host_score(host_info), 63)

    def test_request_ai_response_sanitizes_text(self):
        payload = json.dumps({"response": "Overview:\u001b[31m test\n\u0007Safe"}).encode()

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, _size=-1):
                return payload

        with mock.patch("ai_client.urllib.request.urlopen", return_value=FakeResponse()):
            text = scanner.request_ai_response("prompt")

        self.assertEqual(text, "Overview: test\nSafe")

    def test_request_ai_response_handles_url_errors(self):
        with mock.patch(
            "ai_client.urllib.request.urlopen",
            side_effect=urllib.error.URLError("timed out"),
        ):
            with self.assertRaises(scanner.AIAnalysisError):
                scanner.request_ai_response("prompt")

    def test_request_ai_response_rejects_oversized_payloads(self):
        payload = b"x" * (ai_client.AI_MAX_RESPONSE_BYTES + 1)

        class FakeResponse:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, _size=-1):
                return payload

        with mock.patch("ai_client.urllib.request.urlopen", return_value=FakeResponse()):
            with self.assertRaises(scanner.AIAnalysisError) as ctx:
                scanner.request_ai_response("prompt")

        self.assertIn("too much data", str(ctx.exception))

    def test_get_ai_analysis_limits_prompt_to_highest_priority_services(self):
        results = [{
            "host": "host-a",
            "services": [
                {"port": 6000 + idx, "protocol": "tcp", "service": f"svc-{idx}", "product": "prod", "version": "1.0", "risk": "Low"}
                for idx in range(ai_client.AI_SUMMARY_SERVICE_LIMIT)
            ] + [
                {"port": 6379, "protocol": "tcp", "service": "redis", "product": "Redis", "version": "7.0", "risk": "Critical"},
            ],
        }]

        captured = {}

        def fake_request(prompt, announce_message=None):
            captured["prompt"] = prompt
            return "analysis"

        with mock.patch("ai_client.request_ai_response", side_effect=fake_request):
            text = scanner.get_ai_analysis(results, announce=False)

        self.assertEqual(text, "analysis")
        self.assertIn("Port 6379/tcp: redis", captured["prompt"])
        self.assertNotIn(f"svc-{ai_client.AI_SUMMARY_SERVICE_LIMIT - 1}", captured["prompt"])
        self.assertIn("additional open service(s) were omitted", captured["prompt"])


class HistoryExportTests(unittest.TestCase):
    def test_load_scan_rejects_schema_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(scan_history.HISTORY_DIR) / "schema_invalid_test.json"
            filepath.write_text(json.dumps({"timestamp": "x", "target": "localhost", "ports": "1-10"}))
            try:
                with self.assertRaises(ValueError):
                    scan_history.load_scan(str(filepath))
            finally:
                filepath.unlink(missing_ok=True)

    def test_export_csv_escapes_formula_fields(self):
        results = [{
            "host": "127.0.0.1",
            "hostname": "=danger",
            "ports": [{
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "@http",
                "product": "+nginx",
                "version": "-1.0",
                "risk": "Low",
            }],
        }]

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "report.csv"
            scan_history.export_csv(results, "localhost", "80", filepath=str(filepath))
            text = filepath.read_text()

        self.assertIn("'=danger", text)
        self.assertIn("'@http", text)
        self.assertIn("'+nginx", text)
        self.assertIn("'-1.0", text)

    def test_export_html_fills_missing_ai_and_escapes_html(self):
        results = [{
            "host": "127.0.0.1",
            "hostname": "localhost",
            "services": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6",
                    "risk": "Medium",
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https<script>",
                    "product": "nginx",
                    "version": "1.16",
                    "risk": "Medium",
                },
            ],
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6",
                    "risk": "Medium",
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https<script>",
                    "product": "nginx",
                    "version": "1.16",
                    "risk": "Medium",
                },
            ],
        }]

        ai_cache = {
            ("127.0.0.1", 22, "tcp", "ssh", "open"): "Overview: cached",
        }
        calls = []

        def analysis_getter(service):
            calls.append(service["port"])
            return f"Overview: generated for {service['port']}"

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "report.html"
            scan_history.export_html(
                results,
                "localhost",
                "22,443",
                ai_cache=ai_cache,
                filepath=str(filepath),
                fill_missing_ai=True,
                analysis_getter=analysis_getter,
            )
            text = filepath.read_text()

        self.assertEqual(calls, [443])
        self.assertIn("Overview: cached", text)
        self.assertIn("Overview: generated for 443", text)
        self.assertIn("https&lt;script&gt;", text)

    def test_list_history_skips_invalid_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            valid_path = Path(tmpdir) / "valid.json"
            valid_path.write_text(json.dumps({
                "timestamp": "2026-01-01_00-00-00",
                "target": "localhost",
                "ports": "22",
                "hosts": [],
            }))
            (Path(tmpdir) / "invalid.json").write_text("not json")
            (Path(tmpdir) / "oversized.json").write_text("{}")

            real_getsize = scan_history.os.path.getsize

            def fake_getsize(path):
                if path.endswith("oversized.json"):
                    return scan_history.MAX_SCAN_FILE_BYTES + 1
                return real_getsize(path)

            with mock.patch.object(scan_history, "HISTORY_DIR", tmpdir), \
                 mock.patch("scan_history.os.path.getsize", side_effect=fake_getsize):
                entries = scan_history.list_history()

        self.assertEqual([entry["filename"] for entry in entries], ["valid.json"])

    def test_main_supports_html_export(self):
        results = [{"host": "127.0.0.1", "hostname": "localhost", "state": "up", "services": [], "ports": []}]

        with mock.patch.object(sys, "argv", ["scanner.py", "localhost", "--export", "html", "--no-ai"]), \
             mock.patch("scanner.scan_network", return_value=results), \
             mock.patch("scanner.print_results"), \
             mock.patch("scan_history.export_json", return_value="scan.json"), \
             mock.patch("scan_history.export_html", return_value="scan.html") as export_html:
            exit_code = scanner.main()

        self.assertEqual(exit_code, 0)
        export_html.assert_called_once()


class NetworkMapTests(unittest.TestCase):
    def test_scan_network_map_collects_vendor_and_top_risk(self):
        class FakeHost(dict):
            def __init__(self, hostname, state, protocols=None, **kwargs):
                super().__init__(**kwargs)
                self._hostname = hostname
                self._state = state
                self._protocols = protocols or []

            def hostname(self):
                return self._hostname

            def state(self):
                return self._state

            def all_protocols(self):
                return self._protocols

        fake_hosts = {
            "2001:db8::2": FakeHost(
                "lab-box",
                "up",
                protocols=["tcp"],
                addresses={"mac": "AA:BB:CC:DD:EE:FF"},
                vendor={"AA:BB:CC:DD:EE:FF": "Acme Devices"},
                osmatch=[{"name": "Linux 6.x", "accuracy": "98"}],
                tcp={
                    6379: {"state": "open", "name": "redis", "product": "Redis", "version": "7.0"},
                    22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.6"},
                },
            )
        }

        class FakeScanner:
            def scan(self, hosts=None, arguments=None):
                return None

            def all_hosts(self):
                return list(fake_hosts.keys())

            def __getitem__(self, host):
                return fake_hosts[host]

        fake_nmap = type("FakeNmap", (), {"PortScanner": lambda: FakeScanner(), "PortScannerError": RuntimeError})

        with mock.patch.object(network_map, "nmap", fake_nmap), \
             mock.patch("network_map.discover_hosts", return_value=[{"ip": "2001:db8::2", "hostname": "lab-box"}]), \
             mock.patch("network_map.os.geteuid", return_value=0), \
             mock.patch("network_map.scanner.ensure_nmap_available", return_value=None):
            hosts = network_map.scan_network_map("2001:db8::/64")

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["vendor"], "Acme Devices")
        self.assertEqual(hosts[0]["top_risk"], "Critical")
        self.assertIn("redis", hosts[0]["top_services"])

    def test_discover_hosts_sorts_ipv4_and_ipv6_addresses_safely(self):
        class FakeHost:
            def __init__(self, state, hostname):
                self._state = state
                self._hostname = hostname

            def state(self):
                return self._state

            def hostname(self):
                return self._hostname

        fake_hosts = {
            "2001:db8::2": FakeHost("up", "v6-box"),
            "10.0.0.2": FakeHost("up", "v4-box"),
        }

        class FakeScanner:
            def scan(self, hosts=None, arguments=None):
                return None

            def all_hosts(self):
                return ["2001:db8::2", "10.0.0.2"]

            def __getitem__(self, host):
                return fake_hosts[host]

        fake_nmap = type("FakeNmap", (), {"PortScanner": lambda: FakeScanner(), "PortScannerError": RuntimeError})

        with mock.patch.object(network_map, "nmap", fake_nmap), \
             mock.patch("network_map.scanner.ensure_nmap_available", return_value=None):
            hosts = network_map.discover_hosts("test-target", announce=False)

        self.assertEqual([host["ip"] for host in hosts], ["10.0.0.2", "2001:db8::2"])


if __name__ == "__main__":
    unittest.main()
