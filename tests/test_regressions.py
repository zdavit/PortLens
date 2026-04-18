import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import firewall_rules
import interactive_cli
import scan_history
import scanner


class ScanDiffRegressionTests(unittest.TestCase):
    def test_diff_scans_treats_protocol_changes_as_real_changes(self):
        old_results = [
            {
                "host": "host-a",
                "services": [
                    {"port": 53, "protocol": "tcp", "service": "domain", "risk": "Medium"}
                ],
            }
        ]
        new_results = [
            {
                "host": "host-a",
                "services": [
                    {"port": 53, "protocol": "udp", "service": "domain", "risk": "Medium"}
                ],
            }
        ]

        diff = scan_history.diff_scans(old_results, new_results)

        self.assertEqual(diff["unchanged"], 0)
        self.assertEqual(
            diff["opened"],
            [{"host": "host-a", "port": 53, "protocol": "udp", "service": "domain"}],
        )
        self.assertEqual(
            diff["closed"],
            [{"host": "host-a", "port": 53, "protocol": "tcp", "service": "domain"}],
        )

    def test_format_diff_includes_protocol_labels(self):
        diff = {
            "opened": [{"host": "host-a", "port": 53, "protocol": "udp", "service": "domain"}],
            "closed": [{"host": "host-a", "port": 22, "protocol": "tcp", "service": "ssh"}],
            "unchanged": 0,
            "risk_changes": [
                {
                    "host": "host-a",
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "old_risk": "Low",
                    "new_risk": "Medium",
                }
            ],
        }

        text = scan_history.format_diff(diff)

        self.assertIn("host-a:53/udp (domain)", text)
        self.assertIn("host-a:22/tcp (ssh)", text)
        self.assertIn("host-a:443/tcp (https): Low -> Medium", text)


class FirewallRegressionTests(unittest.TestCase):
    def test_firewall_rules_refuse_remote_scan_results(self):
        results = [
            {
                "host": "203.0.113.10",
                "services": [
                    {"port": 6379, "protocol": "tcp", "service": "redis", "risk": "Critical"}
                ],
            }
        ]

        text = firewall_rules.generate_rules_text(results)

        self.assertIn("only safe for scans of this machine", text)
        self.assertNotIn("iptables -A INPUT", text)
        self.assertIsNone(firewall_rules.generate_iptables_rules(results))
        self.assertIsNone(firewall_rules.generate_firewalld_rules(results))

    def test_firewall_rules_still_work_for_localhost(self):
        results = [
            {
                "host": "127.0.0.1",
                "services": [
                    {"port": 6379, "protocol": "tcp", "service": "redis", "risk": "Critical"}
                ],
            }
        ]

        text = firewall_rules.generate_rules_text(results)

        self.assertIn("iptables -A INPUT -p tcp --dport 6379", text)
        self.assertIn("firewall-cmd --permanent --remove-port=6379/tcp", text)

    def test_firewall_rules_generate_ip6tables_for_local_ipv6_hosts(self):
        results = [
            {
                "host": "::1",
                "services": [
                    {"port": 6379, "protocol": "tcp", "service": "redis", "risk": "Critical"}
                ],
            }
        ]

        with unittest.mock.patch("firewall_rules._local_host_aliases", return_value={"::1"}):
            text = firewall_rules.generate_rules_text(results)

        self.assertIn("ip6tables -A INPUT -p tcp --dport 6379", text)
        self.assertNotIn("iptables -A INPUT -p tcp --dport 6379", text)

    def test_firewall_rules_refuse_remote_ipv6_results(self):
        results = [
            {
                "host": "2001:db8::55",
                "services": [
                    {"port": 6379, "protocol": "tcp", "service": "redis", "risk": "Critical"}
                ],
            }
        ]

        with unittest.mock.patch("firewall_rules._local_host_aliases", return_value={"::1"}):
            text = firewall_rules.generate_rules_text(results)

        self.assertIn("only safe for scans of this machine", text)
        self.assertNotIn("ip6tables -A INPUT", text)


class ClosedPortRegressionTests(unittest.TestCase):
    def test_extract_extraport_states_reads_closed_counts(self):
        xml = """<?xml version='1.0'?>
<nmaprun>
  <host>
    <status state='up'/>
    <address addr='127.0.0.1' addrtype='ipv4'/>
    <ports>
      <extraports state='closed' count='4'>
        <extrareasons reason='resets' count='4'/>
      </extraports>
    </ports>
  </host>
</nmaprun>
"""

        class FakeScanner:
            def get_nmap_last_output(self):
                return xml

        states = scanner.extract_extraport_states(FakeScanner(), {"127.0.0.1"})

        self.assertEqual(states, {"127.0.0.1": {"closed": 4}})

    def test_merge_host_info_synthesizes_closed_rows_for_definite_closed_ports(self):
        combined = {}
        host_info = {
            "host": "127.0.0.1",
            "hostname": "localhost",
            "state": "up",
            "services": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.0",
                    "risk": "Medium",
                }
            ],
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.0",
                    "risk": "Medium",
                }
            ],
        }

        scanner._merge_host_info(
            combined,
            host_info,
            chunk_spec="21-25",
            scan_mode="tcp",
            ignored_states={"closed": 4},
        )

        app = interactive_cli.DashboardApp(initial_target="localhost", initial_ports="21-25")
        app.results = list(combined.values())
        app.show_closed = True
        rows = app.flatten_services()
        closed_rows = [row for row in rows if row["state"] == "closed"]

        self.assertEqual({row["port"] for row in closed_rows}, {21, 23, 24, 25})

    def test_merge_host_info_skips_synthesis_when_ignored_states_are_mixed(self):
        combined = {}
        host_info = {
            "host": "127.0.0.1",
            "hostname": "localhost",
            "state": "up",
            "services": [],
            "ports": [],
        }

        scanner._merge_host_info(
            combined,
            host_info,
            chunk_spec="1-5",
            scan_mode="tcp",
            ignored_states={"closed": 3, "filtered": 2},
        )

        self.assertEqual(combined["127.0.0.1"]["ports"], [])


class AiCacheAndWatchRegressionTests(unittest.TestCase):
    def test_dashboard_service_key_distinguishes_protocols(self):
        app = interactive_cli.DashboardApp(initial_target="localhost", initial_ports="53")

        tcp_key = app.service_key({
            "host": "127.0.0.1",
            "port": 53,
            "protocol": "tcp",
            "service": "domain",
            "state": "open",
        })
        udp_key = app.service_key({
            "host": "127.0.0.1",
            "port": 53,
            "protocol": "udp",
            "service": "domain",
            "state": "open",
        })

        self.assertNotEqual(tcp_key, udp_key)

    def test_html_ai_cache_key_distinguishes_protocols(self):
        tcp_key = scan_history._analysis_cache_key("127.0.0.1", {
            "port": 53,
            "protocol": "tcp",
            "service": "domain",
            "state": "open",
        })
        udp_key = scan_history._analysis_cache_key("127.0.0.1", {
            "port": 53,
            "protocol": "udp",
            "service": "domain",
            "state": "open",
        })

        self.assertNotEqual(tcp_key, udp_key)

    def test_watch_mode_skips_history_export_when_results_do_not_change(self):
        app = interactive_cli.DashboardApp(initial_target="localhost", initial_ports="22")
        app.watch_mode = True
        app.watch_previous_results = [{"host": "127.0.0.1", "services": []}]
        app.scan_triggered_by_watch = True
        payload = [{"host": "127.0.0.1", "hostname": "localhost", "services": [], "ports": []}]
        app.events.put(("results", payload))

        with unittest.mock.patch("interactive_cli.scan_history.diff_scans", return_value={
            "opened": [],
            "closed": [],
            "risk_changes": [],
            "unchanged": 0,
        }), unittest.mock.patch("interactive_cli.scan_history.export_json") as export_json:
            app.process_events()

        export_json.assert_not_called()

    def test_watch_mode_still_saves_when_results_change(self):
        app = interactive_cli.DashboardApp(initial_target="localhost", initial_ports="22")
        app.watch_mode = True
        app.watch_previous_results = [{"host": "127.0.0.1", "services": []}]
        app.scan_triggered_by_watch = True
        payload = [{"host": "127.0.0.1", "hostname": "localhost", "services": [], "ports": []}]
        app.events.put(("results", payload))

        with unittest.mock.patch("interactive_cli.scan_history.diff_scans", return_value={
            "opened": [{"host": "127.0.0.1", "port": 22, "protocol": "tcp", "service": "ssh"}],
            "closed": [],
            "risk_changes": [],
            "unchanged": 0,
        }), unittest.mock.patch("interactive_cli.scan_history.export_json", return_value="scan.json") as export_json:
            app.process_events()

        export_json.assert_called_once_with(payload, "localhost", "22")


if __name__ == "__main__":
    unittest.main()
