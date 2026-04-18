import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import firewall_rules
import scan_history


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


if __name__ == "__main__":
    unittest.main()
