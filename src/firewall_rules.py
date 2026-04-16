"""Generate iptables and firewalld rules to close unnecessary open ports."""

import logging

logger = logging.getLogger("scanner")

# Ports that are almost always intentional and should be kept open by default
SAFE_PORTS = {
    22,   # SSH
    80,   # HTTP
    443,  # HTTPS
}

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}


def _should_block(service):
    """Decide whether a service should have a block rule generated."""
    port = service["port"]
    risk = service.get("risk", "Unknown")
    if port in SAFE_PORTS and risk in ("Low", "Medium"):
        return False
    if risk in ("Critical", "High"):
        return True
    return False


def collect_blockable_services(results):
    """Return a sorted list of open services that should be blocked."""
    blockable = []
    for host_info in results:
        for svc in host_info.get("services", []):
            if svc.get("state", "open") != "open":
                continue
            if _should_block(svc):
                blockable.append({
                    "host": host_info["host"],
                    "port": svc["port"],
                    "protocol": svc.get("protocol", "tcp"),
                    "service": svc.get("service", "unknown"),
                    "risk": svc.get("risk", "Unknown"),
                })
    blockable.sort(key=lambda s: (RISK_ORDER.get(s["risk"], 99), s["port"]))
    return blockable


def generate_iptables_rules(results):
    """Generate iptables DROP rules for high/critical-risk open ports."""
    services = collect_blockable_services(results)
    if not services:
        return None

    lines = [
        "# iptables rules to block high-risk open ports",
        "# Review each rule before applying — do NOT block ports you need!",
        "",
    ]
    for svc in services:
        proto = svc["protocol"]
        port = svc["port"]
        comment = f"{svc['service']} ({svc['risk']})"
        lines.append(
            f"iptables -A INPUT -p {proto} --dport {port} "
            f'-j DROP -m comment --comment "{comment}"'
        )

    lines.append("")
    lines.append("# Save rules (Debian/Ubuntu):")
    lines.append("#   iptables-save > /etc/iptables/rules.v4")
    lines.append("# Save rules (RHEL/Fedora):")
    lines.append("#   iptables-save > /etc/sysconfig/iptables")
    return "\n".join(lines)


def generate_firewalld_rules(results):
    """Generate firewalld commands to block high/critical-risk open ports."""
    services = collect_blockable_services(results)
    if not services:
        return None

    lines = [
        "# firewalld rules to block high-risk open ports",
        "# Review each rule before applying — do NOT block ports you need!",
        "",
    ]
    for svc in services:
        proto = svc["protocol"]
        port = svc["port"]
        comment = f"# {svc['service']} ({svc['risk']})"
        lines.append(comment)
        lines.append(
            f"firewall-cmd --permanent --remove-port={port}/{proto}"
        )
        lines.append(
            f"firewall-cmd --permanent --add-rich-rule="
            f"'rule port port=\"{port}\" protocol=\"{proto}\" drop'"
        )

    lines.append("")
    lines.append("# Reload to apply:")
    lines.append("firewall-cmd --reload")
    return "\n".join(lines)


def generate_rules_text(results):
    """Return a combined text block with both iptables and firewalld rules."""
    services = collect_blockable_services(results)
    if not services:
        return "No high or critical-risk services found — no firewall rules needed."

    summary_lines = [
        f"Found {len(services)} service(s) recommended for blocking:",
        "",
    ]
    for svc in services:
        summary_lines.append(
            f"  • Port {svc['port']}/{svc['protocol']} — {svc['service']} ({svc['risk']})"
        )

    iptables = generate_iptables_rules(results)
    firewalld = generate_firewalld_rules(results)

    parts = ["\n".join(summary_lines)]
    if iptables:
        parts.append("")
        parts.append("═" * 50)
        parts.append("  iptables rules")
        parts.append("═" * 50)
        parts.append(iptables)
    if firewalld:
        parts.append("")
        parts.append("═" * 50)
        parts.append("  firewalld rules")
        parts.append("═" * 50)
        parts.append(firewalld)

    return "\n".join(parts)


def export_firewall_rules(results, filepath):
    """Write firewall rules to a file."""
    from scan_history import _secure_open
    text = generate_rules_text(results)
    with _secure_open(filepath) as f:
        f.write(text)
    logger.info("Exported firewall rules to %s", filepath)
    return filepath
