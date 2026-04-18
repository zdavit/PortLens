"""Generate iptables and firewalld rules to close unnecessary open ports."""

import contextlib
import logging
import socket

logger = logging.getLogger("scanner")

# Ports that are almost always intentional and should be kept open by default
SAFE_PORTS = {
    22,   # SSH
    80,   # HTTP
    443,  # HTTPS
}

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
ALLOWED_PROTOCOLS = {"tcp", "udp"}


def _safe_label(text):
    """Strip shell-unsafe characters from a label used in generated commands."""
    import re
    return re.sub(r"[^A-Za-z0-9 _.()/,-]", "", str(text))[:60]


def _should_block(service):
    """Decide whether a service should have a block rule generated."""
    port = service["port"]
    risk = service.get("risk", "Unknown")
    if port in SAFE_PORTS and risk in ("Low", "Medium"):
        return False
    if risk in ("Critical", "High"):
        return True
    return False


def _local_host_aliases():
    aliases = {"localhost", "127.0.0.1", "::1"}

    for name in ("localhost", socket.gethostname(), socket.getfqdn()):
        if not name:
            continue
        aliases.add(name)
        with contextlib.suppress(socket.gaierror):
            for _, _, _, _, sockaddr in socket.getaddrinfo(name, None):
                if sockaddr:
                    aliases.add(sockaddr[0])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with contextlib.suppress(OSError):
            sock.connect(("8.8.8.8", 80))
            aliases.add(sock.getsockname()[0])
    finally:
        sock.close()

    return aliases


def _remote_scan_warning(results):
    if not results:
        return None

    local_aliases = _local_host_aliases()
    remote_hosts = sorted(
        {
            host_info["host"]
            for host_info in results
            if host_info.get("host") not in local_aliases
        }
    )
    if not remote_hosts:
        return None

    preview = ", ".join(remote_hosts[:3])
    if len(remote_hosts) > 3:
        preview += f", +{len(remote_hosts) - 3} more"

    logger.warning("Refusing firewall rule generation for remote hosts: %s", preview)
    return (
        "Firewall suggestions are only safe for scans of this machine. "
        f"Current results include remote host(s): {preview}. "
        "Scan localhost or this machine's IP directly before generating firewall rules."
    )


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
    if _remote_scan_warning(results):
        return None

    services = collect_blockable_services(results)
    if not services:
        return None

    lines = [
        "# iptables rules to block high-risk open ports",
        "# Review each rule before applying — do NOT block ports you need!",
        "",
    ]
    for svc in services:
        proto = svc["protocol"] if svc["protocol"] in ALLOWED_PROTOCOLS else "tcp"
        port = int(svc["port"])
        comment = _safe_label(f"{svc['service']} ({svc['risk']})")
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
    if _remote_scan_warning(results):
        return None

    services = collect_blockable_services(results)
    if not services:
        return None

    lines = [
        "# firewalld rules to block high-risk open ports",
        "# Review each rule before applying — do NOT block ports you need!",
        "",
    ]
    for svc in services:
        proto = svc["protocol"] if svc["protocol"] in ALLOWED_PROTOCOLS else "tcp"
        port = int(svc["port"])
        comment = _safe_label(f"{svc['service']} ({svc['risk']})")
        lines.append(f"# {comment}")
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
    warning = _remote_scan_warning(results)
    if warning:
        return warning

    services = collect_blockable_services(results)
    if not services:
        return "No high or critical-risk services found — no firewall rules needed."

    summary_lines = [
        f"Found {len(services)} service(s) recommended for blocking:",
        "",
    ]
    for svc in services:
        proto = svc["protocol"] if svc["protocol"] in ALLOWED_PROTOCOLS else "tcp"
        summary_lines.append(
            f"  • Port {int(svc['port'])}/{proto} — {_safe_label(svc['service'])} ({svc['risk']})"
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
