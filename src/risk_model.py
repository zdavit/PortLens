import logging
import re


logger = logging.getLogger("scanner")


RISK_PRIORITY = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Unknown": 0,
}

RISK_LEVELS = {
    # Remote access
    "ssh": "Medium",
    "telnet": "Critical",
    "rdp": "High",
    "ms-wbt-server": "High",
    "vnc": "High",
    "x11": "High",
    # Web
    "http": "Low",
    "https": "Low",
    "http-proxy": "Medium",
    "http-alt": "Low",
    # File transfer
    "ftp": "High",
    "ftp-data": "High",
    "tftp": "High",
    "nfs": "High",
    # Email
    "smtp": "Medium",
    "pop3": "High",
    "imap": "High",
    "submission": "Medium",
    # DNS / name resolution
    "dns": "Medium",
    "domain": "Medium",
    "llmnr": "Low",
    "mdns": "Low",
    "netbios-ns": "Medium",
    "netbios-ssn": "Medium",
    # Databases
    "mysql": "High",
    "postgresql": "High",
    "mongodb": "Critical",
    "redis": "Critical",
    "memcached": "Critical",
    "elasticsearch": "High",
    "couchdb": "High",
    "ms-sql-s": "High",
    "oracle": "High",
    # File sharing / SMB
    "smb": "High",
    "microsoft-ds": "High",
    # Directory / auth
    "ldap": "High",
    "kerberos": "Medium",
    "kerberos-sec": "Medium",
    # Printing
    "ipp": "Low",
    "printer": "Low",
    "cups": "Low",
    # Proxy / tunnel
    "socks": "High",
    "pptp": "High",
    # Container / orchestration
    "docker": "Critical",
    # Messaging / IoT
    "mqtt": "High",
    "amqp": "Medium",
    "sip": "Medium",
    # RPC / system
    "rpcbind": "Medium",
    "sunrpc": "Medium",
    "msrpc": "Medium",
    "ajp13": "High",
    "snmp": "High",
    # Wrapped / unidentified
    "tcpwrapped": "Medium",
    "unknown": "Medium",
    # UDP-specific services
    "dhcps": "Medium",
    "dhcpc": "Medium",
    "tftp": "High",
    "ntp": "Low",
    "snmp": "High",
    "syslog": "Medium",
    "openvpn": "Medium",
    "isakmp": "Medium",
    "l2tp": "Medium",
    "radius": "Medium",
    "upnp": "High",
    "ssdp": "High",
    "nbdgram": "Medium",
    "nbns": "Medium",
}


SERVICE_NAME_ALIASES = {
    "ssl/http": "https",
    "ssl|http": "https",
    "https-alt": "https",
    "ms-sql": "ms-sql-s",
    "mssql": "ms-sql-s",
    "rdp": "ms-wbt-server",
    "smb": "microsoft-ds",
}

PRODUCT_SERVICE_PATTERNS = [
    ("openssh", "ssh"),
    ("dropbear", "ssh"),
    ("redis", "redis"),
    ("postgresql", "postgresql"),
    ("postgres", "postgresql"),
    ("mariadb", "mysql"),
    ("mysql", "mysql"),
    ("mongodb", "mongodb"),
    ("memcached", "memcached"),
    ("elasticsearch", "elasticsearch"),
    ("couchdb", "couchdb"),
    ("samba", "microsoft-ds"),
    ("microsoft sql", "ms-sql-s"),
    ("sql server", "ms-sql-s"),
    ("openldap", "ldap"),
    ("docker", "docker"),
    ("mosquitto", "mqtt"),
    ("rabbitmq", "amqp"),
    ("bind", "domain"),
    ("dnsmasq", "domain"),
    ("unbound", "domain"),
    ("vsftpd", "ftp"),
    ("proftpd", "ftp"),
    ("pure-ftpd", "ftp"),
    ("nginx", "http"),
    ("apache", "http"),
    ("caddy", "http"),
    ("lighttpd", "http"),
    ("iis", "http"),
]

PORT_SERVICE_HINTS = {
    ("tcp", 21): "ftp",
    ("tcp", 22): "ssh",
    ("tcp", 23): "telnet",
    ("tcp", 25): "smtp",
    ("tcp", 53): "domain",
    ("udp", 53): "domain",
    ("tcp", 80): "http",
    ("tcp", 88): "kerberos",
    ("udp", 88): "kerberos",
    ("tcp", 110): "pop3",
    ("tcp", 111): "rpcbind",
    ("udp", 111): "rpcbind",
    ("tcp", 123): "ntp",
    ("udp", 123): "ntp",
    ("tcp", 135): "msrpc",
    ("tcp", 139): "netbios-ssn",
    ("udp", 137): "netbios-ns",
    ("udp", 138): "nbdgram",
    ("tcp", 143): "imap",
    ("udp", 161): "snmp",
    ("udp", 162): "snmp",
    ("tcp", 389): "ldap",
    ("udp", 389): "ldap",
    ("tcp", 443): "https",
    ("tcp", 445): "microsoft-ds",
    ("tcp", 465): "submission",
    ("tcp", 514): "syslog",
    ("udp", 514): "syslog",
    ("tcp", 587): "submission",
    ("tcp", 631): "ipp",
    ("udp", 631): "ipp",
    ("tcp", 636): "ldap",
    ("tcp", 873): "ftp",
    ("tcp", 993): "imap",
    ("tcp", 995): "pop3",
    ("udp", 1194): "openvpn",
    ("tcp", 1433): "ms-sql-s",
    ("udp", 1434): "ms-sql-s",
    ("udp", 1900): "ssdp",
    ("tcp", 3306): "mysql",
    ("tcp", 3389): "ms-wbt-server",
    ("tcp", 5432): "postgresql",
    ("tcp", 5900): "vnc",
    ("tcp", 5985): "http",
    ("tcp", 5986): "https",
    ("tcp", 6379): "redis",
    ("tcp", 6443): "https",
    ("tcp", 8080): "http-alt",
    ("tcp", 8443): "https",
    ("tcp", 9200): "elasticsearch",
    ("tcp", 1883): "mqtt",
    ("tcp", 2375): "docker",
    ("tcp", 2376): "docker",
    ("tcp", 27017): "mongodb",
    ("tcp", 5000): "http-alt",
}


def _version_lt(version_string, threshold):
    nums = re.findall(r"\d+", version_string)
    thresh_nums = re.findall(r"\d+", threshold)
    if not nums:
        return False
    try:
        return [int(n) for n in nums[:3]] < [int(n) for n in thresh_nums[:3]]
    except ValueError:
        return False


VERSION_RISK_OVERRIDES = {
    "ssh": [
        (lambda v: _version_lt(v, "8.0"), "High", "OpenSSH < 8.0 has known vulnerabilities"),
    ],
    "http": [
        (lambda v: "apache" in v.lower() and _version_lt(v, "2.4"), "High",
         "Apache < 2.4 is end-of-life"),
        (lambda v: "nginx" in v.lower() and _version_lt(v, "1.18"), "Medium",
         "nginx < 1.18 is missing years of security fixes"),
    ],
    "https": [
        (lambda v: "apache" in v.lower() and _version_lt(v, "2.4"), "High",
         "Apache < 2.4 is end-of-life"),
        (lambda v: "nginx" in v.lower() and _version_lt(v, "1.18"), "Medium",
         "nginx < 1.18 is missing years of security fixes"),
    ],
    "ftp": [
        (lambda v: "vsftpd" in v.lower() and _version_lt(v, "3.0"), "Critical",
         "vsftpd < 3.0 has known backdoor vulnerabilities"),
    ],
    "mysql": [
        (lambda v: _version_lt(v, "8.0"), "Critical",
         "MySQL < 8.0 lacks modern security defaults"),
    ],
    "postgresql": [
        (lambda v: _version_lt(v, "13"), "Critical",
         "PostgreSQL < 13 is past end-of-life"),
    ],
    "microsoft-ds": [
        (lambda v: "samba" in v.lower() and _version_lt(v, "4.15"), "Critical",
         "Samba < 4.15 is missing current security support"),
    ],
    "domain": [
        (lambda v: "bind" in v.lower() and _version_lt(v, "9.18"), "High",
         "BIND < 9.18 is behind the current supported branch"),
    ],
}


def _normalize_service_name(service_name):
    normalized = (service_name or "").strip().lower()
    return SERVICE_NAME_ALIASES.get(normalized, normalized)


def _product_hint_service(product="", version="", port=None, protocol="tcp"):
    haystack = f"{product} {version}".strip().lower()
    for needle, inferred_service in PRODUCT_SERVICE_PATTERNS:
        if needle in haystack:
            if inferred_service == "http" and port in (443, 5986, 6443, 8443):
                return "https"
            return inferred_service
    return PORT_SERVICE_HINTS.get(((protocol or "tcp").lower(), port))


def _infer_service_name(service_name, product="", version="", port=None, protocol="tcp"):
    normalized = _normalize_service_name(service_name)
    if normalized in RISK_LEVELS and normalized not in ("unknown", "tcpwrapped"):
        return normalized

    if normalized and normalized not in ("unknown", "tcpwrapped"):
        prefix = normalized.split("/", 1)[0]
        if prefix in RISK_LEVELS:
            return prefix

    hinted_service = _product_hint_service(product, version, port=port, protocol=protocol)
    if hinted_service:
        logger.debug(
            "Inferred service %s from port/product context: service=%r product=%r version=%r port=%r/%s",
            hinted_service,
            service_name,
            product,
            version,
            port,
            protocol,
        )
        return hinted_service

    return normalized


def classify_risk(service_name, product="", version="", port=None, protocol="tcp"):
    normalized_service = _infer_service_name(
        service_name,
        product=product,
        version=version,
        port=port,
        protocol=protocol,
    )
    if not normalized_service or normalized_service == "unknown":
        return "Medium"

    base_risk = RISK_LEVELS.get(normalized_service, "Unknown")
    full_version = f"{product} {version}".strip()

    overrides = VERSION_RISK_OVERRIDES.get(normalized_service, [])
    for check_fn, override_risk, reason in overrides:
        if full_version and check_fn(full_version):
            logger.debug(
                "Risk override for %s (%s): %s -> %s (%s)",
                normalized_service, full_version, base_risk, override_risk, reason,
            )
            return override_risk

    return base_risk


RISK_PENALTIES = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
    "Unknown": 5,
}

SERVICE_EXPOSURE_TAGS = {
    "ssh": {"remote-access"},
    "telnet": {"remote-access", "legacy-insecure"},
    "rdp": {"remote-access"},
    "ms-wbt-server": {"remote-access"},
    "vnc": {"remote-access"},
    "x11": {"remote-access"},
    "ftp": {"legacy-insecure", "file-transfer"},
    "ftp-data": {"legacy-insecure", "file-transfer"},
    "tftp": {"legacy-insecure", "file-transfer"},
    "nfs": {"file-sharing"},
    "smtp": {"messaging"},
    "pop3": {"legacy-insecure", "messaging"},
    "imap": {"messaging"},
    "submission": {"messaging"},
    "dns": {"infrastructure"},
    "domain": {"infrastructure"},
    "mysql": {"database"},
    "postgresql": {"database"},
    "mongodb": {"database"},
    "redis": {"database"},
    "memcached": {"database"},
    "elasticsearch": {"database"},
    "couchdb": {"database"},
    "ms-sql-s": {"database"},
    "oracle": {"database"},
    "smb": {"file-sharing"},
    "microsoft-ds": {"file-sharing"},
    "ldap": {"directory-auth"},
    "kerberos": {"directory-auth"},
    "kerberos-sec": {"directory-auth"},
    "docker": {"admin-plane"},
    "rpcbind": {"admin-plane"},
    "sunrpc": {"admin-plane"},
    "msrpc": {"admin-plane"},
    "snmp": {"admin-plane"},
    "ajp13": {"admin-plane"},
    "http-proxy": {"proxy"},
    "socks": {"proxy"},
    "mqtt": {"messaging"},
    "amqp": {"messaging"},
    "sip": {"messaging"},
    "upnp": {"legacy-insecure", "infrastructure"},
    "ssdp": {"legacy-insecure", "infrastructure"},
}

EXPOSURE_PENALTIES = {
    "remote-access": 6,
    "legacy-insecure": 10,
    "file-transfer": 4,
    "file-sharing": 6,
    "messaging": 4,
    "database": 8,
    "directory-auth": 6,
    "admin-plane": 10,
    "proxy": 5,
    "infrastructure": 3,
}

EXPOSURE_LABELS = {
    "remote-access": "Remote access",
    "legacy-insecure": "Legacy / insecure protocols",
    "file-transfer": "File transfer",
    "file-sharing": "File sharing",
    "messaging": "Messaging",
    "database": "Databases",
    "directory-auth": "Directory / auth",
    "admin-plane": "Admin plane",
    "proxy": "Proxying",
    "infrastructure": "Infrastructure",
}


def compute_host_score(host_info):
    """Return a 0-100 security score for a host. 100 = no open services."""
    services = host_info.get("services", [])
    penalty = sum(RISK_PENALTIES.get(svc.get("risk", "Unknown"), 5) for svc in services)
    penalty += sum(EXPOSURE_PENALTIES.get(tag, 0) for tag in host_exposure_tags(host_info))

    if len(services) >= 8:
        penalty += 8
    elif len(services) >= 4:
        penalty += 4

    return max(0, 100 - penalty)


def score_label(score):
    if score >= 90:
        return "Excellent"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Fair"
    if score >= 30:
        return "Poor"
    return "Critical"


def service_exposure_tags(service_name):
    return SERVICE_EXPOSURE_TAGS.get(service_name or "", set())


def host_exposure_tags(host_info):
    tags = set()
    for svc in host_info.get("services", []):
        tags.update(service_exposure_tags(svc.get("service", "")))
    return sorted(tags)


def exposure_label(tag):
    return EXPOSURE_LABELS.get(tag, tag.replace("-", " ").title())


def host_exposure_summary(host_info, limit=3):
    labels = [exposure_label(tag) for tag in host_exposure_tags(host_info)]
    if not labels:
        return "Minimal exposed surface"
    if len(labels) <= limit:
        return ", ".join(labels)
    return ", ".join(labels[:limit]) + f", +{len(labels) - limit} more"


def highest_risk_level(services):
    return max(
        (svc.get("risk", "Unknown") for svc in services),
        key=lambda risk: RISK_PRIORITY.get(risk, 0),
        default="Unknown",
    )
