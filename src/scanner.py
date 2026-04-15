import argparse
import json
import logging
import os
import shutil
import socket
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_log_filename = datetime.now().strftime("scan_%Y-%m-%d_%H-%M-%S.log")
logging.basicConfig(
    filename=os.path.join(LOG_DIR, _log_filename),
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("scanner")

try:
    import nmap
except ImportError:
    nmap = None


SCAN_CHUNK_SIZE = 4096
DEFAULT_PORT_RANGE = "1-1024"
INTERACTIVE_DEFAULT_TARGET = "localhost"
INTERACTIVE_DEFAULT_PORT_RANGE = "1-100"
CLOSED_PORT_DISPLAY_LIMIT = 12
MAX_PORT_NUMBER = 65535
MAX_PORTS_PER_SCAN = 65535
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"
RISK_COLORS = {
    "Critical": "\033[91m",
    "High": "\033[93m",
    "Medium": "\033[33m",
    "Low": "\033[92m",
    "Unknown": "\033[90m",
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

VERSION_RISK_OVERRIDES = {
    "ssh": [
        (lambda v: _version_lt(v, "8.0"), "High", "OpenSSH < 8.0 has known vulnerabilities"),
    ],
    "http": [
        (lambda v: "apache" in v.lower() and _version_lt(v, "2.4"), "High",
         "Apache < 2.4 is end-of-life"),
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
}


def _version_lt(version_string, threshold):
    import re
    nums = re.findall(r"\d+", version_string)
    thresh_nums = re.findall(r"\d+", threshold)
    if not nums:
        return False
    try:
        return [int(n) for n in nums[:3]] < [int(n) for n in thresh_nums[:3]]
    except ValueError:
        return False


def classify_risk(service_name, product="", version=""):
    if not service_name or service_name in ("", "unknown"):
        return "Medium"

    base_risk = RISK_LEVELS.get(service_name, "Unknown")
    full_version = f"{product} {version}".strip()

    overrides = VERSION_RISK_OVERRIDES.get(service_name, [])
    for check_fn, override_risk, reason in overrides:
        if full_version and check_fn(full_version):
            logger.debug(
                "Risk override for %s (%s): %s -> %s (%s)",
                service_name, full_version, base_risk, override_risk, reason,
            )
            return override_risk

    return base_risk

COMMON_EDUCATIONAL_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    3306,
    3389,
    5432,
    6379,
    8080,
]


class ScannerError(Exception):
    """Raised when the scanner cannot complete a scan."""


class AIAnalysisError(Exception):
    """Raised when the AI analysis step fails."""


def ensure_nmap_available():
    if nmap is None:
        raise ScannerError(
            "The python-nmap package is not installed. Run `pip install -r requirements.txt`."
        )
    if shutil.which("nmap") is None:
        raise ScannerError(
            "The `nmap` command is not installed or not on PATH. Install nmap first."
        )


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        hostname_ip = socket.gethostbyname(socket.gethostname())
        if hostname_ip and not hostname_ip.startswith("127."):
            return hostname_ip
        raise ScannerError(
            "Unable to determine the local subnet automatically. Provide a target explicitly."
        )
    finally:
        s.close()


def get_default_target():
    local_ip = get_local_ip()
    return ".".join(local_ip.split(".")[:3]) + ".0/24"


def format_product_name(service):
    product = service["product"]
    if service["version"]:
        product += f" {service['version']}"
    return product.strip() or "N/A"


def collect_open_services(results):
    return [service for host in results for service in host["services"]]


def validate_ports_spec(ports_spec):
    logger.debug("Validating port spec: %s", ports_spec)
    if not ports_spec or not ports_spec.strip():
        raise ScannerError("Port range cannot be empty.")

    total_ports = 0
    normalized_chunks = []

    for chunk in ports_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            raise ScannerError("Port list contains an empty entry.")

        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            try:
                start = int(start_text)
                end = int(end_text)
            except ValueError as exc:
                raise ScannerError(
                    f"Invalid port range `{chunk}`. Use values like `80`, `443`, or `1-100`."
                ) from exc
        else:
            try:
                start = end = int(chunk)
            except ValueError as exc:
                raise ScannerError(
                    f"Invalid port `{chunk}`. Use values like `80`, `443`, or `1-100`."
                ) from exc

        if start > end:
            start, end = end, start

        if start < 1 or end < 1:
            raise ScannerError("Ports must be positive integers.")
        if end > MAX_PORT_NUMBER:
            raise ScannerError(
                f"Port ranges are limited to {MAX_PORT_NUMBER} or lower to keep scans responsive."
            )

        total_ports += end - start + 1
        if total_ports > MAX_PORTS_PER_SCAN:
            raise ScannerError(
                f"Port ranges are limited to {MAX_PORTS_PER_SCAN} ports per scan to avoid long hangs."
            )

        normalized_chunks.append(f"{start}-{end}" if start != end else str(start))

    return ",".join(normalized_chunks)


def count_ports_in_spec(ports_spec):
    total = 0
    for chunk in ports_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            total += int(end) - int(start) + 1
        else:
            total += 1
    return total


def chunk_port_spec(ports_spec, chunk_size=SCAN_CHUNK_SIZE):
    all_ports = list(iter_ports_in_ranges(parse_port_ranges(ports_spec)))
    chunks = []
    for i in range(0, len(all_ports), chunk_size):
        batch = all_ports[i : i + chunk_size]
        if len(batch) == 1:
            chunks.append(str(batch[0]))
        else:
            chunks.append(f"{batch[0]}-{batch[-1]}")
    return chunks


def lookup_service_name(port, protocol="tcp"):
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


def parse_port_ranges(ports_spec):
    ranges = []
    for chunk in ports_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            try:
                start = int(start_text)
                end = int(end_text)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            ranges.append((start, end))
        else:
            try:
                port = int(chunk)
            except ValueError:
                continue
            ranges.append((port, port))
    return ranges


def port_in_ranges(port, ranges):
    return any(start <= port <= end for start, end in ranges)


def iter_ports_in_ranges(ranges):
    for start, end in ranges:
        for port in range(start, end + 1):
            yield port


def synthesize_closed_ports(ports_spec, existing_ports, limit=CLOSED_PORT_DISPLAY_LIMIT):
    ranges = parse_port_ranges(ports_spec)
    if not ranges:
        return []

    candidates = []
    seen = set(existing_ports)

    for port in COMMON_EDUCATIONAL_PORTS:
        if port not in seen and port_in_ranges(port, ranges):
            candidates.append(port)
            seen.add(port)
        if len(candidates) >= limit:
            return candidates

    for port in iter_ports_in_ranges(ranges):
        if port in seen:
            continue
        candidates.append(port)
        seen.add(port)
        if len(candidates) >= limit:
            break

    return candidates


def extract_collapsed_closed_ports(nm, scanned_hosts):
    xml_output = nm.get_nmap_last_output()
    if not xml_output:
        return {}

    if isinstance(xml_output, bytes):
        xml_output = xml_output.decode(errors="ignore")

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return {}

    collapsed_ports = {}
    for host in root.findall("host"):
        if host.find("status") is None or host.find("status").attrib.get("state") != "up":
            continue

        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address[@addrtype='ipv6']")
        if address is None:
            continue

        host_id = address.attrib.get("addr")
        if host_id not in scanned_hosts:
            continue

        ports_node = host.find("ports")
        if ports_node is None:
            continue

        port_specs = []
        for extraports in ports_node.findall("extraports"):
            if extraports.attrib.get("state") != "closed":
                continue
            for reason in extraports.findall("extrareasons"):
                ports_attr = reason.attrib.get("ports")
                if ports_attr:
                    port_specs.append(ports_attr)

        if port_specs:
            collapsed_ports[host_id] = ",".join(port_specs)

    return collapsed_ports


def request_ai_response(prompt, announce_message=None):
    if announce_message:
        print(announce_message)

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        OLLAMA_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        ai_start = time.time()
        logger.debug("Sending AI request to %s", OLLAMA_API_URL)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        logger.debug("AI response received in %.1f seconds", time.time() - ai_start)
    except urllib.error.URLError as exc:
        logger.error("AI request failed (URL error): %s", exc)
        raise AIAnalysisError(
            "Could not reach Ollama at http://localhost:11434. Start Ollama or use --no-ai."
        ) from exc
    except json.JSONDecodeError as exc:
        logger.error("AI response was not valid JSON")
        raise AIAnalysisError("Ollama returned an invalid response.") from exc

    response = data.get("response", "").strip()
    if not response:
        logger.warning("AI returned an empty response")
        raise AIAnalysisError("Ollama returned an empty analysis.")
    return response


SCAN_MODES = ("tcp", "udp", "both")


def _check_root_for_scan(scan_mode):
    if scan_mode in ("udp", "both") and os.geteuid() != 0:
        raise ScannerError(
            f"{scan_mode.upper()} scanning requires root privileges. "
            f"Run with sudo or switch to TCP mode."
        )


def _nmap_scan_args(scan_mode, chunk_spec):
    if scan_mode == "udp":
        return f"-sU --version-intensity 0 -T4 -n -p {chunk_spec}"
    elif scan_mode == "both":
        return f"-sS -sU -sV --version-intensity 0 -T4 -n -p {chunk_spec}"
    else:
        return f"-sV --version-intensity 0 -T4 -n -p {chunk_spec}"


def _merge_host_info(combined, host_info):
    if host_info["host"] not in combined:
        combined[host_info["host"]] = {
            "host": host_info["host"],
            "hostname": host_info["hostname"],
            "state": host_info["state"],
            "services": [],
            "ports": [],
        }
    entry = combined[host_info["host"]]
    entry["ports"].extend(host_info["ports"])
    entry["services"].extend(host_info["services"])
    if host_info.get("hostname"):
        entry["hostname"] = host_info["hostname"]


def scan_network(target, ports=DEFAULT_PORT_RANGE, announce=True, progress_callback=None, scan_mode="tcp"):
    _check_root_for_scan(scan_mode)
    ports = validate_ports_spec(ports)
    total_ports = count_ports_in_spec(ports)
    logger.info("Starting scan: target=%s ports=%s (%d ports) mode=%s", target, ports, total_ports, scan_mode)
    if announce:
        mode_label = scan_mode.upper()
        print(f"\n🔍 Scanning {target} (ports {ports}, {mode_label})...")
    ensure_nmap_available()

    chunks = chunk_port_spec(ports)
    logger.info("Split into %d chunk(s) of up to %d ports each", len(chunks), SCAN_CHUNK_SIZE)

    combined = {}
    scanned_ports = 0
    scan_start = time.time()

    for chunk_index, chunk_spec in enumerate(chunks):
        chunk_count = count_ports_in_spec(chunk_spec)
        logger.info("Scanning chunk %d/%d: ports %s", chunk_index + 1, len(chunks), chunk_spec)

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments=_nmap_scan_args(scan_mode, chunk_spec))
        except (nmap.PortScannerError, OSError) as exc:
            logger.error("nmap scan failed on chunk %s: %s", chunk_spec, exc, exc_info=True)
            raise ScannerError(f"nmap failed while scanning {target}: {exc}") from exc

        for host in nm.all_hosts():
            host_info = {
                "host": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "services": [],
                "ports": [],
            }
            for proto in nm[host].all_protocols():
                ports_list = sorted(nm[host][proto].keys())
                for port in ports_list:
                    info = nm[host][proto][port]
                    service_name = info.get("name", "unknown")
                    product = info.get("product", "")
                    version = info.get("version", "")
                    port_record = {
                        "port": port,
                        "protocol": proto,
                        "state": info.get("state", "unknown"),
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "risk": classify_risk(service_name, product, version),
                    }
                    host_info["ports"].append(port_record)
                    if port_record["state"] == "open":
                        host_info["services"].append(port_record.copy())
            _merge_host_info(combined, host_info)

        scanned_ports += chunk_count
        if progress_callback:
            progress_callback(scanned_ports, total_ports)

    scan_elapsed = time.time() - scan_start
    logger.info("nmap scan finished in %.1f seconds", scan_elapsed)

    results = list(combined.values())

    total_open = sum(len(h["services"]) for h in results)
    total_port_records = sum(len(h["ports"]) for h in results)
    logger.info(
        "Scan results: %d host(s), %d open service(s), %d total port records",
        len(results), total_open, total_port_records,
    )
    return results


def print_results(results):
    if not results:
        print("\n⚠️  No hosts found or no open ports detected.")
        return

    for host_info in results:
        print(f"\n{'='*60}")
        print(f"  Host: {host_info['host']} ({host_info['hostname'] or 'N/A'})")
        print(f"  State: {host_info['state']}")
        print(f"{'='*60}")

        if not host_info["services"]:
            print("  No open ports detected.")
            continue

        print(f"  {'Port':<10} {'Service':<15} {'Product':<20} {'Risk':<10}")
        print(f"  {'-'*55}")
        for svc in host_info["services"]:
            product = format_product_name(svc)
            color = RISK_COLORS.get(svc["risk"], "")
            reset = "\033[0m"
            proto = svc.get("protocol", "tcp")
            port_label = f"{svc['port']}/{proto}"
            print(
                f"  {port_label:<10} {svc['service']:<15} {product:<20} "
                f"{color}{svc['risk']}{reset}"
            )


def get_ai_analysis(results, announce=True):
    services_summary = []
    for host_info in results:
        for svc in host_info["services"]:
            services_summary.append(
                f"Port {svc['port']}: {svc['service']} "
                f"({format_product_name(svc)}) - Risk: {svc['risk']}"
            )

    if not services_summary:
        return "No open services found to analyze."

    prompt = (
        "You are a cybersecurity expert. Analyze the following network scan results "
        "from a local network scan. For each open service:\n"
        "1. Identify what the port and service is — if the service name is empty, unknown, or "
        "tcpwrapped, use the port number to explain what commonly runs on that port\n"
        "2. Briefly explain what the service does\n"
        "3. Explain why it could be a security risk\n"
        "4. Suggest how to secure it\n\n"
        "Keep explanations clear and accessible for someone without deep security knowledge.\n\n"
        "Scan results:\n" + "\n".join(services_summary)
    )

    announce_message = None
    if announce:
        announce_message = "\n🤖 Generating AI security analysis (this may take a moment)..."
    return request_ai_response(prompt, announce_message)


def get_service_ai_analysis(service, announce=True):
    location = service.get("host", "unknown host")
    hostname = service.get("hostname") or "N/A"
    service_name = service['service'] or "unidentified"
    product = service.get('product', '') or "not detected"
    prompt = (
        "You are a cybersecurity expert. Analyze this single open network service and only this service.\n"
        "Return plain text only in exactly this format:\n"
        "Overview: <one short sentence about the detected service>\n\n"
        "What is this: <explain what this port/service is typically used for, what software commonly runs on it, "
        "and why it might be open on this machine — even if the service name is vague, empty, or wrapped>\n\n"
        "Risks:\n"
        "- <short risk>\n"
        "- <short risk>\n\n"
        "Actions:\n"
        "1. <short action>\n"
        "2. <short action>\n"
        "3. <short action>\n\n"
        "Rules:\n"
        "- No markdown formatting, code blocks, bold text, or headings other than Overview, What is this, Risks, Actions.\n"
        "- Add a blank line between each section (Overview, What is this, Risks, Actions).\n"
        "- If the service name is empty, unknown, or tcpwrapped, use the port number to infer what "
        "commonly runs there and explain that.\n"
        "- Focus only on the selected port.\n"
        "- Keep every line concise and easy to read in a terminal UI.\n\n"
        f"Host: {location} ({hostname})\n"
        f"Port: {service['port']}\n"
        f"Service: {service_name}\n"
        f"Product: {product}\n"
        f"Risk: {service['risk']}"
    )

    announce_message = None
    if announce:
        announce_message = (
            f"\n🤖 Generating AI security analysis for port {service['port']} "
            f"({service['service']})..."
        )
    return request_ai_response(prompt, announce_message)


def main():
    parser = argparse.ArgumentParser(
        description="Smart Network Scanner - Scan your local network and get AI-powered security insights"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help=(
            "Target IP or subnet (e.g., 192.168.1.0/24). Defaults to your local subnet "
            "in CLI mode and localhost in interactive mode."
        ),
    )
    parser.add_argument(
        "-p", "--ports",
        default=None,
        help=(
            f"Port range to scan. Defaults to {DEFAULT_PORT_RANGE} in CLI mode and "
            f"{INTERACTIVE_DEFAULT_PORT_RANGE} in interactive mode. Max port {MAX_PORT_NUMBER}, "
            f"max {MAX_PORTS_PER_SCAN} ports per scan."
        ),
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Launch the full-screen interactive dashboard",
    )
    parser.add_argument(
        "--export",
        choices=["json", "csv", "both"],
        default=None,
        help="Export scan results to JSON, CSV, or both (saved in scan_history/)",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show past scan history and exit",
    )
    parser.add_argument(
        "--diff",
        metavar="FILE",
        default=None,
        help="Compare current scan against a previous scan JSON file",
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Scan UDP ports instead of TCP (requires root/sudo)",
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Scan both TCP and UDP ports (requires root/sudo)",
    )
    args = parser.parse_args()

    import scan_history

    if args.history:
        entries = scan_history.list_history()
        if not entries:
            print("No scan history found.")
            return 0
        print(f"\n{'='*70}")
        print("  📋 Scan History")
        print(f"{'='*70}")
        print(f"  {'Timestamp':<22} {'Target':<20} {'Hosts':<7} {'Open':<6} File")
        print(f"  {'-'*65}")
        for e in entries:
            print(
                f"  {e['timestamp']:<22} {e['target']:<20} "
                f"{e['host_count']:<7} {e['open_count']:<6} {e['filename']}"
            )
        print()
        return 0

    scan_mode = "both" if args.both else ("udp" if args.udp else "tcp")

    try:
        if args.interactive:
            from interactive_cli import launch_dashboard

            return launch_dashboard(
                initial_target=args.target or INTERACTIVE_DEFAULT_TARGET,
                initial_ports=args.ports or INTERACTIVE_DEFAULT_PORT_RANGE,
                initial_use_ai=not args.no_ai,
                initial_scan_mode=scan_mode,
            )

        if args.target is None:
            args.target = get_default_target()
            print(f"ℹ️  No target specified. Using local subnet: {args.target}")

        if args.ports is None:
            args.ports = DEFAULT_PORT_RANGE

        results = scan_network(args.target, args.ports, scan_mode=scan_mode)
        print_results(results)

        json_path = scan_history.export_json(results, args.target, args.ports)
        print(f"\n💾 Scan saved to {json_path}")

        if args.export in ("csv", "both"):
            csv_path = scan_history.export_csv(results, args.target, args.ports)
            print(f"💾 CSV exported to {csv_path}")
        if args.export in ("json", "both"):
            print(f"💾 JSON already saved above.")

        if args.diff:
            try:
                old_scan = scan_history.load_scan(args.diff)
            except (OSError, json.JSONDecodeError) as exc:
                print(f"\n⚠️  Could not load previous scan: {exc}")
            else:
                diff = scan_history.diff_scans(old_scan["hosts"], results)
                print(f"\n{'='*60}")
                print("  🔄 Scan Diff")
                print(f"{'='*60}")
                print(scan_history.format_diff(diff))

        if not args.no_ai:
            all_services = collect_open_services(results)
            if all_services:
                try:
                    analysis = get_ai_analysis(results)
                except AIAnalysisError as exc:
                    print(f"\n⚠️  AI analysis unavailable: {exc}")
                else:
                    print(f"\n{'='*60}")
                    print("  🛡️  AI Security Analysis")
                    print(f"{'='*60}")
                    print(analysis)
            else:
                print("\nNo open services to analyze.")
    except ScannerError as exc:
        print(f"\n❌ {exc}")
        return 1
    except KeyboardInterrupt:
        print()
        return 130

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
