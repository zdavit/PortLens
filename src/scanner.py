import argparse
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import time
import xml.etree.ElementTree as ET

from ai_client import (
    AI_MAX_RESPONSE_BYTES,
    AIAnalysisError,
    OLLAMA_API_URL,
    OLLAMA_MODEL,
    get_ai_analysis,
    get_service_ai_analysis,
    request_ai_response,
)
from datetime import datetime
from risk_model import (
    RISK_LEVELS,
    classify_risk,
    compute_host_score,
    highest_risk_level,
    host_exposure_summary,
    score_label,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)

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


SCAN_CHUNK_SIZE = 2048
SCAN_PARALLEL_CHUNKS = 8
DEFAULT_PORT_RANGE = "1-1024"
INTERACTIVE_DEFAULT_TARGET = "localhost"
INTERACTIVE_DEFAULT_PORT_RANGE = "1-100"
CLOSED_PORT_DISPLAY_LIMIT = 12
MAX_PORT_NUMBER = 65535
MAX_PORTS_PER_SCAN = 65535
RISK_COLORS = {
    "Critical": "\033[91m",
    "High": "\033[93m",
    "Medium": "\033[33m",
    "Low": "\033[92m",
    "Unknown": "\033[90m",
}


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


def ensure_nmap_available():
    if nmap is None:
        raise ScannerError(
            "The python-nmap package is not installed. Run `pip install -r requirements.txt`."
        )
    if shutil.which("nmap") is None:
        raise ScannerError(
            "The `nmap` command is not installed or not on PATH. Install nmap first."
        )


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_CONTROL_CHAR_KEEP_NL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
MAX_BANNER_LEN = 200


def sanitize_banner(text):
    """Strip control characters, ANSI escapes, and truncate to MAX_BANNER_LEN."""
    if not text:
        return text
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CONTROL_CHAR_RE.sub("", text)
    return text[:MAX_BANNER_LEN]


def sanitize_text(text):
    """Strip control characters and ANSI escapes, preserving newlines and tabs."""
    if not text:
        return text
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CONTROL_CHAR_KEEP_NL_RE.sub("", text)
    return text


def validate_target(target):
    """Validate and sanitize a scan target. Returns the cleaned target string."""
    if not target or not target.strip():
        raise ScannerError("Target cannot be empty.")

    target = target.strip()

    if target.startswith("-"):
        raise ScannerError("Invalid target: must not start with '-'.")

    dangerous = [" ", "\t", "\n", "\r", ";", "&", "|", "$", "`", "(", ")", "{", "}", "<", ">", "\\", "'", '"']
    for ch in dangerous:
        if ch in target:
            raise ScannerError(f"Invalid target: contains disallowed character '{ch}'.")

    if target == "localhost":
        return target

    # Try as IP address
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            min_prefix = 64 if net.version == 6 else 16
            if net.prefixlen < min_prefix:
                raise ScannerError(
                    f"Subnet too large: minimum prefix length is /{min_prefix} for IPv{net.version}."
                )
            return str(net)
        else:
            ipaddress.ip_address(target)
            return target
    except ValueError:
        pass

    # Try as hostname
    if _HOSTNAME_RE.fullmatch(target) and ".." not in target:
        return target

    raise ScannerError("Target must be an IP address, CIDR range (e.g. 192.168.1.0/24), 'localhost', or a valid hostname.")


def get_local_ip():
    for family, endpoint in (
        (socket.AF_INET, ("8.8.8.8", 80)),
        (socket.AF_INET6, ("2001:4860:4860::8888", 80)),
    ):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            s.connect(endpoint)
            local_ip = s.getsockname()[0]
            if local_ip:
                return local_ip
        except OSError:
            pass
        finally:
            s.close()

    try:
        addresses = socket.getaddrinfo(socket.gethostname(), None)
    except socket.gaierror:
        addresses = []

    for family, _, _, _, sockaddr in addresses:
        host = sockaddr[0]
        try:
            parsed = ipaddress.ip_address(host)
        except ValueError:
            continue
        if not parsed.is_loopback:
            return host

    raise ScannerError(
        "Unable to determine the local subnet automatically. Provide a target explicitly."
    )


def get_default_target():
    local_ip = ipaddress.ip_address(get_local_ip())
    if local_ip.version == 6:
        return str(ipaddress.ip_network(f"{local_ip}/64", strict=False))
    return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))


def format_product_name(service):
    product = service["product"]
    if service["version"]:
        product += f" {service['version']}"
    return product.strip() or "N/A"


def collect_open_services(results):
    return [service for host in results for service in host["services"]]


def _host_sort_key(host):
    try:
        parsed = ipaddress.ip_address(host)
        return (0, parsed.version, int(parsed))
    except ValueError:
        return (1, str(host).lower())


def _merge_port_ranges(ranges):
    if not ranges:
        return []

    merged = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)

    return [(start, end) for start, end in merged]


def _format_port_ranges(ranges):
    return ",".join(
        f"{start}-{end}" if start != end else str(start)
        for start, end in ranges
    )


def _format_port_list(ports):
    return _format_port_ranges(_merge_port_ranges((port, port) for port in ports))


def validate_ports_spec(ports_spec):
    logger.debug("Validating port spec: %s", ports_spec)
    if not ports_spec or not ports_spec.strip():
        raise ScannerError("Port range cannot be empty.")

    ranges = []

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

        ranges.append((start, end))

    merged_ranges = _merge_port_ranges(ranges)
    total_ports = sum(end - start + 1 for start, end in merged_ranges)
    if total_ports > MAX_PORTS_PER_SCAN:
        raise ScannerError(
            f"Port ranges are limited to {MAX_PORTS_PER_SCAN} ports per scan to avoid long hangs."
        )

    return _format_port_ranges(merged_ranges)


def count_ports_in_spec(ports_spec):
    ranges = _merge_port_ranges(parse_port_ranges(ports_spec))
    return sum(end - start + 1 for start, end in ranges)


def chunk_port_spec(ports_spec, chunk_size=SCAN_CHUNK_SIZE):
    ranges = _merge_port_ranges(parse_port_ranges(ports_spec))
    all_ports = list(iter_ports_in_ranges(ranges))
    chunks = []
    for i in range(0, len(all_ports), chunk_size):
        batch = all_ports[i : i + chunk_size]
        chunks.append(_format_port_list(batch))
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


def _record_sort_key(record):
    return (
        int(record.get("port", 0)),
        record.get("protocol", "tcp"),
        0 if record.get("state", "open") == "open" else 1,
        record.get("service", ""),
        record.get("product", ""),
        record.get("version", ""),
    )


def _record_identity(record):
    return (
        int(record.get("port", 0)),
        record.get("protocol", "tcp"),
        record.get("state", "open"),
        record.get("service", ""),
        record.get("product", ""),
        record.get("version", ""),
        record.get("risk", "Unknown"),
    )


def _dedupe_and_sort_records(records):
    deduped = {}
    for record in records:
        deduped[_record_identity(record)] = record.copy()
    return sorted(deduped.values(), key=_record_sort_key)


def _finalize_results(results):
    finalized = []
    for host_info in sorted(results, key=lambda host: _host_sort_key(host["host"])):
        entry = host_info.copy()
        entry["ports"] = _dedupe_and_sort_records(entry.get("ports", []))
        entry["services"] = _dedupe_and_sort_records(entry.get("services", []))
        finalized.append(entry)
    return finalized


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


def extract_extraport_states(nm, scanned_hosts):
    xml_output = nm.get_nmap_last_output()
    if not xml_output:
        return {}

    if isinstance(xml_output, bytes):
        xml_output = xml_output.decode(errors="ignore")

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return {}

    extraport_states = {}
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

        state_counts = {}
        for extraports in ports_node.findall("extraports"):
            state = extraports.attrib.get("state")
            if not state:
                continue
            try:
                count = int(extraports.attrib.get("count", "0"))
            except ValueError:
                count = 0
            state_counts[state] = state_counts.get(state, 0) + count

        if state_counts:
            extraport_states[host_id] = state_counts

    return extraport_states


SCAN_MODES = ("tcp", "udp", "both")


def _check_root_for_scan(scan_mode):
    if scan_mode in ("udp", "both") and os.geteuid() != 0:
        raise ScannerError(
            f"{scan_mode.upper()} scanning requires root privileges. "
            f"Run with sudo or switch to TCP mode."
        )


def _nmap_scan_args(scan_mode, chunk_spec):
    base = "--version-intensity 0 -T4 --min-rate 300 -n"
    if scan_mode == "udp":
        return f"-sU {base} -p {chunk_spec}"
    elif scan_mode == "both":
        return f"-sS -sU -sV {base} -p {chunk_spec}"
    else:
        return f"-sV {base} -p {chunk_spec}"


def _add_closed_port_samples(entry, chunk_spec, scan_mode, ignored_states):
    if not chunk_spec or not ignored_states or set(ignored_states) != {"closed"}:
        return

    existing_closed = sum(1 for port in entry["ports"] if port.get("state") == "closed")
    remaining = CLOSED_PORT_DISPLAY_LIMIT - existing_closed
    if remaining <= 0:
        return

    protocols = ["tcp", "udp"] if scan_mode == "both" else [scan_mode]
    for protocol in protocols:
        if remaining <= 0:
            break

        existing_ports = {
            port_info["port"]
            for port_info in entry["ports"]
            if port_info.get("protocol", "tcp") == protocol
        }
        for port in synthesize_closed_ports(chunk_spec, existing_ports, limit=remaining):
            service_name = lookup_service_name(port, protocol)
            entry["ports"].append({
                "port": port,
                "protocol": protocol,
                "state": "closed",
                "service": service_name,
                "product": "",
                "version": "",
                "risk": classify_risk(service_name),
            })
            remaining -= 1
            if remaining <= 0:
                break


def _merge_host_info(combined, host_info, lock=None, chunk_spec=None, scan_mode="tcp", ignored_states=None):
    if lock:
        lock.acquire()
    try:
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
        # Only synthesize hidden rows when nmap says every omitted port in this chunk was closed.
        _add_closed_port_samples(entry, chunk_spec, scan_mode, ignored_states)
    finally:
        if lock:
            lock.release()


def _parse_nmap_host(nm, host):
    """Extract host info and port records from an nmap scan result."""
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
            service_name = sanitize_banner(info.get("name", "unknown"))
            product = sanitize_banner(info.get("product", ""))
            version = sanitize_banner(info.get("version", ""))
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
    return host_info


def _is_subnet_target(target):
    """Check if the target is a subnet (CIDR) rather than a single host."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.num_addresses > 1
    except ValueError:
        return False


def scan_network(target, ports=DEFAULT_PORT_RANGE, announce=True, progress_callback=None, scan_mode="tcp"):
    target = validate_target(target)
    _check_root_for_scan(scan_mode)
    ports = validate_ports_spec(ports)
    total_ports = count_ports_in_spec(ports)
    logger.info("Starting scan: target=%s ports=%s (%d ports) mode=%s", target, ports, total_ports, scan_mode)
    if announce:
        mode_label = scan_mode.upper()
        print(f"\n🔍 Scanning {target} (ports {ports}, {mode_label})...")
    ensure_nmap_available()

    # For subnet targets, discover live hosts first to avoid scanning dead IPs
    if _is_subnet_target(target):
        from network_map import discover_hosts
        live = discover_hosts(target, announce=announce, progress_callback=progress_callback)
        if not live:
            logger.info("No live hosts found on %s", target)
            return []
        scan_targets = [h["ip"] for h in live]
        logger.info("Scanning %d live host(s) instead of full subnet", len(scan_targets))
        if announce:
            print(f"   Scanning {len(scan_targets)} live host(s) on ports {ports}...")
    else:
        scan_targets = [target]

    chunks = chunk_port_spec(ports)
    logger.info("Split into %d chunk(s) of up to %d ports each", len(chunks), SCAN_CHUNK_SIZE)

    combined = {}
    total_work = len(scan_targets) * len(chunks)
    scan_start = time.time()

    use_parallel = len(chunks) > 1 and SCAN_PARALLEL_CHUNKS > 1
    if use_parallel:
        import concurrent.futures
        import threading

        lock = threading.Lock()
        completed_work = [0]  # mutable counter for threads

        def _scan_chunk(host_target, chunk_index, chunk_spec):
            logger.info("Scanning host %s chunk %d/%d: ports %s", host_target, chunk_index + 1, len(chunks), chunk_spec)
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=host_target, arguments=_nmap_scan_args(scan_mode, chunk_spec))
            except (nmap.PortScannerError, OSError) as exc:
                logger.error("nmap scan failed on %s chunk %s: %s", host_target, chunk_spec, exc, exc_info=True)
                raise ScannerError(f"nmap failed while scanning {host_target}: {exc}") from exc

            ignored_states = extract_extraport_states(nm, set(nm.all_hosts()))
            for host in nm.all_hosts():
                host_info = _parse_nmap_host(nm, host)
                _merge_host_info(
                    combined,
                    host_info,
                    lock=lock,
                    chunk_spec=chunk_spec,
                    scan_mode=scan_mode,
                    ignored_states=ignored_states.get(host),
                )

            with lock:
                completed_work[0] += 1
                if progress_callback:
                    progress_callback(completed_work[0], total_work)

        workers = min(SCAN_PARALLEL_CHUNKS, len(chunks))
        logger.info("Scanning with %d parallel workers", workers)
        if progress_callback:
            progress_callback(0, total_work, f"Scanning with {workers} parallel workers...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = []
            for host_target in scan_targets:
                for chunk_index, chunk_spec in enumerate(chunks):
                    futures.append(pool.submit(_scan_chunk, host_target, chunk_index, chunk_spec))

            for future in concurrent.futures.as_completed(futures):
                future.result()  # re-raises any ScannerError
    else:
        completed_work = 0
        for host_target in scan_targets:
            for chunk_index, chunk_spec in enumerate(chunks):
                logger.info("Scanning host %s chunk %d/%d: ports %s", host_target, chunk_index + 1, len(chunks), chunk_spec)

                try:
                    nm = nmap.PortScanner()
                    nm.scan(hosts=host_target, arguments=_nmap_scan_args(scan_mode, chunk_spec))
                except (nmap.PortScannerError, OSError) as exc:
                    logger.error("nmap scan failed on %s chunk %s: %s", host_target, chunk_spec, exc, exc_info=True)
                    raise ScannerError(f"nmap failed while scanning {host_target}: {exc}") from exc

                ignored_states = extract_extraport_states(nm, set(nm.all_hosts()))
                for host in nm.all_hosts():
                    host_info = _parse_nmap_host(nm, host)
                    _merge_host_info(
                        combined,
                        host_info,
                        chunk_spec=chunk_spec,
                        scan_mode=scan_mode,
                        ignored_states=ignored_states.get(host),
                    )

                completed_work += 1
                if progress_callback:
                    progress_callback(completed_work, total_work)

    scan_elapsed = time.time() - scan_start
    logger.info("nmap scan finished in %.1f seconds", scan_elapsed)

    results = _finalize_results(list(combined.values()))

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


def main():
    parser = argparse.ArgumentParser(
        description="PortLens - Scan your local network and get AI-powered security insights"
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
        choices=["json", "csv", "html", "both", "all"],
        default=None,
        help="Export scan results to JSON, CSV, HTML, or all formats (saved in scan_history/)",
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
        "--firewall",
        action="store_true",
        help="Generate iptables, ip6tables, or firewalld rules to block high-risk open ports",
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

        if args.export in ("csv", "both", "all"):
            csv_path = scan_history.export_csv(results, args.target, args.ports)
            print(f"💾 CSV exported to {csv_path}")
        if args.export in ("json", "both", "all"):
            print(f"💾 JSON already saved above.")
        if args.export in ("html", "all"):
            print("\n🧾 Generating HTML security report...")
            html_path = scan_history.export_html(
                results,
                args.target,
                args.ports,
                fill_missing_ai=not args.no_ai,
                analysis_getter=(
                    lambda svc: get_service_ai_analysis(svc, announce=False)
                ) if not args.no_ai else None,
            )
            print(f"💾 HTML exported to {html_path}")

        if args.diff:
            try:
                old_scan = scan_history.load_scan(args.diff)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"\n⚠️  Could not load previous scan: {exc}")
            else:
                diff = scan_history.diff_scans(old_scan["hosts"], results)
                print(f"\n{'='*60}")
                print("  🔄 Scan Diff")
                print(f"{'='*60}")
                print(scan_history.format_diff(diff))

        if args.firewall:
            import firewall_rules
            rules_text = firewall_rules.generate_rules_text(results)
            print(f"\n{'='*60}")
            print("  🔥 Firewall Rule Suggestions")
            print(f"{'='*60}")
            print(rules_text)

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
