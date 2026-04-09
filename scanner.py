import argparse
import json
import shutil
import socket
import urllib.error
import urllib.request

try:
    import nmap
except ImportError:
    nmap = None


DEFAULT_PORT_RANGE = "1-1024"
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
    "ftp": "High",
    "ssh": "Medium",
    "telnet": "Critical",
    "smtp": "Medium",
    "dns": "Medium",
    "http": "Low",
    "pop3": "High",
    "imap": "High",
    "https": "Low",
    "smb": "High",
    "microsoft-ds": "High",
    "mysql": "High",
    "postgresql": "High",
    "rdp": "High",
    "ms-wbt-server": "High",
    "vnc": "High",
    "http-proxy": "Medium",
}


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


def scan_network(target, ports=DEFAULT_PORT_RANGE, announce=True):
    if announce:
        print(f"\n🔍 Scanning {target} (ports {ports})...")
    ensure_nmap_available()

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=f"-sV -p {ports}")
    except (nmap.PortScannerError, OSError) as exc:
        raise ScannerError(f"nmap failed while scanning {target}: {exc}") from exc

    results = []
    for host in nm.all_hosts():
        host_info = {
            "host": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "services": [],
        }
        for proto in nm[host].all_protocols():
            ports_list = sorted(nm[host][proto].keys())
            for port in ports_list:
                info = nm[host][proto][port]
                if info["state"] == "open":
                    service_name = info.get("name", "unknown")
                    host_info["services"].append({
                        "port": port,
                        "service": service_name,
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                        "risk": RISK_LEVELS.get(service_name, "Unknown"),
                    })
        results.append(host_info)
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

        print(f"  {'Port':<8} {'Service':<15} {'Product':<20} {'Risk':<10}")
        print(f"  {'-'*53}")
        for svc in host_info["services"]:
            product = format_product_name(svc)
            color = RISK_COLORS.get(svc["risk"], "")
            reset = "\033[0m"
            print(
                f"  {svc['port']:<8} {svc['service']:<15} {product:<20} "
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
        "1. Briefly explain what the service does\n"
        "2. Explain why it could be a security risk\n"
        "3. Suggest how to secure it\n\n"
        "Keep explanations clear and accessible for someone without deep security knowledge.\n\n"
        "Scan results:\n" + "\n".join(services_summary)
    )

    if announce:
        print("\n🤖 Generating AI security analysis (this may take a moment)...")
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
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as exc:
        raise AIAnalysisError(
            "Could not reach Ollama at http://localhost:11434. Start Ollama or use --no-ai."
        ) from exc
    except json.JSONDecodeError as exc:
        raise AIAnalysisError("Ollama returned an invalid response.") from exc

    response = data.get("response", "").strip()
    if not response:
        raise AIAnalysisError("Ollama returned an empty analysis.")
    return response


def main():
    parser = argparse.ArgumentParser(
        description="Smart Network Scanner - Scan your local network and get AI-powered security insights"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target IP or subnet (e.g., 192.168.1.0/24). Defaults to your local subnet.",
    )
    parser.add_argument(
        "-p", "--ports",
        default=DEFAULT_PORT_RANGE,
        help=f"Port range to scan (default: {DEFAULT_PORT_RANGE})",
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
    args = parser.parse_args()

    try:
        if args.interactive:
            from interactive_cli import launch_dashboard

            return launch_dashboard(
                initial_target=args.target,
                initial_ports=args.ports,
                initial_use_ai=not args.no_ai,
            )

        if args.target is None:
            args.target = get_default_target()
            print(f"ℹ️  No target specified. Using local subnet: {args.target}")

        results = scan_network(args.target, args.ports)
        print_results(results)

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

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
