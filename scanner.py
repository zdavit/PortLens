import argparse
import json
import socket
import urllib.request
import nmap

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


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def scan_network(target, ports="1-1024"):
    print(f"\n🔍 Scanning {target} (ports {ports})...")
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments=f"-sV -p {ports}")

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
            product = svc["product"]
            if svc["version"]:
                product += f" {svc['version']}"
            risk_colors = {
                "Critical": "\033[91m",
                "High": "\033[93m",
                "Medium": "\033[33m",
                "Low": "\033[92m",
                "Unknown": "\033[90m",
            }
            color = risk_colors.get(svc["risk"], "")
            reset = "\033[0m"
            print(
                f"  {svc['port']:<8} {svc['service']:<15} {product:<20} "
                f"{color}{svc['risk']}{reset}"
            )


def get_ai_analysis(results):
    services_summary = []
    for host_info in results:
        for svc in host_info["services"]:
            services_summary.append(
                f"Port {svc['port']}: {svc['service']} "
                f"({svc['product']} {svc['version']}) - Risk: {svc['risk']}"
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

    print("\n🤖 Generating AI security analysis (this may take a moment)...")
    payload = json.dumps({
        "model": "llama3.2",
        "prompt": prompt,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())
    return data["response"]


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
        default="1-1024",
        help="Port range to scan (default: 1-1024)",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis",
    )
    args = parser.parse_args()

    if args.target is None:
        local_ip = get_local_ip()
        subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
        print(f"ℹ️  No target specified. Using local subnet: {subnet}")
        args.target = subnet

    results = scan_network(args.target, args.ports)
    print_results(results)

    if not args.no_ai:
        all_services = [s for h in results for s in h["services"]]
        if all_services:
            analysis = get_ai_analysis(results)
            print(f"\n{'='*60}")
            print("  🛡️  AI Security Analysis")
            print(f"{'='*60}")
            print(analysis)
        else:
            print("\nNo open services to analyze.")

    print()


if __name__ == "__main__":
    main()
