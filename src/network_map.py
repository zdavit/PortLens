import logging
import os

import scanner

try:
    import nmap
except ImportError:
    nmap = None

logger = logging.getLogger("scanner")

_OS_FAMILY_KEYWORDS = ["Linux", "Windows", "macOS", "FreeBSD", "OpenBSD", "NetBSD", "iOS", "Android"]


def _best_os_guess(os_matches):
    """Pick the best OS guess by aggregating matches into OS families.

    If the top match has high confidence (>=90%), use it directly.
    Otherwise, group matches by OS family and return the family with the
    highest combined weight, along with the best specific match name.
    """
    best = os_matches[0]
    best_acc = int(best.get("accuracy", 0))

    if best_acc >= 90:
        return f"{best.get('name', 'Unknown')} ({best_acc}%)"

    family_scores = {}
    family_best = {}
    for match in os_matches:
        name = match.get("name", "")
        acc = int(match.get("accuracy", 0))
        family = "Other"
        for kw in _OS_FAMILY_KEYWORDS:
            if kw.lower() in name.lower():
                family = kw
                break
        family_scores[family] = family_scores.get(family, 0) + acc
        if family not in family_best or acc > int(family_best[family].get("accuracy", 0)):
            family_best[family] = match

    top_family = max(family_scores, key=family_scores.get)
    top_match = family_best[top_family]
    top_acc = int(top_match.get("accuracy", 0))
    return f"{top_match.get('name', 'Unknown')} ({top_acc}%)"


def discover_hosts(target, announce=True, progress_callback=None):
    """Run a fast ping sweep to find live hosts on a subnet."""
    scanner.ensure_nmap_available()
    logger.info("Host discovery starting: target=%s", target)
    if announce:
        print(f"\n🔎 Discovering live hosts on {target}...")
    if progress_callback:
        progress_callback(0, 0, "Discovering live hosts...")

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sn -T4 -n")
    except (nmap.PortScannerError, OSError) as exc:
        logger.error("Host discovery failed: %s", exc, exc_info=True)
        raise scanner.ScannerError(f"Host discovery failed: {exc}") from exc

    live_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            live_hosts.append({
                "ip": host,
                "hostname": nm[host].hostname() or "",
            })

    live_hosts.sort(key=lambda h: tuple(int(p) for p in h["ip"].split(".") if p.isdigit()))
    logger.info("Host discovery found %d live host(s)", len(live_hosts))
    if announce:
        print(f"   Found {len(live_hosts)} live host(s).")
    return live_hosts


def scan_network_map(target, progress_callback=None):
    """Discover hosts on a subnet with OS detection and open port counts.

    Runs ``nmap -O -T4 -n --top-ports 100`` which requires root.
    Returns a list of dicts: host, hostname, os_guess, open_port_count, state.
    """
    target = scanner.validate_target(target)
    scanner.ensure_nmap_available()
    if os.geteuid() != 0:
        raise scanner.ScannerError("Network mapping with OS detection requires root. Run with sudo.")

    # Discover live hosts first, then OS-detect only those in one batch
    live = discover_hosts(target, announce=False)
    if not live:
        logger.info("No live hosts found on %s", target)
        return []

    live_ips = " ".join(h["ip"] for h in live)
    logger.info("Network map: OS-detecting %d live host(s)", len(live))

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=live_ips, arguments="-O --osscan-guess -T4 -n --top-ports 100")
    except (nmap.PortScannerError, OSError) as exc:
        logger.error("Network map scan failed: %s", exc, exc_info=True)
        raise scanner.ScannerError(f"Network map scan failed: {exc}") from exc

    hosts = []
    for host in nm.all_hosts():
        hostname = nm[host].hostname() or ""
        state = nm[host].state()

        os_guess = "Unknown"
        try:
            os_matches = nm[host].get("osmatch", [])
            if os_matches:
                os_guess = _best_os_guess(os_matches)
        except (KeyError, IndexError):
            pass

        open_count = 0
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                if nm[host][proto][port].get("state") == "open":
                    open_count += 1

        hosts.append({
            "host": host,
            "hostname": hostname,
            "os_guess": os_guess,
            "open_port_count": open_count,
            "state": state,
        })

    hosts.sort(key=lambda h: tuple(int(p) for p in h["host"].split(".") if p.isdigit()))
    logger.info("Network map found %d host(s)", len(hosts))
    return hosts
