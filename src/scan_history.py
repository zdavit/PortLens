import csv
import json
import logging
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_DIR = os.path.join(BASE_DIR, "scan_history")
os.makedirs(HISTORY_DIR, exist_ok=True)

logger = logging.getLogger("scanner")


def _timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _scan_filename(target, timestamp, ext):
    safe_target = target.replace("/", "_").replace(":", "_").replace(" ", "_")
    return f"{timestamp}_{safe_target}.{ext}"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_json(results, target, ports, filepath=None):
    ts = _timestamp()
    if filepath is None:
        filepath = os.path.join(HISTORY_DIR, _scan_filename(target, ts, "json"))

    record = {
        "timestamp": ts,
        "target": target,
        "ports": ports,
        "hosts": results,
    }
    with open(filepath, "w") as f:
        json.dump(record, f, indent=2)

    logger.info("Exported JSON scan to %s", filepath)
    return filepath


def export_csv(results, target, ports, filepath=None):
    ts = _timestamp()
    if filepath is None:
        filepath = os.path.join(HISTORY_DIR, _scan_filename(target, ts, "csv"))

    fieldnames = ["timestamp", "target", "host", "hostname", "port", "protocol", "state",
                  "service", "product", "version", "risk"]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for host_info in results:
            for port_rec in host_info.get("ports", host_info.get("services", [])):
                writer.writerow({
                    "timestamp": ts,
                    "target": target,
                    "host": host_info["host"],
                    "hostname": host_info.get("hostname", ""),
                    "port": port_rec["port"],
                    "protocol": port_rec.get("protocol", "tcp"),
                    "state": port_rec.get("state", "open"),
                    "service": port_rec["service"],
                    "product": port_rec.get("product", ""),
                    "version": port_rec.get("version", ""),
                    "risk": port_rec.get("risk", "Unknown"),
                })

    logger.info("Exported CSV scan to %s", filepath)
    return filepath


# ---------------------------------------------------------------------------
# History listing
# ---------------------------------------------------------------------------

def list_history():
    files = sorted(
        [f for f in os.listdir(HISTORY_DIR) if f.endswith(".json")],
        reverse=True,
    )
    entries = []
    for fname in files:
        fpath = os.path.join(HISTORY_DIR, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
            entries.append({
                "filename": fname,
                "filepath": fpath,
                "timestamp": data.get("timestamp", ""),
                "target": data.get("target", ""),
                "ports": data.get("ports", ""),
                "host_count": len(data.get("hosts", [])),
                "open_count": sum(
                    len(h.get("services", [])) for h in data.get("hosts", [])
                ),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return entries


def load_scan(filepath):
    with open(filepath) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def _service_set(results):
    services = set()
    for host_info in results:
        host = host_info["host"]
        for svc in host_info.get("services", []):
            services.add((host, svc["port"], svc["service"]))
    return services


def _port_risk_map(results):
    mapping = {}
    for host_info in results:
        host = host_info["host"]
        for svc in host_info.get("services", []):
            mapping[(host, svc["port"], svc["service"])] = svc.get("risk", "Unknown")
    return mapping


def diff_scans(old_results, new_results):
    old_services = _service_set(old_results)
    new_services = _service_set(new_results)

    opened = sorted(new_services - old_services)
    closed = sorted(old_services - new_services)
    unchanged = sorted(old_services & new_services)

    old_risks = _port_risk_map(old_results)
    new_risks = _port_risk_map(new_results)
    risk_changes = []
    for key in unchanged:
        old_risk = old_risks.get(key, "Unknown")
        new_risk = new_risks.get(key, "Unknown")
        if old_risk != new_risk:
            risk_changes.append((key, old_risk, new_risk))

    return {
        "opened": [{"host": h, "port": p, "service": s} for h, p, s in opened],
        "closed": [{"host": h, "port": p, "service": s} for h, p, s in closed],
        "unchanged": len(unchanged),
        "risk_changes": [
            {"host": k[0], "port": k[1], "service": k[2],
             "old_risk": old_r, "new_risk": new_r}
            for k, old_r, new_r in risk_changes
        ],
    }


def format_diff(diff):
    lines = []
    if diff["opened"]:
        lines.append("NEW open services:")
        for s in diff["opened"]:
            lines.append(f"  + {s['host']}:{s['port']} ({s['service']})")
    if diff["closed"]:
        lines.append("CLOSED since last scan:")
        for s in diff["closed"]:
            lines.append(f"  - {s['host']}:{s['port']} ({s['service']})")
    if diff["risk_changes"]:
        lines.append("Risk level changes:")
        for rc in diff["risk_changes"]:
            lines.append(
                f"  ~ {rc['host']}:{rc['port']} ({rc['service']}): "
                f"{rc['old_risk']} -> {rc['new_risk']}"
            )
    lines.append(f"Unchanged services: {diff['unchanged']}")
    if not diff["opened"] and not diff["closed"] and not diff["risk_changes"]:
        lines.append("No changes detected since the last scan.")
    return "\n".join(lines)
