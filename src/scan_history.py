import csv
import html
import json
import logging
import os
import stat
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_DIR = os.path.join(BASE_DIR, "scan_history")
os.makedirs(HISTORY_DIR, mode=0o700, exist_ok=True)

logger = logging.getLogger("scanner")


def _timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _secure_file(filepath):
    """Set file permissions to owner-only read/write (0600)."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


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
    _secure_file(filepath)

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

    _secure_file(filepath)
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
    """Load a scan JSON file. Only allows files inside HISTORY_DIR."""
    real_path = os.path.realpath(filepath)
    allowed_dir = os.path.realpath(HISTORY_DIR)
    if not real_path.startswith(allowed_dir + os.sep) and real_path != allowed_dir:
        raise OSError(
            f"Access denied: scan files must be inside {HISTORY_DIR}/. "
            f"Got: {filepath}"
        )
    with open(real_path) as f:
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


# ---------------------------------------------------------------------------
# HTML report export
# ---------------------------------------------------------------------------

_RISK_COLORS = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Medium": "#f39c12",
    "Low": "#27ae60",
    "Unknown": "#95a5a6",
}


def export_html(results, target, ports, ai_cache=None, filepath=None):
    """Generate a self-contained HTML security report."""
    ts = _timestamp()
    if filepath is None:
        filepath = os.path.join(HISTORY_DIR, _scan_filename(target, ts, "html"))

    if ai_cache is None:
        ai_cache = {}

    e = html.escape

    host_sections = []
    for host_info in results:
        host = host_info["host"]
        hostname = host_info.get("hostname") or "N/A"
        services = host_info.get("services", [])

        # Compute score inline
        penalty = 0
        risk_penalties = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Unknown": 5}
        for svc in services:
            penalty += risk_penalties.get(svc.get("risk", "Unknown"), 5)
        score = max(0, 100 - penalty)

        rows = []
        for svc in host_info.get("ports", services):
            risk = svc.get("risk", "Unknown")
            color = _RISK_COLORS.get(risk, "#95a5a6")
            product = svc.get("product", "")
            if svc.get("version"):
                product += f" {svc['version']}"
            product = product.strip() or "N/A"
            rows.append(
                f'<tr>'
                f'<td>{svc["port"]}/{e(svc.get("protocol", "tcp"))}</td>'
                f'<td>{e(svc.get("state", "open"))}</td>'
                f'<td>{e(svc.get("service", "unknown"))}</td>'
                f'<td>{e(product)}</td>'
                f'<td style="color:{color};font-weight:bold">{e(risk)}</td>'
                f'</tr>'
            )

        ai_sections = []
        for svc in services:
            key = (host, svc["port"], svc["service"], svc.get("state", "open"))
            analysis = ai_cache.get(key)
            if analysis:
                ai_sections.append(
                    f'<div class="ai-box">'
                    f'<h4>Port {svc["port"]} — {e(svc["service"])}</h4>'
                    f'<pre>{e(analysis)}</pre>'
                    f'</div>'
                )

        ai_html = "\n".join(ai_sections) if ai_sections else '<p class="muted">No AI analysis available.</p>'

        host_sections.append(
            f'<div class="host">'
            f'<h2>{e(host)} ({e(hostname)})</h2>'
            f'<p>Security Score: <strong>{score}/100</strong> | '
            f'Open services: {len(services)}</p>'
            f'<table><thead><tr>'
            f'<th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Risk</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
            f'<h3>AI Analysis</h3>{ai_html}'
            f'</div>'
        )

    body = "\n".join(host_sections) if host_sections else '<p>No hosts found.</p>'

    report = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Security Report — {e(target)} — {e(ts)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       max-width: 960px; margin: 2em auto; padding: 0 1em; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #00d9ff; }} h2 {{ color: #00d9ff; border-bottom: 1px solid #333; padding-bottom: .3em; }}
h3 {{ color: #bb86fc; }} h4 {{ color: #03dac6; margin: .5em 0; }}
table {{ width: 100%; border-collapse: collapse; margin: 1em 0; }}
th, td {{ padding: .5em .8em; text-align: left; border-bottom: 1px solid #333; }}
th {{ background: #16213e; color: #00d9ff; }}
tr:hover {{ background: #16213e; }}
.host {{ margin: 2em 0; }}
.ai-box {{ background: #16213e; padding: 1em; border-radius: 6px; margin: .8em 0; }}
.ai-box pre {{ white-space: pre-wrap; margin: 0; }}
.muted {{ color: #666; }}
</style></head><body>
<h1>🛡️ Security Report</h1>
<p>Target: <strong>{e(target)}</strong> | Ports: {e(ports)} | Generated: {e(ts)}</p>
{body}
</body></html>"""

    with open(filepath, "w") as f:
        f.write(report)
    _secure_file(filepath)
    logger.info("Exported HTML report to %s", filepath)
    return filepath
