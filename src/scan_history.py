import contextlib
import csv
import html
import json
import logging
import os
import stat
from datetime import datetime

import scanner

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_DIR = os.path.join(BASE_DIR, "scan_history")
os.makedirs(HISTORY_DIR, mode=0o700, exist_ok=True)

logger = logging.getLogger("scanner")


def _timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


@contextlib.contextmanager
def _secure_open(filepath, mode="w", **kwargs):
    """Open a file for writing with owner-only permissions from the start."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(filepath, flags, 0o600)
    with os.fdopen(fd, mode, **kwargs) as f:
        yield f


def _csv_safe(value):
    """Escape values that could be interpreted as spreadsheet formulas."""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@"):
        return "'" + s
    return s


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
    with _secure_open(filepath) as f:
        json.dump(record, f, indent=2)

    logger.info("Exported JSON scan to %s", filepath)
    return filepath


def export_csv(results, target, ports, filepath=None):
    ts = _timestamp()
    if filepath is None:
        filepath = os.path.join(HISTORY_DIR, _scan_filename(target, ts, "csv"))

    fieldnames = ["timestamp", "target", "host", "hostname", "port", "protocol", "state",
                  "service", "product", "version", "risk"]

    with _secure_open(filepath, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for host_info in results:
            for port_rec in host_info.get("ports", host_info.get("services", [])):
                writer.writerow({
                    "timestamp": ts,
                    "target": target,
                    "host": host_info["host"],
                    "hostname": _csv_safe(host_info.get("hostname", "")),
                    "port": port_rec["port"],
                    "protocol": port_rec.get("protocol", "tcp"),
                    "state": port_rec.get("state", "open"),
                    "service": _csv_safe(port_rec["service"]),
                    "product": _csv_safe(port_rec.get("product", "")),
                    "version": _csv_safe(port_rec.get("version", "")),
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
            file_size = os.path.getsize(fpath)
            if file_size > MAX_SCAN_FILE_BYTES:
                raise OSError(
                    f"Scan file too large ({file_size} bytes, max {MAX_SCAN_FILE_BYTES})."
                )
            with open(fpath) as f:
                data = json.load(f)
            _validate_scan_schema(data)
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
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            logger.warning("Skipping invalid history file %s: %s", fpath, exc)
            continue
    return entries


MAX_SCAN_FILE_BYTES = 10 * 1024 * 1024  # 10 MB
_REQUIRED_SCAN_KEYS = {"timestamp", "target", "ports", "hosts"}


def _validate_scan_schema(data):
    """Check that a loaded scan record has the expected structure."""
    if not isinstance(data, dict):
        raise ValueError("Scan file does not contain a JSON object.")
    missing = _REQUIRED_SCAN_KEYS - data.keys()
    if missing:
        raise ValueError(f"Scan file missing required keys: {', '.join(sorted(missing))}")
    if not isinstance(data["hosts"], list):
        raise ValueError("'hosts' must be a list.")


def load_scan(filepath):
    """Load a scan JSON file. Only allows files inside HISTORY_DIR."""
    real_path = os.path.realpath(filepath)
    allowed_dir = os.path.realpath(HISTORY_DIR)
    if not real_path.startswith(allowed_dir + os.sep) and real_path != allowed_dir:
        raise OSError(
            f"Access denied: scan files must be inside {HISTORY_DIR}/. "
            f"Got: {filepath}"
        )
    file_size = os.path.getsize(real_path)
    if file_size > MAX_SCAN_FILE_BYTES:
        raise OSError(
            f"Scan file too large ({file_size} bytes, max {MAX_SCAN_FILE_BYTES})."
        )
    with open(real_path) as f:
        data = json.load(f)
    _validate_scan_schema(data)
    return data


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def _service_key(host, service):
    return (
        host,
        service["port"],
        service.get("protocol", "tcp"),
        service["service"],
    )


def _service_set(results):
    services = set()
    for host_info in results:
        host = host_info["host"]
        for svc in host_info.get("services", []):
            services.add(_service_key(host, svc))
    return services


def _port_risk_map(results):
    mapping = {}
    for host_info in results:
        host = host_info["host"]
        for svc in host_info.get("services", []):
            mapping[_service_key(host, svc)] = svc.get("risk", "Unknown")
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
        "opened": [
            {"host": h, "port": p, "protocol": proto, "service": s}
            for h, p, proto, s in opened
        ],
        "closed": [
            {"host": h, "port": p, "protocol": proto, "service": s}
            for h, p, proto, s in closed
        ],
        "unchanged": len(unchanged),
        "risk_changes": [
            {
                "host": k[0],
                "port": k[1],
                "protocol": k[2],
                "service": k[3],
                "old_risk": old_r,
                "new_risk": new_r,
            }
            for k, old_r, new_r in risk_changes
        ],
    }


def format_diff(diff):
    lines = []
    if diff["opened"]:
        lines.append("NEW open services:")
        for s in diff["opened"]:
            lines.append(
                f"  + {s['host']}:{s['port']}/{s.get('protocol', 'tcp')} ({s['service']})"
            )
    if diff["closed"]:
        lines.append("CLOSED since last scan:")
        for s in diff["closed"]:
            lines.append(
                f"  - {s['host']}:{s['port']}/{s.get('protocol', 'tcp')} ({s['service']})"
            )
    if diff["risk_changes"]:
        lines.append("Risk level changes:")
        for rc in diff["risk_changes"]:
            lines.append(
                f"  ~ {rc['host']}:{rc['port']}/{rc.get('protocol', 'tcp')} ({rc['service']}): "
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


def _analysis_cache_key(host, service):
    return (
        host,
        service["port"],
        service.get("protocol", "tcp"),
        service["service"],
        service.get("state", "open"),
    )


def populate_ai_cache(results, ai_cache=None, analysis_getter=None):
    if ai_cache is None:
        ai_cache = {}
    if analysis_getter is None:
        return ai_cache

    for host_info in results:
        for svc in host_info.get("services", []):
            key = _analysis_cache_key(host_info["host"], svc)
            if key in ai_cache:
                continue

            service_record = svc.copy()
            service_record["host"] = host_info["host"]
            service_record["hostname"] = host_info.get("hostname") or "N/A"

            try:
                ai_cache[key] = analysis_getter(service_record)
            except Exception as exc:
                logger.warning(
                    "Skipping AI analysis for %s:%s/%s in HTML export: %s",
                    host_info["host"],
                    svc["port"],
                    svc.get("protocol", "tcp"),
                    exc,
                )
    return ai_cache


def export_html(results, target, ports, ai_cache=None, filepath=None, fill_missing_ai=False, analysis_getter=None):
    """Generate a self-contained HTML security report."""
    ts = _timestamp()
    if filepath is None:
        filepath = os.path.join(HISTORY_DIR, _scan_filename(target, ts, "html"))

    if ai_cache is None:
        ai_cache = {}

    if fill_missing_ai:
        populate_ai_cache(results, ai_cache=ai_cache, analysis_getter=analysis_getter)

    e = html.escape

    host_sections = []
    for host_info in results:
        host = host_info["host"]
        hostname = host_info.get("hostname") or "N/A"
        services = host_info.get("services", [])

        score = scanner.compute_host_score(host_info)
        exposure = scanner.host_exposure_summary(host_info)

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
            key = _analysis_cache_key(host, svc)
            analysis = ai_cache.get(key)
            if analysis:
                ai_sections.append(
                    f'<div class="ai-box">'
                    f'<h4>Port {svc["port"]}/{e(svc.get("protocol", "tcp"))} — {e(svc["service"])}</h4>'
                    f'<pre>{e(analysis)}</pre>'
                    f'</div>'
                )

        ai_html = "\n".join(ai_sections) if ai_sections else '<p class="muted">No AI analysis available.</p>'

        host_sections.append(
            f'<div class="host">'
            f'<h2>{e(host)} ({e(hostname)})</h2>'
            f'<p>Security Score: <strong>{score}/100</strong> | '
            f'Open services: {len(services)} | Exposure: {e(exposure)}</p>'
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

    with _secure_open(filepath) as f:
        f.write(report)
    logger.info("Exported HTML report to %s", filepath)
    return filepath
