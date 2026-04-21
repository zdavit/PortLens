# PortLens

PortLens is a CLI tool that scans your local network for open ports and running services, then uses a local AI model (Ollama + llama3.2) to explain potential security risks in plain language.

[![Watch the demo](https://img.youtube.com/vi/9PS6Ip5TzUY/hqdefault.jpg)](https://youtu.be/9PS6Ip5TzUY)

## Features

- **Network device mapping** — scan a subnet and view a table of all discovered hosts with hostname, highest observed risk, vendor/MAC info when available, and OS guess (`nmap -O`); select a host to set it as the scan target
- **Two-phase scanning** — automatic ping sweep discovers live hosts first, then only port-scans those hosts (dramatically faster on subnets)
- **Security score summary** — per-host 0-100 security score based on the number, severity, and exposure type of open services, shown in the detail pane
- **Target input validation** — rejects shell characters, nmap option injection, and overly broad subnets before scanning
- **Full port scanning** — scan any range up to all 65535 ports with parallel chunked nmap (8 concurrent workers, `-T4`, `--min-rate 300`, `-sV`)
- **70+ service risk classifications** — covers remote access, web, databases, file sharing, printing, DNS, RPC, containers, and more
- **Version-aware risk overrides** — outdated software (e.g., OpenSSH < 8.0, MySQL < 8.0, PostgreSQL < 13) is automatically escalated to a higher risk level
- **AI-powered security analysis** — per-service explanations with Overview, What is this, Risks, and Actions sections powered by Ollama + llama3.2
- **Interactive curses dashboard** — full-screen terminal UI with live scanning, service browsing, and inline AI analysis
- **Port range presets** — quick menu with common ranges (1-100, 1-1024, 1-10000, all ports, common services) plus custom input
- **Scan history** — every scan auto-saves to `scan_history/` as JSON for future reference
- **JSON/CSV/HTML export** — export results and reports on demand from the CLI or dashboard
- **Scan diffing** — compare current results against any previous scan to see new/closed TCP vs UDP services and risk changes
- **Structured logging** — all scan activity, timing, errors, and AI requests logged to `logs/`
- **Friendly error handling** — clear messages when nmap or Ollama are unavailable instead of crashes
- **Localhost validation script** — automated testing of scan output against expected services
- **Firewall rule suggestions** — generate `iptables`, `ip6tables`, and `firewalld` rules to block high/critical-risk open ports for this machine only (`g` key in dashboard, `--firewall` flag in CLI)
- **HTML report export** — self-contained HTML security report with scores, port tables, and complete per-service AI analysis (`x` key in dashboard)
- **IPv4 + IPv6 aware defaults** — automatic target detection, subnet validation, and host sorting now handle both IPv4 and IPv6 targets safely
- **Deterministic scan normalization** — overlapping port inputs are merged, non-contiguous ranges stay exact, and final host/service rows are sorted and deduplicated before display/export
- **Bounded AI summaries** — large whole-scan AI requests are capped to the highest-priority services so subnet scans stay responsive and prompts stay manageable
- **Smarter watch mode history** — automatic watch rescans only save new history entries when something actually changes
- **IPv6 firewall parity** — local IPv6 scans now generate `ip6tables` suggestions alongside existing `iptables`/`firewalld` output where appropriate
- **Expanded regression tests** — automated tests cover validation, history loading, AI request handling, HTML/CSV export, and mocked network-map scans
- **Security hardening** — atomic file creation with `0o600` permissions, CSV formula injection prevention, AI output sanitization, shell-safe firewall rule generation, scan history schema validation
- **Fully local** — no API keys or cloud services required

## Project Structure

```
src/
  scanner.py          # Scan orchestration, target/port validation, and CLI entry point
  ai_client.py        # Ollama request handling and AI prompt generation
  risk_model.py       # Risk classification, exposure tags, and host scoring
  network_map.py      # Host discovery, OS guessing, and subnet mapping
  interactive_cli.py  # Full-screen curses dashboard, watch mode, and viewers
  scan_history.py     # JSON/CSV/HTML export, history browsing, and diffing
  firewall_rules.py   # iptables/ip6tables/firewalld rule generation for risky ports
  validate_localhost.py  # Automated validation script
tests/                # Core feature and regression test suite
README.md             # Project overview, usage, and demo guidance
TODO.md               # Completed work and remaining ideas
requirements.txt      # Python dependency pinning
logs/                 # Debug/error logs (gitignored)
scan_history/         # Saved scan results and reports (gitignored)
venv/                 # Python virtual environment (gitignored)
```

## Prerequisites

- Python 3.10+
- [nmap](https://nmap.org/) — install with `sudo dnf install nmap` (Fedora) or `sudo apt install nmap` (Ubuntu)
- [Ollama](https://ollama.com/) — install with `curl -fsSL https://ollama.com/install.sh | sh`
- A pulled Ollama model: `ollama pull llama3.2`

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic scanning (no root needed)
python3 src/scanner.py --interactive

# With root — required for network mapping (m key), UDP scanning, and OS detection
sudo venv/bin/python src/scanner.py --interactive
```

> **Note:** Using `sudo venv/bin/python` runs as root while keeping your venv packages. Do **not** use `sudo pip install` — it can break system packages.

For full CLI usage details, run `python3 src/scanner.py --help`.

Useful export examples:

```bash
# Save CSV and JSON
python3 src/scanner.py localhost --export both

# Save an HTML report directly from the CLI
python3 src/scanner.py localhost --export html

# Save everything at once
python3 src/scanner.py localhost --export all
```

Interactive mode opens to an idle dashboard. Press `r` to scan, `m` to discover hosts on your subnet, or `?` for all keybindings. Selecting a host in the network map sets it as the scan target.

#### Keybindings

| Key | Action |
|-----|--------|
| `?` | Show help with all keybindings |
| `r` | Run a scan |
| `t` | Edit target host or subnet |
| `p` | Open port range menu (presets + custom) |
| `f` | Set ports to 1-65535 (full scan) |
| `d` | Reset target to auto-detected local subnet |
| `u` | Cycle scan mode (TCP / UDP / Both) |
| `m` | Network map — discover hosts with OS detection, risk summary, and vendor/MAC info (requires root) |
| `w` | Toggle watch mode (auto-rescan every 60s) |
| `g` | Generate firewall rules for risky ports |
| `o` | Toggle open-only / open+closed port view |
| `a` | Toggle AI analysis on/off |
| `e` | Export current results to CSV |
| `x` | Export HTML security report |
| `h` | Browse scan history and open a scrollable diff viewer against current results |
| `↑/↓` | Navigate through detected services |
| `←/→` | Scroll details pane |
| `q` | Quit the dashboard |

The dashboard keeps scans running in the background, shows live progress, lists open services in a color-coded table, and displays per-service details with a security score, exposure summary, and AI-generated explanation for the currently selected port. In watch mode, unchanged rescans update the status banner but do not create extra history files.

## Risk Classification

Services are classified into four risk levels based on the service type and detected software version:

| Level | Color | Examples |
|-------|-------|----------|
| **Critical** | Red | telnet, redis, memcached, mongodb, docker, outdated MySQL/PostgreSQL |
| **High** | Yellow | FTP, VNC, RDP, SMB, LDAP, databases, outdated OpenSSH |
| **Medium** | Orange | SSH (current), SMTP, DNS, RPC, tcpwrapped, unidentified services |
| **Low** | Green | HTTP/HTTPS, LLMNR, mDNS, IPP/CUPS printing |

Version-aware overrides automatically escalate risk when outdated software is detected (e.g., OpenSSH < 8.0, Apache < 2.4, nginx < 1.18, Samba < 4.15, vsftpd < 3.0). Whole-scan AI summaries are automatically limited to the highest-priority services so large subnet scans do not overwhelm the local model.

## Validation

Use the validation script to confirm the localhost scan path still works and that expected services are detected.

For the automated regression suite:

```bash
python3 -m unittest discover -s tests -p 'test*.py'
```

```bash
# Validate the scan structure only
python3 src/validate_localhost.py -p 1-100

# Validate expected localhost services
python3 src/validate_localhost.py -p 1-100 --expect 22:ssh --expect 80:http

# Require AI analysis to succeed too
python3 src/validate_localhost.py -p 1-100 --expect 22:ssh --expect 80:http --check-ai
```

## Example Output

```
🔍 Scanning localhost (ports 1-100, TCP)...

============================================================
  Host: 127.0.0.1 (localhost)
  State: up
============================================================
  Port       Service         Product              Risk
  -------------------------------------------------------
  22/tcp     ssh             OpenSSH 10.0         Medium
  80/tcp     http            Caddy httpd          Low

💾 Scan saved to scan_history/2026-04-13_15-47-42_localhost.json

🤖 Generating AI security analysis (this may take a moment)...

============================================================
  🛡️  AI Security Analysis
============================================================
  [AI-generated explanation of each service, its risks, and
   recommendations for securing it]
```
