# Smart Network Scanner

A CLI tool that scans your local network for open ports and running services, then uses a local AI model (Ollama + llama3.2) to explain potential security risks in plain language.

## Proposal

I am building a smart network scanner that analyzes a target system or local network to identify open ports and running services, then uses an AI model to explain potential security risks in a clear and accessible way. The tool will perform service detection using a network scanning library and present results through a simple interface. Key features will include identifying open ports, mapping them to known services (such as SSH or HTTP), assigning a basic risk level, and generating AI-powered explanations of what each service does, why it could be a vulnerability, and how it might be secured. The goal is to turn raw technical scan data into meaningful security insights that are easy to understand and demonstrate.

To build this project, I will speak to the agent in a question-answer type of feedback to iteratively generate, test, and refine the application. The agent will be guided by structured prompts to implement features step-by-step, and I will provide feedback based on runtime behavior, error messages, and expected outputs. Feedback mechanisms will include testing scans on known targets (such as localhost), validating that detected services match expected results, and ensuring the AI explanations are accurate and relevant. I will also use the agent to review and improve code structure, readability, and documentation, allowing for continuous refinement and a higher-quality final product.

## Week 13

So far AMP has been pretty helpful and smart about its ideas and suggestions. Everything works pretty well but there's still a vast amount of things I want done before I'm satisfied. The port scanning works well and the toggles for open and closed ports work too. The local Ollama ai gives good suggestions and when it summarizes the port stuff it is pretty information dense. For next week I want more features like network device mapping and potentially expanding this to be a web interface instead of just CLI (even though CLIs are just awesome).

I haven't really thrown anything super complicated at the AI so far so it's been able to handle most things. Therefore I can't really speak on the "smartest" or "dumbest" things its done because those things aren't very far apart in terms of complexity. https://ampcode.com/threads/T-019d7017-01e5-779d-bd5a-1553cde7fcfb Here is the main thread I've been working with it and its been pretty easy. I've chosen to not use agentic looping since that was a real pain last time and instead just talk to AMP normally, I've found that that has been a good way to work with it. 

## Features

- **Network device mapping** — scan a subnet and view a table of all discovered hosts with hostname, OS guess (`nmap -O`), and open port count (press `m` in the dashboard); select a host to set it as the scan target
- **Two-phase scanning** — automatic ping sweep discovers live hosts first, then only port-scans those hosts (dramatically faster on subnets)
- **Security score summary** — per-host 0-100 security score based on the number and severity of open services, shown in the detail pane
- **Target input validation** — rejects shell characters, nmap option injection, and overly broad subnets before scanning
- **Full port scanning** — scan any range up to all 65535 ports with parallel chunked nmap (8 concurrent workers, `-T4`, `--min-rate 300`, `-sV`)
- **70+ service risk classifications** — covers remote access, web, databases, file sharing, printing, DNS, RPC, containers, and more
- **Version-aware risk overrides** — outdated software (e.g., OpenSSH < 8.0, MySQL < 8.0, PostgreSQL < 13) is automatically escalated to a higher risk level
- **AI-powered security analysis** — per-service explanations with Overview, What is this, Risks, and Actions sections powered by Ollama + llama3.2
- **Interactive curses dashboard** — full-screen terminal UI with live scanning, service browsing, and inline AI analysis
- **Port range presets** — quick menu with common ranges (1-100, 1-1024, 1-10000, all ports, common services) plus custom input
- **Scan history** — every scan auto-saves to `scan_history/` as JSON for future reference
- **CSV/JSON export** — export results on demand for external analysis or reporting
- **Scan diffing** — compare current results against any previous scan to see new/closed ports and risk changes
- **Structured logging** — all scan activity, timing, errors, and AI requests logged to `logs/`
- **Friendly error handling** — clear messages when nmap or Ollama are unavailable instead of crashes
- **Localhost validation script** — automated testing of scan output against expected services
- **Firewall rule suggestions** — generate `iptables` and `firewalld` rules to block high/critical-risk open ports (`g` key in dashboard, `--firewall` flag in CLI)
- **HTML report export** — self-contained HTML security report with scores, port tables, and AI analysis (`x` key in dashboard)
- **Security hardening** — atomic file creation with `0o600` permissions, CSV formula injection prevention, AI output sanitization, shell-safe firewall rule generation, scan history schema validation
- **Fully local** — no API keys or cloud services required

## Project Structure

```
src/
  scanner.py          # Core scanner, risk classification, AI prompts, CLI entry point
  network_map.py      # Host discovery (ping sweep) and OS-detection mapping
  interactive_cli.py  # Full-screen curses dashboard
  scan_history.py     # JSON/CSV export, history listing, scan diffing
  firewall_rules.py   # iptables/firewalld rule generation for risky ports
  validate_localhost.py  # Automated validation script
logs/                 # Debug/error logs (gitignored)
scan_history/         # Saved scan results as JSON/CSV (gitignored)
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
| `m` | Network map — discover hosts with OS detection (requires root) |
| `w` | Toggle watch mode (auto-rescan every 60s) |
| `g` | Generate firewall rules for risky ports |
| `o` | Toggle open-only / open+closed port view |
| `a` | Toggle AI analysis on/off |
| `e` | Export current results to CSV |
| `x` | Export HTML security report |
| `h` | Browse scan history and diff against current results |
| `↑/↓` | Navigate through detected services |
| `←/→` | Scroll details pane |
| `q` | Quit the dashboard |

The dashboard keeps scans running in the background, shows live progress, lists open services in a color-coded table, and displays per-service details with a security score and AI-generated explanation for the currently selected port.

## Risk Classification

Services are classified into four risk levels based on the service type and detected software version:

| Level | Color | Examples |
|-------|-------|----------|
| **Critical** | Red | telnet, redis, memcached, mongodb, docker, outdated MySQL/PostgreSQL |
| **High** | Yellow | FTP, VNC, RDP, SMB, LDAP, databases, outdated OpenSSH |
| **Medium** | Orange | SSH (current), SMTP, DNS, RPC, tcpwrapped, unidentified services |
| **Low** | Green | HTTP/HTTPS, LLMNR, mDNS, IPP/CUPS printing |

Version-aware overrides automatically escalate risk when outdated software is detected (e.g., OpenSSH < 8.0, Apache < 2.4, vsftpd < 3.0).

## Validation

Use the validation script to confirm the localhost scan path still works and that expected services are detected.

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
