# Smart Network Scanner

A CLI tool that scans your local network for open ports and running services, then uses a local AI model (Ollama + llama3.2) to explain potential security risks in plain language.

## Proposal

I am building a smart network scanner that analyzes a target system or local network to identify open ports and running services, then uses an AI model to explain potential security risks in a clear and accessible way. The tool will perform service detection using a network scanning library and present results through a simple interface. Key features will include identifying open ports, mapping them to known services (such as SSH or HTTP), assigning a basic risk level, and generating AI-powered explanations of what each service does, why it could be a vulnerability, and how it might be secured. The goal is to turn raw technical scan data into meaningful security insights that are easy to understand and demonstrate.

To build this project, I will speak to the agent in a question-answer type of feedback to iteratively generate, test, and refine the application. The agent will be guided by structured prompts to implement features step-by-step, and I will provide feedback based on runtime behavior, error messages, and expected outputs. Feedback mechanisms will include testing scans on known targets (such as localhost), validating that detected services match expected results, and ensuring the AI explanations are accurate and relevant. I will also use the agent to review and improve code structure, readability, and documentation, allowing for continuous refinement and a higher-quality final product.

## Features

- Port scanning with service and version detection (powered by nmap)
- Risk level assignment (Critical / High / Medium / Low) for detected services
- AI-powered security analysis explaining each service, its risks, and how to secure it
- Friendly failure messages when `nmap` or Ollama are unavailable
- Localhost validation script for checking scan output against expected services
- Fully local — no API keys or cloud services required

## Prerequisites

- Python 3.10+
- [nmap](https://nmap.org/) — install with `sudo dnf install nmap` (Fedora) or `sudo apt install nmap` (Ubuntu)
- [Ollama](https://ollama.com/) — install with `curl -fsSL https://ollama.com/install.sh | sh`
- A pulled Ollama model: `ollama pull llama3.2`

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Launch the full-screen interactive dashboard
python3 scanner.py --interactive

# Scan localhost (default port range 1-1024)
python3 scanner.py localhost

# Scan a specific port range
python3 scanner.py localhost -p 1-100

# Scan your local subnet (auto-detected)
python3 scanner.py

# Scan without AI analysis
python3 scanner.py localhost --no-ai
```

If Ollama is not running, the scan still completes and reports a clear warning for the AI step instead of crashing.

## Interactive Dashboard

Launch the dashboard with `python3 scanner.py --interactive` to get a full-screen terminal UI similar to a lightweight `btop` workflow.

Interactive mode now starts with a quick `localhost` scan over ports `1-100` so the screen feels responsive immediately. Press `d` any time to switch back to the auto-detected local subnet for a broader scan.

- `r` starts a scan
- `t` edits the target host or subnet
- `p` edits the port range
- `o` toggles between open-only and open-plus-closed educational port view
- `a` toggles AI analysis
- `d` restores the auto-detected local subnet
- `j` and `k` move through detected services
- `q` exits the dashboard

The dashboard keeps scans running in the background, shows live status updates, lists open services in a table, and displays per-service details with an AI-generated explanation for only the currently selected port.

## Validation

Use the validation script to confirm the localhost scan path still works and that expected services are detected.

```bash
# Validate the scan structure only
python3 validate_localhost.py -p 1-100

# Validate expected localhost services
python3 validate_localhost.py -p 1-100 --expect 22:ssh --expect 80:http

# Require AI analysis to succeed too
python3 validate_localhost.py -p 1-100 --expect 22:ssh --expect 80:http --check-ai
```

## Example Output

```
🔍 Scanning localhost (ports 1-100)...

============================================================
  Host: 127.0.0.1 (localhost)
  State: up
============================================================
  Port     Service         Product              Risk
  -----------------------------------------------------
  22       ssh             OpenSSH 10.0         Medium
  80       http            Caddy httpd          Low

🤖 Generating AI security analysis (this may take a moment)...

============================================================
  🛡️  AI Security Analysis
============================================================
  [AI-generated explanation of each service, its risks, and
   recommendations for securing it]
```
