# Smart Network Scanner

A CLI tool that scans your local network for open ports and running services, then uses a local AI model (Ollama + llama3.2) to explain potential security risks in plain language.

## Proposal

I am building a smart network scanner that analyzes a target system or local network to identify open ports and running services, then uses an AI model to explain potential security risks in a clear and accessible way. The tool will perform service detection using a network scanning library and present results through a simple interface. Key features will include identifying open ports, mapping them to known services (such as SSH or HTTP), assigning a basic risk level, and generating AI-powered explanations of what each service does, why it could be a vulnerability, and how it might be secured. The goal is to turn raw technical scan data into meaningful security insights that are easy to understand and demonstrate.

To build this project, I will use an agentic development loop powered by an AI coding assistant to iteratively generate, test, and refine the application. The agent will be guided by structured prompts to implement features step-by-step, and I will provide feedback based on runtime behavior, error messages, and expected outputs. Feedback mechanisms will include testing scans on known targets (such as localhost), validating that detected services match expected results, and ensuring the AI explanations are accurate and relevant. I will also use the agent to review and improve code structure, readability, and documentation, allowing for continuous refinement and a higher-quality final product.

## Features

- Port scanning with service and version detection (powered by nmap)
- Risk level assignment (Critical / High / Medium / Low) for detected services
- AI-powered security analysis explaining each service, its risks, and how to secure it
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
# Scan localhost (default port range 1-1024)
python3 scanner.py localhost

# Scan a specific port range
python3 scanner.py localhost -p 1-100

# Scan your local subnet (auto-detected)
python3 scanner.py

# Scan without AI analysis
python3 scanner.py localhost --no-ai
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
